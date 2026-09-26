package spoofer

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type failingTCPForwarderRequest struct {
	id            stack.TransportEndpointID
	completeCalls []bool
}

func TestSetupTCPOptionsDisablesTimeWait(t *testing.T) {
	opts := &Opts{}
	st, err := opts.opts().BuildStack(false)
	if err != nil {
		t.Fatalf("build stack: %v", err)
	}
	defer st.Destroy()

	var before tcpip.TCPTimeWaitTimeoutOption
	if err := st.TransportProtocolOption(tcp.ProtocolNumber, &before); err != nil {
		t.Fatalf("get initial TCP TIME_WAIT: %v", err)
	}
	if before == 0 {
		t.Fatal("initial TCP TIME_WAIT is disabled; test cannot verify the change")
	}
	if err := opts.setupTCPOptions(st); err != nil {
		t.Fatalf("set up TCP options: %v", err)
	}

	var after tcpip.TCPTimeWaitTimeoutOption
	if err := st.TransportProtocolOption(tcp.ProtocolNumber, &after); err != nil {
		t.Fatalf("get configured TCP TIME_WAIT: %v", err)
	}
	if after != 0 {
		t.Fatalf("TCP TIME_WAIT = %v, want 0", time.Duration(after))
	}
}

func (r *failingTCPForwarderRequest) ID() stack.TransportEndpointID {
	return r.id
}

func (*failingTCPForwarderRequest) CreateEndpoint(*waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return nil, &tcpip.ErrInvalidEndpointState{}
}

func (r *failingTCPForwarderRequest) Complete(sendReset bool) {
	r.completeCalls = append(r.completeCalls, sendReset)
}

func TestPreparedTCPResourceClosedWhenEndpointCreationFails(t *testing.T) {
	preparedClosed := false
	reported := make(chan error, 1)
	opts := &Opts{
		PrepareTCP: func(context.Context, stack.TransportEndpointID) (PreparedTCPHandler, error) {
			return PreparedTCPHandlerFuncs{
				HandleFunc: func(net.Conn) {
					t.Error("HandleTCP called after endpoint creation failed")
				},
				CloseFunc: func() error {
					preparedClosed = true
					return nil
				},
			}, nil
		},
		OnTCPError: func(_ stack.TransportEndpointID, err error) {
			reported <- err
		},
	}
	request := &failingTCPForwarderRequest{}

	opts.handlePreparedTCP(context.Background(), request)

	if !preparedClosed {
		t.Fatal("prepared resource was not closed")
	}
	if len(request.completeCalls) != 1 || !request.completeCalls[0] {
		t.Fatalf("Complete calls = %v, want one reset", request.completeCalls)
	}
	select {
	case err := <-reported:
		if !strings.Contains(err.Error(), "create intercepted TCP endpoint") {
			t.Fatalf("reported error = %v, want endpoint creation context", err)
		}
	default:
		t.Fatal("endpoint creation error was not reported")
	}
}

func TestPreparedTCPCloseErrorIsReported(t *testing.T) {
	closeErr := errors.New("close upstream failed")
	reported := make(chan error, 1)
	opts := &Opts{
		PrepareTCP: func(context.Context, stack.TransportEndpointID) (PreparedTCPHandler, error) {
			return PreparedTCPHandlerFuncs{
				CloseFunc: func() error { return closeErr },
			}, nil
		},
		OnTCPError: func(_ stack.TransportEndpointID, err error) {
			reported <- err
		},
	}

	opts.handlePreparedTCP(context.Background(), &failingTCPForwarderRequest{})

	if err := <-reported; !errors.Is(err, closeErr) {
		t.Fatalf("reported error = %v, want close error", err)
	}
}
