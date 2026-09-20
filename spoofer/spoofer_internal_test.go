package spoofer

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

type failingTCPForwarderRequest struct {
	id            stack.TransportEndpointID
	completeCalls []bool
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
