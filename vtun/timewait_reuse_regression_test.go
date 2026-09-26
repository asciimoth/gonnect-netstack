package vtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect-netstack/spoofer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	timeWaitReuseAttempts = 6
	timeWaitReuseTimeout  = 2 * time.Second
)

type timeWaitReuseCloseDirection string

const (
	spooferClosesFirst timeWaitReuseCloseDirection = "spoofer_closes_first"
	clientClosesFirst  timeWaitReuseCloseDirection = "client_closes_first"
)

func newTimeWaitReuseClient(
	t *testing.T,
	localAddr netip.Addr,
	configure func(*spoofer.Opts),
) (*VTun, context.CancelFunc) {
	t.Helper()

	client, err := (&Opts{
		LocalAddrs:     []netip.Addr{localAddr},
		NoLoopbackAddr: true,
	}).Build()
	if err != nil {
		t.Fatalf("build VTun: %v", err)
	}
	select {
	case <-client.Events():
	case <-time.After(timeWaitReuseTimeout):
		_ = client.Close()
		t.Fatal("VTun did not become ready")
	}

	// The client must release its local tuple immediately. The test keeps the
	// spoofer behavior independent and verifies that Launch configures it.
	clientTimeWait := tcpip.TCPTimeWaitTimeoutOption(0)
	if err := client.stack.SetTransportProtocolOption(
		tcp.ProtocolNumber,
		&clientTimeWait,
	); err != nil {
		_ = client.Close()
		t.Fatalf("disable client TIME_WAIT: %v", err)
	}

	lifetime, cancel := context.WithCancel(context.Background())
	opts := &spoofer.Opts{TCPPrepareTimeout: timeWaitReuseTimeout}
	configure(opts)
	opts.WithTunEndpoint(client, 256)
	linkEndpoint := opts.Endpoint
	spooferStack, err := opts.LaunchContext(lifetime)
	if err != nil {
		cancel()
		_ = client.Close()
		t.Fatalf("launch Spoofer: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		linkEndpoint.Close()
		linkEndpoint.Wait()
		spooferStack.Destroy()
	})
	return client, cancel
}

func runTimeWaitReuseConnection(
	t *testing.T,
	client *VTun,
	network, local, remote string,
	attempt int,
	closeDirection timeWaitReuseCloseDirection,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeWaitReuseTimeout)
	conn, err := client.DialTCP(ctx, network, local, remote)
	cancel()
	if err != nil {
		t.Fatalf("attempt %d dial: %v", attempt, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeWaitReuseTimeout)); err != nil {
		t.Fatalf("attempt %d set deadline: %v", attempt, err)
	}

	request := fmt.Sprintf("request-%d", attempt)
	wantReply := fmt.Sprintf("reply-%d", attempt)
	if closeDirection == clientClosesFirst {
		if _, err := conn.Write([]byte(request)); err != nil {
			t.Fatalf("attempt %d write: %v", attempt, err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatalf("attempt %d close write: %v", attempt, err)
		}
		wantReply = "reply:" + request
	}

	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("attempt %d read: %v", attempt, err)
	}
	if string(reply) != wantReply {
		t.Fatalf("attempt %d reply = %q, want %q", attempt, reply, wantReply)
	}
}

func serveTimeWaitReuseConnection(
	conn net.Conn,
	attempt int,
	closeDirection timeWaitReuseCloseDirection,
	done chan<- int,
	errors chan<- error,
) {
	defer func() {
		if err := conn.Close(); err != nil {
			errors <- fmt.Errorf("attempt %d close: %w", attempt, err)
		}
		done <- attempt
	}()
	if err := conn.SetDeadline(time.Now().Add(timeWaitReuseTimeout)); err != nil {
		errors <- fmt.Errorf("attempt %d set deadline: %w", attempt, err)
		return
	}

	var reply string
	if closeDirection == clientClosesFirst {
		request, err := io.ReadAll(conn)
		if err != nil {
			errors <- fmt.Errorf("attempt %d read: %w", attempt, err)
			return
		}
		reply = "reply:" + string(request)
	} else {
		reply = fmt.Sprintf("reply-%d", attempt)
	}
	if _, err := conn.Write([]byte(reply)); err != nil {
		errors <- fmt.Errorf("attempt %d write: %w", attempt, err)
	}
}

func waitForTimeWaitReuseHandler(
	t *testing.T,
	done <-chan int,
	handlerErrors <-chan error,
	attempt int,
) {
	t.Helper()
	select {
	case err := <-handlerErrors:
		t.Fatal(err)
	case got := <-done:
		if got != attempt {
			t.Fatalf("completed handler = %d, want %d", got, attempt)
		}
	case <-time.After(timeWaitReuseTimeout):
		t.Fatalf("attempt %d handler did not finish", attempt)
	}
	select {
	case err := <-handlerErrors:
		t.Fatal(err)
	default:
	}
}

func TestSpooferAcceptsReusedClientTupleAfterServerClose(t *testing.T) {
	done := make(chan int, 2)
	handlerErrors := make(chan error, 2)
	var prepareCalls atomic.Int32
	client, _ := newTimeWaitReuseClient(
		t,
		netip.MustParseAddr("192.0.2.2"),
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(
				context.Context,
				stack.TransportEndpointID,
			) (spoofer.PreparedTCPHandler, error) {
				attempt := int(prepareCalls.Add(1))
				return spoofer.PreparedTCPHandlerFuncs{
					HandleFunc: func(conn net.Conn) {
						go serveTimeWaitReuseConnection(
							conn, attempt, spooferClosesFirst, done, handlerErrors,
						)
					},
				}, nil
			}
		},
	)

	for attempt := 1; attempt <= 2; attempt++ {
		runTimeWaitReuseConnection(
			t,
			client,
			"tcp4",
			"192.0.2.2:41000",
			"192.0.2.80:443",
			attempt,
			spooferClosesFirst,
		)
		waitForTimeWaitReuseHandler(t, done, handlerErrors, attempt)
		time.Sleep(10 * time.Millisecond)
	}
	if got := int(prepareCalls.Load()); got != 2 {
		t.Fatalf("PrepareTCP calls = %d, want 2", got)
	}
}

func TestSpooferRepeatedlyReusesClientTuple(t *testing.T) {
	testCases := []struct {
		name           string
		network        string
		localAddr      netip.Addr
		remoteAddr     netip.Addr
		prepared       bool
		closeDirection timeWaitReuseCloseDirection
	}{
		{"IPv4/prepared/spoofer closes", "tcp4", netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.80"), true, spooferClosesFirst},
		{"IPv4/prepared/client closes", "tcp4", netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.80"), true, clientClosesFirst},
		{"IPv4/eager/spoofer closes", "tcp4", netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.80"), false, spooferClosesFirst},
		{"IPv4/eager/client closes", "tcp4", netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.80"), false, clientClosesFirst},
		{"IPv6/prepared/spoofer closes", "tcp6", netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::80"), true, spooferClosesFirst},
		{"IPv6/prepared/client closes", "tcp6", netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::80"), true, clientClosesFirst},
		{"IPv6/eager/spoofer closes", "tcp6", netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::80"), false, spooferClosesFirst},
		{"IPv6/eager/client closes", "tcp6", netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::80"), false, clientClosesFirst},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan int, timeWaitReuseAttempts)
			handlerErrors := make(chan error, timeWaitReuseAttempts)
			var callbackCalls atomic.Int32
			client, _ := newTimeWaitReuseClient(t, tc.localAddr, func(opts *spoofer.Opts) {
				if tc.prepared {
					opts.PrepareTCP = func(
						context.Context,
						stack.TransportEndpointID,
					) (spoofer.PreparedTCPHandler, error) {
						attempt := int(callbackCalls.Add(1))
						return spoofer.PreparedTCPHandlerFuncs{
							HandleFunc: func(conn net.Conn) {
								go serveTimeWaitReuseConnection(
									conn, attempt, tc.closeDirection, done, handlerErrors,
								)
							},
						}, nil
					}
					return
				}
				opts.OnTCPConn = func(conn net.Conn, _ stack.TransportEndpointID) {
					attempt := int(callbackCalls.Add(1))
					go serveTimeWaitReuseConnection(
						conn, attempt, tc.closeDirection, done, handlerErrors,
					)
				}
			})

			local := netip.AddrPortFrom(tc.localAddr, 41000).String()
			remote := netip.AddrPortFrom(tc.remoteAddr, 443).String()
			for attempt := 1; attempt <= timeWaitReuseAttempts; attempt++ {
				runTimeWaitReuseConnection(
					t, client, tc.network, local, remote, attempt, tc.closeDirection,
				)
				waitForTimeWaitReuseHandler(t, done, handlerErrors, attempt)
				time.Sleep(5 * time.Millisecond)
			}
			if got := int(callbackCalls.Load()); got != timeWaitReuseAttempts {
				t.Fatalf("TCP callback calls = %d, want %d", got, timeWaitReuseAttempts)
			}
		})
	}
}

func TestSpooferReusesManyClientTuplesConcurrently(t *testing.T) {
	const (
		workers          = 12
		attemptsPerTuple = 8
	)
	var prepareCalls atomic.Int32
	client, _ := newTimeWaitReuseClient(
		t,
		netip.MustParseAddr("192.0.2.2"),
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(
				context.Context,
				stack.TransportEndpointID,
			) (spoofer.PreparedTCPHandler, error) {
				prepareCalls.Add(1)
				return spoofer.PreparedTCPHandlerFuncs{
					HandleFunc: func(conn net.Conn) {
						go func() {
							defer func() { _ = conn.Close() }()
							_, _ = conn.Write([]byte("ok"))
						}()
					},
				}, nil
			}
		},
	)

	start := make(chan struct{})
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			local := netip.AddrPortFrom(
				netip.MustParseAddr("192.0.2.2"), uint16(42000+worker),
			).String()
			for attempt := 1; attempt <= attemptsPerTuple; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), timeWaitReuseTimeout)
				conn, err := client.DialTCP(ctx, "tcp4", local, "192.0.2.80:443")
				cancel()
				if err != nil {
					errors <- fmt.Errorf("worker %d attempt %d dial: %w", worker, attempt, err)
					return
				}
				_ = conn.SetDeadline(time.Now().Add(timeWaitReuseTimeout))
				body, readErr := io.ReadAll(conn)
				_ = conn.Close()
				if readErr != nil || string(body) != "ok" {
					errors <- fmt.Errorf(
						"worker %d attempt %d reply = %q, error = %v",
						worker, attempt, body, readErr,
					)
					return
				}
				// Let the client stack run its zero-duration TIME_WAIT cleanup
				// callback before this worker binds the same local tuple again.
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	wantCalls := int32(workers * attemptsPerTuple)
	if got := prepareCalls.Load(); got != wantCalls {
		t.Fatalf("PrepareTCP calls = %d, want %d", got, wantCalls)
	}
}

func TestSpooferReusesClientTupleAfterReset(t *testing.T) {
	resetErr := errors.New("controlled reset")
	reported := make(chan error, 1)
	var prepareCalls atomic.Int32
	client, _ := newTimeWaitReuseClient(
		t,
		netip.MustParseAddr("192.0.2.2"),
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(
				context.Context,
				stack.TransportEndpointID,
			) (spoofer.PreparedTCPHandler, error) {
				if prepareCalls.Add(1) == 1 {
					return nil, resetErr
				}
				return spoofer.PreparedTCPHandlerFuncs{
					HandleFunc: func(conn net.Conn) {
						go func() {
							defer func() { _ = conn.Close() }()
							_, _ = conn.Write([]byte("ok"))
						}()
					},
				}, nil
			}
			opts.OnTCPError = func(_ stack.TransportEndpointID, err error) {
				reported <- err
			}
		},
	)

	local := "192.0.2.2:43000"
	remote := "192.0.2.80:443"
	ctx, cancel := context.WithTimeout(context.Background(), timeWaitReuseTimeout)
	conn, err := client.DialTCP(ctx, "tcp4", local, remote)
	cancel()
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("first dial succeeded after the spoofer reset it")
	}
	select {
	case err := <-reported:
		if !errors.Is(err, resetErr) {
			t.Fatalf("reported error = %v, want %v", err, resetErr)
		}
	case <-time.After(timeWaitReuseTimeout):
		t.Fatal("reset error was not reported")
	}

	ctx, cancel = context.WithTimeout(context.Background(), timeWaitReuseTimeout)
	conn, err = client.DialTCP(ctx, "tcp4", local, remote)
	cancel()
	if err != nil {
		t.Fatalf("dial after reset: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeWaitReuseTimeout))
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after reset: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("reply after reset = %q, want ok", body)
	}
	if got := prepareCalls.Load(); got != 2 {
		t.Fatalf("PrepareTCP calls = %d, want 2", got)
	}
}

func TestSpooferShutdownWhileReusedTupleIsBeingPrepared(t *testing.T) {
	prepareStarted := make(chan struct{})
	prepareStopped := make(chan error, 1)
	var prepareCalls atomic.Int32
	client, cancelSpoofer := newTimeWaitReuseClient(
		t,
		netip.MustParseAddr("192.0.2.2"),
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(
				ctx context.Context,
				_ stack.TransportEndpointID,
			) (spoofer.PreparedTCPHandler, error) {
				if prepareCalls.Add(1) == 1 {
					return spoofer.PreparedTCPHandlerFuncs{
						HandleFunc: func(conn net.Conn) {
							go func() {
								defer func() { _ = conn.Close() }()
								_, _ = conn.Write([]byte("ok"))
							}()
						},
					}, nil
				}
				close(prepareStarted)
				<-ctx.Done()
				prepareStopped <- ctx.Err()
				return nil, ctx.Err()
			}
		},
	)

	local := "192.0.2.2:44000"
	remote := "192.0.2.80:443"
	ctx, cancel := context.WithTimeout(context.Background(), timeWaitReuseTimeout)
	conn, err := client.DialTCP(ctx, "tcp4", local, remote)
	cancel()
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeWaitReuseTimeout))
	body, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("first reply = %q, error = %v", body, err)
	}
	time.Sleep(10 * time.Millisecond)

	dialResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeWaitReuseTimeout)
		defer cancel()
		conn, err := client.DialTCP(ctx, "tcp4", local, remote)
		if conn != nil {
			_ = conn.Close()
		}
		dialResult <- err
	}()
	select {
	case <-prepareStarted:
	case <-time.After(timeWaitReuseTimeout):
		t.Fatal("reused connection did not reach PrepareTCP")
	}
	cancelSpoofer()
	select {
	case err := <-prepareStopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("PrepareTCP context error = %v, want context.Canceled", err)
		}
	case <-time.After(timeWaitReuseTimeout):
		t.Fatal("PrepareTCP did not stop during shutdown")
	}
	select {
	case err := <-dialResult:
		if err == nil {
			t.Fatal("reused dial succeeded during shutdown")
		}
	case <-time.After(timeWaitReuseTimeout):
		t.Fatal("reused dial did not stop during shutdown")
	}
	if got := prepareCalls.Load(); got != 2 {
		t.Fatalf("PrepareTCP calls = %d, want 2", got)
	}
}
