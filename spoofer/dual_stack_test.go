package spoofer_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect-netstack/spoofer"
	"github.com/asciimoth/gonnect-netstack/vtun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const spooferTestFallbackDelay = 30 * time.Millisecond

var (
	spooferTestIPv4 = netip.MustParseAddr("192.0.2.80")
	spooferTestIPv6 = netip.MustParseAddr("2001:db8::80")
)

func newSpooferClient(
	t *testing.T,
	lookup func(context.Context, string, string) ([]net.IP, error),
	configure func(*spoofer.Opts),
) (*vtun.VTun, context.CancelFunc) {
	return newSpooferClientWithLocalAddrs(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::2"),
	}, lookup, configure)
}

func closeSpooferTestConn(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func newSpooferClientWithLocalAddrs(
	t *testing.T,
	localAddrs []netip.Addr,
	lookup func(context.Context, string, string) ([]net.IP, error),
	configure func(*spoofer.Opts),
) (*vtun.VTun, context.CancelFunc) {
	t.Helper()
	client, err := (&vtun.Opts{
		LocalAddrs:       localAddrs,
		NoLoopbackAddr:   true,
		Lookup:           lookup,
		TCPFallbackDelay: spooferTestFallbackDelay,
	}).Build()
	if err != nil {
		t.Fatalf("build VTun: %v", err)
	}
	select {
	case <-client.Events():
	case <-time.After(time.Second):
		t.Fatal("VTun did not become ready")
	}

	lifetime, cancel := context.WithCancel(context.Background())
	opts := &spoofer.Opts{TCPPrepareTimeout: 2 * time.Second}
	configure(opts)
	opts.WithTunEndpoint(client, 32)
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

func echoPreparedHandler() spoofer.PreparedTCPHandler {
	return spoofer.PreparedTCPHandlerFuncs{
		HandleFunc: func(conn net.Conn) {
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		},
	}
}

func endpointDestination(id stack.TransportEndpointID) netip.Addr {
	addr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return addr.Unmap()
}

func TestPrepareTCPDelaysClientHandshakeUntilUpstreamIsReady(t *testing.T) {
	prepareStarted := make(chan struct{})
	releasePrepare := make(chan struct{})
	var startOnce sync.Once
	client, _ := newSpooferClient(t, nil, func(opts *spoofer.Opts) {
		opts.PrepareTCP = func(ctx context.Context, _ stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
			startOnce.Do(func() { close(prepareStarted) })
			select {
			case <-releasePrepare:
				return echoPreparedHandler(), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	})

	type dialResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan dialResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		conn, err := client.DialTCP(ctx, "tcp6", "", netip.AddrPortFrom(spooferTestIPv6, 443).String())
		result <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-prepareStarted:
	case <-time.After(time.Second):
		t.Fatal("PrepareTCP was not called")
	}
	select {
	case got := <-result:
		if got.conn != nil {
			_ = got.conn.Close()
		}
		t.Fatalf("DialTCP returned before upstream readiness: %v", got.err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releasePrepare)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("DialTCP failed after preparation: %v", got.err)
		}
		_ = got.conn.Close()
	case <-time.After(time.Second):
		t.Fatal("DialTCP did not finish after preparation")
	}
}

func TestVTunSpooferDualStackFallsBackToPreparedIPv4(t *testing.T) {
	v6Started := make(chan struct{})
	releaseV6 := make(chan struct{})
	v6Failure := errors.New("controlled IPv6 upstream failure")
	errorEvents := make(chan error, 4)
	var v6Once sync.Once

	client, _ := newSpooferClient(
		t,
		func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.IP(spooferTestIPv6.AsSlice()), net.IP(spooferTestIPv4.AsSlice())}, nil
		},
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(ctx context.Context, id stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
				if endpointDestination(id).Is6() {
					v6Once.Do(func() { close(v6Started) })
					select {
					case <-releaseV6:
						return nil, v6Failure
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return echoPreparedHandler(), nil
			}
			opts.OnTCPError = func(_ stack.TransportEndpointID, err error) {
				errorEvents <- err
			}
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := client.DialTCP(ctx, "tcp", "", "dual.test:443")
	if err != nil {
		t.Fatalf("dual-stack DialTCP failed: %v", err)
	}
	defer closeSpooferTestConn(t, conn)
	if elapsed := time.Since(started); elapsed < spooferTestFallbackDelay/2 {
		t.Fatalf("DialTCP completed in %v, before the fallback delay", elapsed)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("DialTCP fallback took %v", elapsed)
	}
	select {
	case <-v6Started:
	default:
		t.Fatal("IPv6 preparation did not start")
	}
	if remote := conn.RemoteAddr().String(); !strings.HasPrefix(remote, spooferTestIPv4.String()+":") {
		t.Fatalf("winning remote address = %q, want IPv4 %s", remote, spooferTestIPv4)
	}

	payload := []byte("dual-stack fallback")
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("Read echo: %v", err)
	}
	if string(received) != string(payload) {
		t.Fatalf("echo = %q, want %q", received, payload)
	}

	close(releaseV6)
	select {
	case err := <-errorEvents:
		if !errors.Is(err, v6Failure) {
			t.Fatalf("OnTCPError error = %v, want IPv6 failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IPv6 preparation failure was not reported")
	}
}

func TestVTunSpooferLoopbackIPv6DoesNotImplyReachability(t *testing.T) {
	releaseV6 := make(chan struct{})
	client, _ := newSpooferClientWithLocalAddrs(
		t,
		[]netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.IPv6Loopback()},
		func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.IP(spooferTestIPv6.AsSlice()), net.IP(spooferTestIPv4.AsSlice())}, nil
		},
		func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(ctx context.Context, id stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
				if endpointDestination(id).Is6() {
					select {
					case <-releaseV6:
						return nil, errors.New("controlled IPv6 failure")
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return echoPreparedHandler(), nil
			}
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, "tcp", "", "dual.test:443")
	if err != nil {
		close(releaseV6)
		t.Fatalf("DialTCP failed: %v", err)
	}
	defer closeSpooferTestConn(t, conn)
	close(releaseV6)
	if remote := conn.RemoteAddr().String(); !strings.HasPrefix(remote, spooferTestIPv4.String()+":") {
		t.Fatalf("winning remote address = %q, want IPv4 %s", remote, spooferTestIPv4)
	}
}

func TestPrepareTCPFailureResetsClientAndReportsCause(t *testing.T) {
	prepareErr := errors.New("upstream refused connection")
	errorEvents := make(chan error, 1)
	client, _ := newSpooferClient(t, nil, func(opts *spoofer.Opts) {
		opts.PrepareTCP = func(context.Context, stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
			return nil, prepareErr
		}
		opts.OnTCPError = func(_ stack.TransportEndpointID, err error) {
			errorEvents <- err
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, "tcp4", "", netip.AddrPortFrom(spooferTestIPv4, 443).String())
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("DialTCP succeeded after preparation failure")
	}
	select {
	case reported := <-errorEvents:
		if !errors.Is(reported, prepareErr) {
			t.Fatalf("OnTCPError error = %v, want preparation cause", reported)
		}
	case <-time.After(time.Second):
		t.Fatal("preparation failure was not reported")
	}
}

func TestVTunSpooferDualStackPreservesLocalBind(t *testing.T) {
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.IP(spooferTestIPv6.AsSlice()), net.IP(spooferTestIPv4.AsSlice())}, nil
	}

	t.Run("explicit IPv4 address", func(t *testing.T) {
		v6Attempted := make(chan struct{}, 1)
		client, _ := newSpooferClient(t, lookup, func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(_ context.Context, id stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
				if endpointDestination(id).Is6() {
					v6Attempted <- struct{}{}
					return nil, errors.New("unexpected IPv6 attempt")
				}
				return echoPreparedHandler(), nil
			}
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		local := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), 0).String()
		conn, err := client.DialTCP(ctx, "tcp", local, "dual.test:443")
		if err != nil {
			t.Fatalf("DialTCP with explicit local address: %v", err)
		}
		defer closeSpooferTestConn(t, conn)
		select {
		case <-v6Attempted:
			t.Fatal("explicit IPv4 local address permitted an IPv6 attempt")
		default:
		}
		if localAddr := conn.LocalAddr().String(); !strings.HasPrefix(localAddr, "192.0.2.2:") {
			t.Fatalf("local address = %q, want explicit IPv4 address", localAddr)
		}
	})

	t.Run("wildcard fixed port", func(t *testing.T) {
		releaseV6 := make(chan struct{})
		client, _ := newSpooferClient(t, lookup, func(opts *spoofer.Opts) {
			opts.PrepareTCP = func(ctx context.Context, id stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
				if endpointDestination(id).Is6() {
					select {
					case <-releaseV6:
						return nil, errors.New("controlled IPv6 failure")
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return echoPreparedHandler(), nil
			}
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := client.DialTCP(ctx, "tcp", ":32123", "dual.test:443")
		if err != nil {
			close(releaseV6)
			t.Fatalf("DialTCP with fixed local port: %v", err)
		}
		defer closeSpooferTestConn(t, conn)
		close(releaseV6)
		_, port, err := net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			t.Fatalf("parse local address %q: %v", conn.LocalAddr(), err)
		}
		if port != "32123" {
			t.Fatalf("local port = %q, want 32123", port)
		}
	})
}

func TestLaunchContextCancelsPendingTCPPreparation(t *testing.T) {
	prepareStarted := make(chan struct{})
	prepareStopped := make(chan error, 1)
	var startOnce sync.Once
	client, cancelSpoofer := newSpooferClient(t, nil, func(opts *spoofer.Opts) {
		opts.PrepareTCP = func(ctx context.Context, _ stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
			startOnce.Do(func() { close(prepareStarted) })
			<-ctx.Done()
			prepareStopped <- ctx.Err()
			return nil, ctx.Err()
		}
	})

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	dialResult := make(chan error, 1)
	go func() {
		conn, err := client.DialTCP(
			dialCtx, "tcp6", "", netip.AddrPortFrom(spooferTestIPv6, 443).String(),
		)
		if conn != nil {
			_ = conn.Close()
		}
		dialResult <- err
	}()

	select {
	case <-prepareStarted:
	case <-time.After(time.Second):
		t.Fatal("PrepareTCP was not called")
	}
	cancelSpoofer()
	select {
	case err := <-prepareStopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("PrepareTCP context error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("PrepareTCP did not stop after Spoofer cancellation")
	}
	select {
	case err := <-dialResult:
		if err == nil {
			t.Fatal("DialTCP succeeded during Spoofer shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("DialTCP did not stop after Spoofer cancellation")
	}
}

func TestPreparedTCPHandlerIsClosedWhenPreparationExpires(t *testing.T) {
	prepareStarted := make(chan struct{})
	handlerClosed := make(chan struct{})
	var startOnce sync.Once
	var closeOnce sync.Once
	client, cancelSpoofer := newSpooferClient(t, nil, func(opts *spoofer.Opts) {
		opts.PrepareTCP = func(ctx context.Context, _ stack.TransportEndpointID) (spoofer.PreparedTCPHandler, error) {
			startOnce.Do(func() { close(prepareStarted) })
			<-ctx.Done()
			return spoofer.PreparedTCPHandlerFuncs{
				CloseFunc: func() error {
					closeOnce.Do(func() { close(handlerClosed) })
					return nil
				},
			}, nil
		}
	})

	ctx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	go func() {
		conn, _ := client.DialTCP(ctx, "tcp4", "", netip.AddrPortFrom(spooferTestIPv4, 443).String())
		if conn != nil {
			_ = conn.Close()
		}
	}()
	select {
	case <-prepareStarted:
	case <-time.After(time.Second):
		t.Fatal("PrepareTCP was not called")
	}
	cancelSpoofer()
	select {
	case <-handlerClosed:
	case <-time.After(time.Second):
		t.Fatal("prepared handler was not closed after cancellation")
	}
}
