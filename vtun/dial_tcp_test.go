package vtun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type trackedDialConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newTrackedDialConn() *trackedDialConn {
	return &trackedDialConn{closed: make(chan struct{})}
}

func (*trackedDialConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*trackedDialConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *trackedDialConn) Close() error                   { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*trackedDialConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*trackedDialConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*trackedDialConn) SetDeadline(time.Time) error      { return nil }
func (*trackedDialConn) SetReadDeadline(time.Time) error  { return nil }
func (*trackedDialConn) SetWriteDeadline(time.Time) error { return nil }

func testDualStackCandidates() []tcpDialCandidate {
	return []tcpDialCandidate{
		{remote: "[2001:db8::10]:443"},
		{remote: "192.0.2.10:443"},
	}
}

func closeTCPDialTestConn(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func TestRaceTCPDialImmediateFailureStartsFallback(t *testing.T) {
	v6Err := errors.New("IPv6 route failed")
	winner := newTrackedDialConn()
	var attempts []string
	var attemptsMu sync.Mutex

	started := time.Now()
	conn, err := raceTCPDial(
		context.Background(), "tcp", "dual.test:443", testDualStackCandidates(), time.Hour,
		func(_ context.Context, candidate tcpDialCandidate) (net.Conn, error) {
			attemptsMu.Lock()
			attempts = append(attempts, candidate.remote)
			attemptsMu.Unlock()
			if strings.Contains(candidate.remote, "2001:db8") {
				return nil, v6Err
			}
			return winner, nil
		},
	)
	if err != nil {
		t.Fatalf("raceTCPDial() failed: %v", err)
	}
	defer closeTCPDialTestConn(t, conn)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fallback took %v after a definitive failure", elapsed)
	}
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if len(attempts) != 2 || !strings.Contains(attempts[0], "2001:db8") || attempts[1] != "192.0.2.10:443" {
		t.Fatalf("attempts = %v, want IPv6 then IPv4", attempts)
	}
}

func TestRaceTCPDialBlackholeUsesFallbackTimer(t *testing.T) {
	const fallbackDelay = 30 * time.Millisecond
	v4Started := make(chan time.Time, 1)
	winner := newTrackedDialConn()
	started := time.Now()

	conn, err := raceTCPDial(
		context.Background(), "tcp", "dual.test:443", testDualStackCandidates(), fallbackDelay,
		func(ctx context.Context, candidate tcpDialCandidate) (net.Conn, error) {
			if strings.Contains(candidate.remote, "2001:db8") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			v4Started <- time.Now()
			return winner, nil
		},
	)
	if err != nil {
		t.Fatalf("raceTCPDial() failed: %v", err)
	}
	defer closeTCPDialTestConn(t, conn)

	startTime := <-v4Started
	if elapsed := startTime.Sub(started); elapsed < fallbackDelay/2 {
		t.Fatalf("IPv4 started after %v, before fallback delay %v", elapsed, fallbackDelay)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blackhole fallback took %v", elapsed)
	}
}

func TestRaceTCPDialFastFirstCandidateDoesNotStartFallback(t *testing.T) {
	winner := newTrackedDialConn()
	var attempts atomic.Int32
	conn, err := raceTCPDial(
		context.Background(), "tcp", "dual.test:443", testDualStackCandidates(), time.Hour,
		func(context.Context, tcpDialCandidate) (net.Conn, error) {
			attempts.Add(1)
			return winner, nil
		},
	)
	if err != nil {
		t.Fatalf("raceTCPDial() failed: %v", err)
	}
	defer closeTCPDialTestConn(t, conn)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempt count = %d, want 1", got)
	}
}

func TestRaceTCPDialClosesLateSuccess(t *testing.T) {
	releaseV6 := make(chan struct{})
	v6Returned := make(chan struct{})
	late := newTrackedDialConn()
	winner := newTrackedDialConn()

	conn, err := raceTCPDial(
		context.Background(), "tcp", "dual.test:443", testDualStackCandidates(), time.Millisecond,
		func(_ context.Context, candidate tcpDialCandidate) (net.Conn, error) {
			if strings.Contains(candidate.remote, "2001:db8") {
				<-releaseV6
				close(v6Returned)
				return late, nil
			}
			return winner, nil
		},
	)
	if err != nil {
		t.Fatalf("raceTCPDial() failed: %v", err)
	}
	defer closeTCPDialTestConn(t, conn)
	close(releaseV6)
	select {
	case <-v6Returned:
	case <-time.After(time.Second):
		t.Fatal("late IPv6 attempt did not return")
	}
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("late successful connection was not closed")
	}
}

func TestRaceTCPDialAggregatesCandidateErrors(t *testing.T) {
	v6Err := errors.New("v6 refused")
	v4Err := errors.New("v4 unreachable")
	_, err := raceTCPDial(
		context.Background(), "tcp", "dual.test:443", testDualStackCandidates(), time.Hour,
		func(_ context.Context, candidate tcpDialCandidate) (net.Conn, error) {
			if strings.Contains(candidate.remote, "2001:db8") {
				return nil, v6Err
			}
			return nil, v4Err
		},
	)
	if err == nil {
		t.Fatal("raceTCPDial() succeeded, want failure")
	}
	if !errors.Is(err, v6Err) || !errors.Is(err, v4Err) {
		t.Fatalf("error %v does not retain both candidate errors", err)
	}
	for _, address := range []string{"[2001:db8::10]:443", "192.0.2.10:443"} {
		if !strings.Contains(err.Error(), address) {
			t.Errorf("error %q does not contain candidate %q", err, address)
		}
	}
}

func TestRaceTCPDialCancellationStopsAllAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	stopped := make(chan struct{}, 2)
	result := make(chan error, 1)
	go func() {
		_, err := raceTCPDial(
			ctx, "tcp", "dual.test:443", testDualStackCandidates(), time.Millisecond,
			func(ctx context.Context, _ tcpDialCandidate) (net.Conn, error) {
				started <- struct{}{}
				<-ctx.Done()
				stopped <- struct{}{}
				return nil, ctx.Err()
			},
		)
		result <- err
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("not all dial attempts started")
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("race error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("race did not return after cancellation")
	}
	for range 2 {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("a dial attempt remained after cancellation")
		}
	}
}

func TestTCPDialCandidatesInterleaveAndRestrictFamilies(t *testing.T) {
	lookupCalls := 0
	var lookupNetworks []string
	device := &VTun{
		hasV4: true,
		hasV6: true,
		lookup: func(_ context.Context, network, _ string) ([]net.IP, error) {
			lookupCalls++
			lookupNetworks = append(lookupNetworks, network)
			return []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("2001:db8::2"),
				net.ParseIP("192.0.2.1"),
				net.ParseIP("192.0.2.2"),
			}, nil
		},
	}

	tests := []struct {
		name    string
		network string
		local   string
		want    []string
	}{
		{
			name:    "dual stack stable interleave",
			network: "tcp",
			want: []string{
				"[2001:db8::1]:443",
				"192.0.2.1:443",
				"[2001:db8::2]:443",
				"192.0.2.2:443",
			},
		},
		{
			name:    "tcp4",
			network: "tcp4",
			want:    []string{"192.0.2.1:443", "192.0.2.2:443"},
		},
		{
			name:    "tcp6",
			network: "tcp6",
			want:    []string{"[2001:db8::1]:443", "[2001:db8::2]:443"},
		},
		{
			name:    "explicit IPv4 local address",
			network: "tcp",
			local:   "192.0.2.99:32100",
			want:    []string{"192.0.2.1:443", "192.0.2.2:443"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates, err := device.tcpDialCandidates(
				context.Background(), test.network, test.local, "dual.test:443",
			)
			if err != nil {
				t.Fatalf("tcpDialCandidates() failed: %v", err)
			}
			got := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				got = append(got, candidate.remote)
				if test.local != "" && candidate.local != test.local {
					t.Errorf("candidate local = %q, want %q", candidate.local, test.local)
				}
			}
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("candidate addresses = %v, want %v", got, test.want)
			}
		})
	}
	if lookupCalls != len(tests) {
		t.Fatalf("lookup calls = %d, want %d", lookupCalls, len(tests))
	}
	wantNetworks := []string{"ip", "ip4", "ip6", "ip"}
	if strings.Join(lookupNetworks, ",") != strings.Join(wantNetworks, ",") {
		t.Fatalf("lookup networks = %v, want %v", lookupNetworks, wantNetworks)
	}
}

func TestTCPDialCandidatesLiteralsBypassLookup(t *testing.T) {
	device := &VTun{
		hasV4: true,
		hasV6: true,
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("literal address used DNS lookup")
			return nil, nil
		},
	}

	for _, test := range []struct {
		network string
		remote  string
	}{
		{network: "tcp4", remote: "192.0.2.20:80"},
		{network: "tcp6", remote: "[2001:db8::20]:80"},
	} {
		candidates, err := device.tcpDialCandidates(
			context.Background(), test.network, "", test.remote,
		)
		if err != nil {
			t.Fatalf("tcpDialCandidates(%q) failed: %v", test.remote, err)
		}
		if len(candidates) != 1 || candidates[0].remote != test.remote {
			t.Fatalf("candidates for %q = %+v, want one literal", test.remote, candidates)
		}
	}
}

func TestTCPDialCandidatesWildcardLocalPortFollowsRemoteFamily(t *testing.T) {
	device := &VTun{
		hasV4: true,
		hasV6: true,
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("2001:db8::30"), net.ParseIP("192.0.2.30")}, nil
		},
	}
	candidates, err := device.tcpDialCandidates(
		context.Background(), "tcp", ":32000", "dual.test:443",
	)
	if err != nil {
		t.Fatalf("tcpDialCandidates() failed: %v", err)
	}
	want := []string{"[::]:32000", "0.0.0.0:32000"}
	for index, candidate := range candidates {
		if candidate.local != want[index] {
			t.Errorf("candidate %d local = %q, want %q", index, candidate.local, want[index])
		}
	}
}

func TestTCPDialCandidatesRejectUnsupportedLiteralFamily(t *testing.T) {
	device := &VTun{hasV4: true}
	_, err := device.tcpDialCandidates(
		context.Background(), "tcp6", "", "[2001:db8::40]:443",
	)
	if err == nil || !errors.Is(err, errNoSuitableAddress) {
		t.Fatalf("tcpDialCandidates() error = %v, want no suitable address", err)
	}
}

func TestLookupHostCustomResolverFiltersUnsupportedFamilies(t *testing.T) {
	device := &VTun{
		hasV4: true,
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("2001:db8::50"), net.ParseIP("192.0.2.50")}, nil
		},
	}
	hosts, err := device.LookupHost(context.Background(), "dual.test")
	if err != nil {
		t.Fatalf("LookupHost() failed: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "192.0.2.50" {
		t.Fatalf("LookupHost() = %v, want only supported IPv4 address", hosts)
	}
}

func TestInterleaveTCPAddrsPreservesOrderWithinFamilies(t *testing.T) {
	input := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}
	want := []netip.Addr{input[0], input[2], input[1], input[3]}
	got := interleaveTCPAddrs(input)
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("interleaved addresses = %v, want %v", got, want)
		}
	}
}
