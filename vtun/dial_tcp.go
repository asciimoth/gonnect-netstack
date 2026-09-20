package vtun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

type tcpDialCandidate struct {
	local  string
	remote string
}

type tcpDialResult struct {
	index int
	conn  net.Conn
	err   error
}

// tcpDialDecision makes success, cancellation, and late success atomic with
// respect to each other. This lets a late successful attempt close its own
// connection after another attempt has won.
type tcpDialDecision struct {
	mu      sync.Mutex
	decided bool
}

func (d *tcpDialDecision) claim() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.decided {
		return false
	}
	d.decided = true
	return true
}

func (d *tcpDialDecision) isDecided() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.decided
}

func (vt *VTun) dialResolvedTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	candidates, err := vt.tcpDialCandidates(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}

	conn, err := raceTCPDial(
		ctx,
		network,
		raddr,
		candidates,
		vt.tcpFallbackDelay,
		func(attemptCtx context.Context, candidate tcpDialCandidate) (net.Conn, error) {
			return vt.dialTCP(attemptCtx, network, candidate.local, candidate.remote)
		},
	)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(gonnect.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s %s: internal connection type %T is not TCP", network, raddr, conn)
	}
	return tcpConn, nil
}

// raceTCPDial starts candidates in their supplied, interleaved order. A
// failure advances the race immediately. Otherwise, the fallback timer
// advances it. The first completed connection owns the result.
func raceTCPDial(
	ctx context.Context,
	network, address string,
	candidates []tcpDialCandidate,
	fallbackDelay time.Duration,
	dial func(context.Context, tcpDialCandidate) (net.Conn, error),
) (net.Conn, error) {
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan tcpDialResult, len(candidates))
	failures := make([]error, len(candidates))
	decision := &tcpDialDecision{}
	next := 0
	active := 0

	startNext := func() {
		if next >= len(candidates) || decision.isDecided() {
			return
		}
		index := next
		candidate := candidates[index]
		next++
		active++
		go func() {
			conn, err := dial(attemptCtx, candidate)
			if err == nil {
				if decision.claim() {
					results <- tcpDialResult{index: index, conn: conn}
					return
				}
				_ = conn.Close()
				return
			}
			results <- tcpDialResult{index: index, err: err}
		}()
	}

	startNext()
	var timer *time.Timer
	var timerC <-chan time.Time
	armTimer := func() {
		timerC = nil
		if next >= len(candidates) || fallbackDelay < 0 || decision.isDecided() {
			return
		}
		if timer == nil {
			timer = time.NewTimer(fallbackDelay)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(fallbackDelay)
		}
		timerC = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	armTimer()

	for {
		select {
		case result := <-results:
			active--
			if result.err == nil {
				cancel()
				return result.conn, nil
			}
			candidate := candidates[result.index]
			failures[result.index] = fmt.Errorf("%s: %w", candidate.remote, result.err)

			if decision.isDecided() {
				// A successful attempt has claimed the race and has queued its
				// result. Do not start more work while this failure is handled.
				continue
			}
			if next < len(candidates) {
				startNext()
				armTimer()
				continue
			}
			if active == 0 {
				decision.claim()
				if ctx.Err() != nil {
					return nil, tcpDialError(network, address, ctx.Err(), failures)
				}
				return nil, tcpDialError(network, address, nil, failures)
			}

		case <-timerC:
			timerC = nil
			startNext()
			armTimer()

		case <-ctx.Done():
			if decision.claim() {
				cancel()
				return nil, tcpDialError(network, address, ctx.Err(), failures)
			}
			// A connection completed immediately before cancellation. Its
			// result is already queued and is the defined winner.
		}
	}
}

func tcpDialError(network, address string, contextErr error, failures []error) error {
	causes := make([]error, 0, len(failures)+1)
	if contextErr != nil {
		causes = append(causes, contextErr)
	}
	for _, err := range failures {
		if err != nil {
			causes = append(causes, err)
		}
	}
	if len(causes) == 0 {
		causes = append(causes, errNoSuitableAddress)
	}
	return &net.OpError{
		Op:  "dial",
		Net: network,
		Addr: &gonnect.NetAddr{
			Net:  network,
			Addr: address,
		},
		Err: errors.Join(causes...),
	}
}

func (vt *VTun) tcpDialCandidates(
	ctx context.Context,
	network, laddr, raddr string,
) ([]tcpDialCandidate, error) {
	remoteHost, remotePort, err := splitTCPAddress(raddr, false)
	if err != nil {
		return nil, err
	}
	remoteAddrs, err := vt.resolveTCPAddrs(ctx, network, remoteHost)
	if err != nil {
		return nil, err
	}
	remoteAddrs = interleaveTCPAddrs(remoteAddrs)

	localHost := ""
	var localPort uint16
	if laddr != "" {
		localHost, localPort, err = splitTCPAddress(laddr, true)
		if err != nil {
			return nil, err
		}
	}

	var localAddrs []netip.Addr
	localIsWildcard := localHost == ""
	if !localIsWildcard {
		localAddrs, err = vt.resolveTCPAddrs(ctx, network, localHost)
		if err != nil {
			return nil, err
		}
		for _, addr := range localAddrs {
			if addr.IsUnspecified() {
				localIsWildcard = true
				break
			}
		}
	}

	candidates := make([]tcpDialCandidate, 0, len(remoteAddrs))
	for _, remote := range remoteAddrs {
		remoteAddress := netip.AddrPortFrom(remote, remotePort).String()
		if localIsWildcard {
			local := ""
			if laddr != "" {
				wildcard := netip.IPv4Unspecified()
				if remote.Is6() {
					wildcard = netip.IPv6Unspecified()
				}
				local = netip.AddrPortFrom(wildcard, localPort).String()
			}
			candidates = append(candidates, tcpDialCandidate{local: local, remote: remoteAddress})
			continue
		}

		for _, local := range localAddrs {
			if local.Is4() != remote.Is4() {
				continue
			}
			candidates = append(candidates, tcpDialCandidate{
				local:  netip.AddrPortFrom(local, localPort).String(),
				remote: remoteAddress,
			})
		}
	}

	if len(candidates) == 0 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errNoSuitableAddress}
	}
	return candidates, nil
}

func splitTCPAddress(address string, local bool) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, &net.AddrError{Addr: address, Err: "missing port in address"}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		kind := "remote"
		if local {
			kind = "local"
		}
		return "", 0, &net.AddrError{Addr: address, Err: "invalid " + kind + " port"}
	}
	return host, uint16(port), nil
}

func (vt *VTun) resolveTCPAddrs(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if vt.tcpAddrAllowed(network, addr) {
			return []netip.Addr{addr}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errNoSuitableAddress}
	}

	vt.lookupMu.RLock()
	lookup := vt.lookup
	vt.lookupMu.RUnlock()
	var hosts []string
	if lookup != nil {
		ips, err := lookup(ctx, gonnect.FamilyFromNetwork(network), host)
		if err != nil {
			return nil, err
		}
		hosts = make([]string, 0, len(ips))
		for _, ip := range ips {
			hosts = append(hosts, ip.String())
		}
	} else {
		var err error
		hosts, err = vt.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	addrs := make([]netip.Addr, 0, len(hosts))
	seen := make(map[netip.Addr]struct{}, len(hosts))
	for _, value := range hosts {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !vt.tcpAddrAllowed(network, addr) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errNoSuitableAddress}
	}
	return addrs, nil
}

func (vt *VTun) tcpAddrAllowed(network string, addr netip.Addr) bool {
	family := gonnect.FamilyFromNetwork(network)
	if addr.Is4() {
		return vt.hasV4 && family != "ip6"
	}
	return addr.Is6() && vt.hasV6 && family != "ip4"
}

func interleaveTCPAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) < 2 {
		return addrs
	}
	v4 := make([]netip.Addr, 0, len(addrs))
	v6 := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	if len(v4) == 0 || len(v6) == 0 {
		return addrs
	}

	result := make([]netip.Addr, 0, len(addrs))
	preferV6 := addrs[0].Is6()
	for len(v4) != 0 || len(v6) != 0 {
		if preferV6 && len(v6) != 0 {
			result = append(result, v6[0])
			v6 = v6[1:]
		} else if !preferV6 && len(v4) != 0 {
			result = append(result, v4[0])
			v4 = v4[1:]
		} else if len(v6) != 0 {
			result = append(result, v6[0])
			v6 = v6[1:]
		} else {
			result = append(result, v4[0])
			v4 = v4[1:]
		}
		preferV6 = !preferV6
	}
	return result
}
