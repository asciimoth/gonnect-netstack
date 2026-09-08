package vtun_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/gonnect/tun"
)

const (
	ipProtocolICMPv4 = 1
	ipProtocolTCP    = 6
	ipProtocolUDP    = 17
	ipProtocolICMPv6 = 58
)

type outboundIPPacket struct {
	source      netip.Addr
	destination netip.Addr
	protocol    byte
	tcpFlags    byte
}

func buildSourceRouteVTun(t *testing.T, opts vtun.Opts) *vtun.VTun {
	t.Helper()

	device, err := opts.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := device.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})
	return device
}

func closeTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func parseOutboundIPPacket(packet []byte) (outboundIPPacket, error) {
	if len(packet) == 0 {
		return outboundIPPacket{}, fmt.Errorf("empty packet")
	}

	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return outboundIPPacket{}, fmt.Errorf("short IPv4 packet: %d bytes", len(packet))
		}
		parsed := outboundIPPacket{
			source:      netip.AddrFrom4([4]byte(packet[12:16])),
			destination: netip.AddrFrom4([4]byte(packet[16:20])),
			protocol:    packet[9],
		}
		transportOffset := int(packet[0]&0x0f) * 4
		if parsed.protocol == ipProtocolTCP && len(packet) > transportOffset+13 {
			parsed.tcpFlags = packet[transportOffset+13]
		}
		return parsed, nil
	case 6:
		if len(packet) < 40 {
			return outboundIPPacket{}, fmt.Errorf("short IPv6 packet: %d bytes", len(packet))
		}
		parsed := outboundIPPacket{
			source:      netip.AddrFrom16([16]byte(packet[8:24])),
			destination: netip.AddrFrom16([16]byte(packet[24:40])),
			protocol:    packet[6],
		}
		if parsed.protocol == ipProtocolTCP && len(packet) > 53 {
			parsed.tcpFlags = packet[53]
		}
		return parsed, nil
	default:
		return outboundIPPacket{}, fmt.Errorf("unsupported IP version %d", packet[0]>>4)
	}
}

// readOutboundIPPacket skips packets from prior closed or retransmitted flows.
// This makes it possible to use one VTun for several packet-level checks.
func readOutboundIPPacket(
	t *testing.T,
	device *vtun.VTun,
	destination netip.Addr,
	protocol byte,
) outboundIPPacket {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		type readResult struct {
			packet []byte
			err    error
		}
		result := make(chan readResult, 1)
		go func() {
			buf := [][]byte{make([]byte, 65535)}
			sizes := make([]int, 1)
			n, err := device.Read(buf, sizes, 0)
			if err != nil {
				result <- readResult{err: err}
				return
			}
			if n != 1 {
				result <- readResult{err: fmt.Errorf("Read() returned %d packets", n)}
				return
			}
			result <- readResult{packet: slices.Clone(buf[0][:sizes[0]])}
		}()

		remaining := time.Until(deadline)
		select {
		case got := <-result:
			if got.err != nil {
				t.Fatalf("Read() failed: %v", got.err)
			}
			parsed, err := parseOutboundIPPacket(got.packet)
			if err != nil {
				t.Fatalf("parse outbound packet: %v", err)
			}
			if parsed.destination == destination && parsed.protocol == protocol &&
				(protocol != ipProtocolTCP || parsed.tcpFlags&0x02 != 0) {
				return parsed
			}
		case <-time.After(remaining):
			t.Fatalf("timeout waiting for protocol %d packet to %s", protocol, destination)
		}
	}

	t.Fatalf("timeout waiting for protocol %d packet to %s", protocol, destination)
	return outboundIPPacket{}
}

func assertPacketSource(
	t *testing.T,
	device *vtun.VTun,
	destination, wantSource netip.Addr,
	protocol byte,
) {
	t.Helper()
	packet := readOutboundIPPacket(t, device, destination, protocol)
	if packet.source != wantSource {
		t.Fatalf(
			"protocol %d packet to %s has source %s, want %s",
			protocol, destination, packet.source, wantSource,
		)
	}
}

func sendUDP(t *testing.T, device *vtun.VTun, local netip.Addr, destination netip.Addr) {
	t.Helper()
	localAddrPort := netip.AddrPort{}
	if local.IsValid() {
		localAddrPort = netip.AddrPortFrom(local, 0)
	}
	conn, err := device.DialUDPAddrPort(localAddrPort, netip.AddrPortFrom(destination, 42000))
	if err != nil {
		t.Fatalf("DialUDPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, conn)
	if _, err := conn.Write([]byte("source-route-test")); err != nil {
		t.Fatalf("UDP Write() failed: %v", err)
	}
}

func sendTCP(t *testing.T, device *vtun.VTun, destination netip.Addr) {
	t.Helper()
	conn, err := device.DialTCPAddrPort(
		context.Background(),
		netip.AddrPortFrom(destination, 42001),
	)
	if err != nil {
		t.Fatalf("DialTCPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, conn)
}

func TestSourceRoutesIPv4TCPAndUDP(t *testing.T) {
	defaultSource := netip.MustParseAddr("10.20.0.2")
	carrierSource := netip.MustParseAddr("100.64.0.2")
	specificSource := netip.MustParseAddr("100.80.0.2")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{defaultSource, carrierSource, specificSource},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("100.64.0.0/10"), Source: carrierSource},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: defaultSource},
			{Destination: netip.MustParsePrefix("100.80.0.0/16"), Source: specificSource},
		},
	})

	tests := []struct {
		destination string
		wantSource  netip.Addr
	}{
		{destination: "100.80.0.1", wantSource: specificSource},
		{destination: "100.100.0.1", wantSource: carrierSource},
		{destination: "203.0.113.1", wantSource: defaultSource},
	}
	for _, test := range tests {
		destination := netip.MustParseAddr(test.destination)
		sendUDP(t, device, netip.Addr{}, destination)
		assertPacketSource(t, device, destination, test.wantSource, ipProtocolUDP)
	}

	for _, test := range tests {
		destination := netip.MustParseAddr(test.destination)
		sendTCP(t, device, destination)
		assertPacketSource(t, device, destination, test.wantSource, ipProtocolTCP)
	}
}

func TestSourceRoutesIPv6TCPUDPAndICMP(t *testing.T) {
	// The default source is most similar to the destination. This arrangement
	// verifies the route policy instead of gVisor's automatic prefix-similarity
	// selection.
	defaultSource := netip.MustParseAddr("2001:db8:1234::2")
	broadSource := netip.MustParseAddr("2001:db8:aaaa::2")
	specificSource := netip.MustParseAddr("2001:db8:ffff::2")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{defaultSource, broadSource, specificSource},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("::/0"), Source: defaultSource},
			{Destination: netip.MustParsePrefix("2001:db8:1200::/40"), Source: broadSource},
			{Destination: netip.MustParsePrefix("2001:db8:1234::/48"), Source: specificSource},
		},
	})

	destination := netip.MustParseAddr("2001:db8:1234::1")
	sendUDP(t, device, netip.Addr{}, destination)
	assertPacketSource(t, device, destination, specificSource, ipProtocolUDP)

	sendTCP(t, device, destination)
	assertPacketSource(t, device, destination, specificSource, ipProtocolTCP)

	ping, err := device.DialPingAddr(netip.Addr{}, destination)
	if err != nil {
		t.Fatalf("DialPingAddr() failed: %v", err)
	}
	defer closeTestResource(t, ping)
	if got := ping.LocalAddr().(vtun.PingAddr).Addr; got != specificSource {
		t.Fatalf("Ping LocalAddr() = %s, want %s", got, specificSource)
	}
	if _, err := ping.Write([]byte("source-route-test")); err != nil {
		t.Fatalf("Ping Write() failed: %v", err)
	}
	assertPacketSource(t, device, destination, specificSource, ipProtocolICMPv6)
}

func TestSourceRoutesExplicitLocalAddressOverridesPolicy(t *testing.T) {
	policySource := netip.MustParseAddr("10.30.0.2")
	explicitSource := netip.MustParseAddr("10.30.0.3")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{policySource, explicitSource},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: policySource},
		},
	})

	udpDestination := netip.MustParseAddr("192.0.2.10")
	sendUDP(t, device, explicitSource, udpDestination)
	assertPacketSource(t, device, udpDestination, explicitSource, ipProtocolUDP)

	tcpDestination := netip.MustParseAddr("192.0.2.11")
	conn, err := device.DialTCP(
		context.Background(),
		"tcp4",
		netip.AddrPortFrom(explicitSource, 0).String(),
		netip.AddrPortFrom(tcpDestination, 42001).String(),
	)
	if err != nil {
		t.Fatalf("DialTCP() failed: %v", err)
	}
	defer closeTestResource(t, conn)
	assertPacketSource(t, device, tcpDestination, explicitSource, ipProtocolTCP)

	pingDestination := netip.MustParseAddr("192.0.2.12")
	ping, err := device.DialPingAddr(explicitSource, pingDestination)
	if err != nil {
		t.Fatalf("DialPingAddr() failed: %v", err)
	}
	defer closeTestResource(t, ping)
	if _, err := ping.Write([]byte("explicit-source")); err != nil {
		t.Fatalf("Ping Write() failed: %v", err)
	}
	assertPacketSource(t, device, pingDestination, explicitSource, ipProtocolICMPv4)
}

func TestSourceRoutesRejectUnassignedExplicitLocalAddress(t *testing.T) {
	assigned := netip.MustParseAddr("10.40.0.2")
	unassigned := netip.MustParseAddr("10.40.0.99")
	destination := netip.MustParseAddr("192.0.2.20")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{assigned},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: assigned},
		},
	})

	if _, err := device.DialUDPAddrPort(
		netip.AddrPortFrom(unassigned, 0),
		netip.AddrPortFrom(destination, 53),
	); err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("DialUDPAddrPort() error = %v, want unassigned-address error", err)
	}
	if _, err := device.DialTCP(
		context.Background(), "tcp4",
		netip.AddrPortFrom(unassigned, 0).String(),
		netip.AddrPortFrom(destination, 80).String(),
	); err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("DialTCP() error = %v, want unassigned-address error", err)
	}
	if _, err := device.DialPingAddr(unassigned, destination); err == nil || !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("DialPingAddr() error = %v, want unassigned-address error", err)
	}
}

func TestSourceRoutesMissingMatchIsNetworkUnreachable(t *testing.T) {
	ipv4Source := netip.MustParseAddr("10.50.0.2")
	ipv6Source := netip.MustParseAddr("2001:db8:50::2")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{ipv4Source, ipv6Source},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), Source: ipv4Source},
		},
	})

	unreachable := netip.MustParseAddr("192.0.2.30")
	if _, err := device.DialUDPAddrPort(
		netip.AddrPort{}, netip.AddrPortFrom(unreachable, 53),
	); err == nil || !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("DialUDPAddrPort() error = %v, want network unreachable", err)
	}
	if _, err := device.DialTCPAddrPort(
		context.Background(), netip.AddrPortFrom(unreachable, 80),
	); err == nil || !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("DialTCPAddrPort() error = %v, want network unreachable", err)
	}
	if _, err := device.DialPingAddr(netip.Addr{}, unreachable); err == nil || !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("DialPingAddr() error = %v, want network unreachable", err)
	}

	// IPv6 has no source policy, so it keeps its legacy default route.
	ipv6Destination := netip.MustParseAddr("2001:db8:ffff::1")
	sendUDP(t, device, netip.Addr{}, ipv6Destination)
	assertPacketSource(t, device, ipv6Destination, ipv6Source, ipProtocolUDP)
}

func TestSourceRouteValidation(t *testing.T) {
	ipv4Source := netip.MustParseAddr("10.60.0.2")
	otherIPv4Source := netip.MustParseAddr("10.60.0.3")
	ipv6Source := netip.MustParseAddr("2001:db8:60::2")

	tests := []struct {
		name    string
		routes  []vtun.SourceRoute
		wantErr string
	}{
		{
			name:    "invalid destination",
			routes:  []vtun.SourceRoute{{Source: ipv4Source}},
			wantErr: "destination prefix is invalid",
		},
		{
			name: "invalid source",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
			}},
			wantErr: "source address is invalid",
		},
		{
			name: "unspecified source",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
				Source:      netip.IPv4Unspecified(),
			}},
			wantErr: "is unspecified",
		},
		{
			name: "multicast source",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
				Source:      netip.MustParseAddr("224.0.0.1"),
			}},
			wantErr: "is multicast",
		},
		{
			name: "loopback source",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
				Source:      netip.MustParseAddr("127.0.0.1"),
			}},
			wantErr: "is loopback",
		},
		{
			name: "different families",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
				Source:      ipv6Source,
			}},
			wantErr: "different IP families",
		},
		{
			name: "unassigned source",
			routes: []vtun.SourceRoute{{
				Destination: netip.MustParsePrefix("192.0.2.0/24"),
				Source:      netip.MustParseAddr("10.60.0.99"),
			}},
			wantErr: "is not assigned",
		},
		{
			name: "conflict after masking",
			routes: []vtun.SourceRoute{
				{Destination: netip.MustParsePrefix("192.0.2.1/24"), Source: ipv4Source},
				{Destination: netip.MustParsePrefix("192.0.2.200/24"), Source: otherIPv4Source},
			},
			wantErr: "conflicting source addresses",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (&vtun.Opts{
				LocalAddrs:   []netip.Addr{ipv4Source, otherIPv4Source, ipv6Source},
				SourceRoutes: test.routes,
			}).Build()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Build() error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestSourceRoutesAreMaskedAndExactDuplicatesAreRemoved(t *testing.T) {
	source := netip.MustParseAddr("10.61.0.2")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{source},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("192.0.2.1/24"), Source: source},
			{Destination: netip.MustParsePrefix("192.0.2.200/24"), Source: source},
		},
	})

	routes := device.SourceRoutes()
	if len(routes) != 1 {
		t.Fatalf("SourceRoutes() returned %d routes, want 1", len(routes))
	}
	want := netip.MustParsePrefix("192.0.2.0/24")
	if routes[0].Destination != want {
		t.Fatalf("destination = %s, want %s", routes[0].Destination, want)
	}

	// The returned slice does not alias the active configuration.
	routes[0].Source = netip.MustParseAddr("10.61.0.99")
	if got := device.SourceRoutes()[0].Source; got != source {
		t.Fatalf("active source changed through returned slice: got %s, want %s", got, source)
	}
}

func TestSetSourceRoutesRejectsInvalidTableAtomically(t *testing.T) {
	source := netip.MustParseAddr("10.62.0.2")
	initial := []vtun.SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      source,
	}}
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs:   []netip.Addr{source},
		SourceRoutes: initial,
	})

	err := device.SetSourceRoutes([]vtun.SourceRoute{{
		Destination: netip.MustParsePrefix("192.0.2.0/24"),
		Source:      netip.MustParseAddr("10.62.0.99"),
	}})
	if err == nil || !strings.Contains(err.Error(), "is not assigned") {
		t.Fatalf("SetSourceRoutes() error = %v, want unassigned-address error", err)
	}
	if got := device.SourceRoutes(); !slices.Equal(got, initial) {
		t.Fatalf("SourceRoutes() = %v after rejected update, want %v", got, initial)
	}
}

func TestEmptySourceRoutesPreserveLegacySourceSelection(t *testing.T) {
	first := netip.MustParseAddr("10.70.0.2")
	second := netip.MustParseAddr("100.64.0.2")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{first, second},
	})

	udpDestination := netip.MustParseAddr("100.80.0.1")
	sendUDP(t, device, netip.Addr{}, udpDestination)
	assertPacketSource(t, device, udpDestination, first, ipProtocolUDP)

	tcpDestination := netip.MustParseAddr("100.80.0.2")
	sendTCP(t, device, tcpDestination)
	assertPacketSource(t, device, tcpDestination, first, ipProtocolTCP)
}

func TestSetSourceRoutesEmptyRestoresLegacySourceSelection(t *testing.T) {
	legacySource := netip.MustParseAddr("10.71.0.2")
	policySource := netip.MustParseAddr("10.71.0.3")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{legacySource, policySource},
		SourceRoutes: []vtun.SourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      policySource,
		}},
	})

	policyDestination := netip.MustParseAddr("192.0.2.71")
	sendUDP(t, device, netip.Addr{}, policyDestination)
	assertPacketSource(t, device, policyDestination, policySource, ipProtocolUDP)

	if err := device.SetSourceRoutes(nil); err != nil {
		t.Fatalf("SetSourceRoutes(nil) failed: %v", err)
	}
	legacyDestination := netip.MustParseAddr("192.0.2.72")
	sendUDP(t, device, netip.Addr{}, legacyDestination)
	assertPacketSource(t, device, legacyDestination, legacySource, ipProtocolUDP)
}

func TestSetSourceRoutesPreservesExistingICMPSource(t *testing.T) {
	oldSource := netip.MustParseAddr("2001:db8:72::2")
	newSource := netip.MustParseAddr("2001:db8:72::3")
	device := buildSourceRouteVTun(t, vtun.Opts{
		LocalAddrs: []netip.Addr{oldSource, newSource},
		SourceRoutes: []vtun.SourceRoute{{
			Destination: netip.MustParsePrefix("::/0"),
			Source:      oldSource,
		}},
	})

	oldDestination := netip.MustParseAddr("2001:db8:ffff::72")
	oldPing, err := device.DialPingAddr(netip.Addr{}, oldDestination)
	if err != nil {
		t.Fatalf("old DialPingAddr() failed: %v", err)
	}
	defer closeTestResource(t, oldPing)
	if err := device.SetSourceRoutes([]vtun.SourceRoute{{
		Destination: netip.MustParsePrefix("::/0"),
		Source:      newSource,
	}}); err != nil {
		t.Fatalf("SetSourceRoutes() failed: %v", err)
	}
	if _, err := oldPing.Write([]byte("existing flow")); err != nil {
		t.Fatalf("existing Ping Write() failed: %v", err)
	}
	assertPacketSource(t, device, oldDestination, oldSource, ipProtocolICMPv6)

	newDestination := netip.MustParseAddr("2001:db8:ffff::73")
	newPing, err := device.DialPingAddr(netip.Addr{}, newDestination)
	if err != nil {
		t.Fatalf("new DialPingAddr() failed: %v", err)
	}
	defer closeTestResource(t, newPing)
	if got := newPing.LocalAddr().(vtun.PingAddr).Addr; got != newSource {
		t.Fatalf("new Ping LocalAddr() = %s, want %s", got, newSource)
	}
	if _, err := newPing.Write([]byte("new flow")); err != nil {
		t.Fatalf("new Ping Write() failed: %v", err)
	}
	assertPacketSource(t, device, newDestination, newSource, ipProtocolICMPv6)
}

func connectSourceRouteVTuns(t *testing.T, clientOpts, serverOpts vtun.Opts) (*vtun.VTun, *vtun.VTun) {
	t.Helper()
	client := buildSourceRouteVTun(t, clientOpts)
	server := buildSourceRouteVTun(t, serverOpts)
	bridge := tun.NewP2P(nil, nil)
	bridge.SetA(client)
	bridge.SetB(server)
	t.Cleanup(bridge.Stop)
	return client, server
}

func parseNetAddrIP(addr net.Addr) (netip.Addr, error) {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	default:
		return netip.Addr{}, fmt.Errorf("address has type %T, want TCP or UDP address", addr)
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("cannot parse address %v", addr)
	}
	return parsed.Unmap(), nil

}

func netAddrIP(t *testing.T, addr net.Addr) netip.Addr {
	t.Helper()
	parsed, err := parseNetAddrIP(addr)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func acceptWithTimeout(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("Accept() failed: %v", got.err)
		}
		return got.conn
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for TCP connection")
		return nil
	}
}

func TestSetSourceRoutesPreservesExistingFlows(t *testing.T) {
	oldSource := netip.MustParseAddr("10.80.0.2")
	newSource := netip.MustParseAddr("10.80.0.3")
	serverAddress := netip.MustParseAddr("203.0.113.80")
	oldRoutes := []vtun.SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      oldSource,
	}}
	newRoutes := []vtun.SourceRoute{{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      newSource,
	}}
	client, server := connectSourceRouteVTuns(t, vtun.Opts{
		LocalAddrs:   []netip.Addr{oldSource, newSource},
		SourceRoutes: oldRoutes,
	}, vtun.Opts{LocalAddrs: []netip.Addr{serverAddress}})

	udpListener, err := server.ListenUDPAddrPort(netip.AddrPortFrom(serverAddress, 43000))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, udpListener)
	oldUDP, err := client.DialUDPAddrPort(
		netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 43000),
	)
	if err != nil {
		t.Fatalf("old DialUDPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, oldUDP)
	if _, err := oldUDP.Write([]byte("before update")); err != nil {
		t.Fatalf("old UDP Write() failed: %v", err)
	}
	buf := make([]byte, 64)
	if err := udpListener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("UDP SetReadDeadline() failed: %v", err)
	}
	_, remote, err := udpListener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("UDP ReadFrom() failed: %v", err)
	}
	if got := netAddrIP(t, remote); got != oldSource {
		t.Fatalf("old UDP source = %s, want %s", got, oldSource)
	}

	tcpListener, err := server.ListenTCPAddrPort(netip.AddrPortFrom(serverAddress, 43001))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, tcpListener)
	oldTCP, err := client.DialTCPAddrPort(
		context.Background(), netip.AddrPortFrom(serverAddress, 43001),
	)
	if err != nil {
		t.Fatalf("old DialTCPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, oldTCP)
	acceptedOldTCP := acceptWithTimeout(t, tcpListener)
	defer closeTestResource(t, acceptedOldTCP)
	if got := netAddrIP(t, acceptedOldTCP.RemoteAddr()); got != oldSource {
		t.Fatalf("old TCP source = %s, want %s", got, oldSource)
	}

	if err := client.SetSourceRoutes(newRoutes); err != nil {
		t.Fatalf("SetSourceRoutes() failed: %v", err)
	}

	if _, err := oldUDP.Write([]byte("after update")); err != nil {
		t.Fatalf("existing UDP Write() failed after update: %v", err)
	}
	_, remote, err = udpListener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("existing UDP ReadFrom() failed after update: %v", err)
	}
	if got := netAddrIP(t, remote); got != oldSource {
		t.Fatalf("existing UDP source = %s after update, want %s", got, oldSource)
	}

	if _, err := oldTCP.Write([]byte("after update")); err != nil {
		t.Fatalf("existing TCP Write() failed after update: %v", err)
	}
	if err := acceptedOldTCP.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("TCP SetReadDeadline() failed: %v", err)
	}
	if _, err := acceptedOldTCP.Read(buf); err != nil {
		t.Fatalf("existing TCP Read() failed after update: %v", err)
	}
	if got := netAddrIP(t, acceptedOldTCP.RemoteAddr()); got != oldSource {
		t.Fatalf("existing TCP source = %s after update, want %s", got, oldSource)
	}

	newUDP, err := client.DialUDPAddrPort(
		netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 43000),
	)
	if err != nil {
		t.Fatalf("new DialUDPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, newUDP)
	if _, err := newUDP.Write([]byte("new flow")); err != nil {
		t.Fatalf("new UDP Write() failed: %v", err)
	}
	_, remote, err = udpListener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("new UDP ReadFrom() failed: %v", err)
	}
	if got := netAddrIP(t, remote); got != newSource {
		t.Fatalf("new UDP source = %s, want %s", got, newSource)
	}

	newTCP, err := client.DialTCPAddrPort(
		context.Background(), netip.AddrPortFrom(serverAddress, 43001),
	)
	if err != nil {
		t.Fatalf("new DialTCPAddrPort() failed: %v", err)
	}
	defer closeTestResource(t, newTCP)
	acceptedNewTCP := acceptWithTimeout(t, tcpListener)
	defer closeTestResource(t, acceptedNewTCP)
	if got := netAddrIP(t, acceptedNewTCP.RemoteAddr()); got != newSource {
		t.Fatalf("new TCP source = %s, want %s", got, newSource)
	}
}

func truncatedDNSResponse(query []byte) []byte {
	response := slices.Clone(query)
	response[2] |= 0x82 // Set the response and truncated bits.
	response[3] |= 0x80 // Set recursion available.
	response[6] = 0
	response[7] = 0
	return response
}

func successfulIPv4DNSResponse(query []byte, answer [4]byte) []byte {
	response := slices.Clone(query)
	response[2] |= 0x80 // Set the response bit.
	response[3] |= 0x80 // Set recursion available.
	response[6] = 0
	response[7] = 1
	response = append(response,
		0xc0, 0x0c, // Compressed answer name.
		0x00, 0x01, // A record.
		0x00, 0x01, // Internet class.
		0x00, 0x00, 0x00, 0x3c, // 60-second TTL.
		0x00, 0x04, // Four-byte record data.
	)
	return append(response, answer[:]...)
}

func TestSourceRoutesApplyToDNSUDPAndTCPFallback(t *testing.T) {
	defaultSource := netip.MustParseAddr("10.90.0.2")
	dnsSource := netip.MustParseAddr("100.64.0.2")
	dnsServer := netip.MustParseAddr("100.80.0.1")
	client, server := connectSourceRouteVTuns(t, vtun.Opts{
		LocalAddrs:     []netip.Addr{defaultSource, dnsSource},
		NoLoopbackAddr: true,
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("100.64.0.0/10"), Source: dnsSource},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: defaultSource},
		},
		DnsServers: []netip.Addr{dnsServer},
	}, vtun.Opts{LocalAddrs: []netip.Addr{dnsServer}})

	udpListener, err := server.ListenUDPAddrPort(netip.AddrPortFrom(dnsServer, 53))
	if err != nil {
		t.Fatalf("DNS UDP listen failed: %v", err)
	}
	defer closeTestResource(t, udpListener)
	tcpListener, err := server.ListenTCPAddrPort(netip.AddrPortFrom(dnsServer, 53))
	if err != nil {
		t.Fatalf("DNS TCP listen failed: %v", err)
	}
	defer closeTestResource(t, tcpListener)

	udpSource := make(chan netip.Addr, 1)
	tcpSource := make(chan netip.Addr, 1)
	serverErrors := make(chan error, 2)
	go func() {
		buf := make([]byte, 512)
		if err := udpListener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverErrors <- err
			return
		}
		n, remote, err := udpListener.ReadFrom(buf)
		if err != nil {
			serverErrors <- err
			return
		}
		source, err := parseNetAddrIP(remote)
		if err != nil {
			serverErrors <- err
			return
		}
		udpSource <- source
		_, err = udpListener.WriteTo(truncatedDNSResponse(buf[:n]), remote)
		serverErrors <- err
	}()
	go func() {
		conn, err := tcpListener.Accept()
		if err != nil {
			serverErrors <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverErrors <- err
			return
		}
		source, err := parseNetAddrIP(conn.RemoteAddr())
		if err != nil {
			serverErrors <- err
			return
		}
		tcpSource <- source

		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			serverErrors <- err
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			serverErrors <- err
			return
		}
		response := successfulIPv4DNSResponse(query, [4]byte{192, 0, 2, 90})
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := conn.Write(append(length[:], response...)); err != nil {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := client.LookupIP(ctx, "ip4", "source-route.example")
	if err != nil {
		for range 2 {
			select {
			case serverErr := <-serverErrors:
				t.Logf("DNS server result before lookup failure: %v", serverErr)
			default:
			}
		}
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.90")) {
		t.Fatalf("LookupIP() = %v, want [192.0.2.90]", ips)
	}
	for range 2 {
		if err := <-serverErrors; err != nil {
			t.Fatalf("DNS server failed: %v", err)
		}
	}
	if got := <-udpSource; got != dnsSource {
		t.Fatalf("DNS UDP source = %s, want %s", got, dnsSource)
	}
	if got := <-tcpSource; got != dnsSource {
		t.Fatalf("DNS TCP source = %s, want %s", got, dnsSource)
	}
}
