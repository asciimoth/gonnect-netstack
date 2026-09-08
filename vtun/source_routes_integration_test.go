package vtun_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/asciimoth/gonnect-netstack/vtun"
)

// runTCPEcho verifies source selection and bidirectional data transfer through
// two bridged VTun stacks. localOverride is optional.
func runTCPEcho(
	t *testing.T,
	client, server *vtun.VTun,
	destination netip.Addr,
	port uint16,
	wantSource, localOverride netip.Addr,
) {
	t.Helper()

	remote := netip.AddrPortFrom(destination, port)
	listener, err := server.ListenTCPAddrPort(remote)
	if err != nil {
		t.Fatalf("ListenTCPAddrPort(%s) failed: %v", remote, err)
	}
	defer closeTestResource(t, listener)

	var clientConn net.Conn
	if localOverride.IsValid() {
		network := "tcp4"
		if destination.Is6() {
			network = "tcp6"
		}
		clientConn, err = client.DialTCP(
			context.Background(),
			network,
			netip.AddrPortFrom(localOverride, 0).String(),
			remote.String(),
		)
	} else {
		clientConn, err = client.DialTCPAddrPort(context.Background(), remote)
	}
	if err != nil {
		t.Fatalf("TCP dial to %s failed: %v", remote, err)
	}
	defer closeTestResource(t, clientConn)

	serverConn := acceptWithTimeout(t, listener)
	defer closeTestResource(t, serverConn)
	if got := netAddrIP(t, clientConn.LocalAddr()); got != wantSource {
		t.Fatalf("TCP client source for %s = %s, want %s", destination, got, wantSource)
	}
	if got := netAddrIP(t, serverConn.RemoteAddr()); got != wantSource {
		t.Fatalf("TCP server peer for %s = %s, want %s", destination, got, wantSource)
	}

	deadline := time.Now().Add(3 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("TCP client SetDeadline() failed: %v", err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("TCP server SetDeadline() failed: %v", err)
	}
	request := []byte("tcp request for " + destination.String())
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("TCP client Write() failed: %v", err)
	}
	received := make([]byte, len(request))
	if _, err := io.ReadFull(serverConn, received); err != nil {
		t.Fatalf("TCP server Read() failed: %v", err)
	}
	if !bytes.Equal(received, request) {
		t.Fatalf("TCP server received %q, want %q", received, request)
	}

	reply := []byte("tcp reply from " + destination.String())
	if _, err := serverConn.Write(reply); err != nil {
		t.Fatalf("TCP server Write() failed: %v", err)
	}
	received = make([]byte, len(reply))
	if _, err := io.ReadFull(clientConn, received); err != nil {
		t.Fatalf("TCP client Read() failed: %v", err)
	}
	if !bytes.Equal(received, reply) {
		t.Fatalf("TCP client received %q, want %q", received, reply)
	}
}

// runUDPEcho verifies source selection and request-response traffic through two
// bridged VTun stacks. localOverride is optional.
func runUDPEcho(
	t *testing.T,
	client, server *vtun.VTun,
	destination netip.Addr,
	port uint16,
	wantSource, localOverride netip.Addr,
) {
	t.Helper()

	remote := netip.AddrPortFrom(destination, port)
	listener, err := server.ListenUDPAddrPort(remote)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort(%s) failed: %v", remote, err)
	}
	defer closeTestResource(t, listener)

	local := netip.AddrPort{}
	if localOverride.IsValid() {
		local = netip.AddrPortFrom(localOverride, 0)
	}
	clientConn, err := client.DialUDPAddrPort(local, remote)
	if err != nil {
		t.Fatalf("UDP dial to %s failed: %v", remote, err)
	}
	defer closeTestResource(t, clientConn)
	if got := netAddrIP(t, clientConn.LocalAddr()); got != wantSource {
		t.Fatalf("UDP client source for %s = %s, want %s", destination, got, wantSource)
	}

	deadline := time.Now().Add(3 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("UDP client SetDeadline() failed: %v", err)
	}
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatalf("UDP server SetDeadline() failed: %v", err)
	}
	request := []byte("udp request for " + destination.String())
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("UDP client Write() failed: %v", err)
	}
	received := make([]byte, 256)
	n, peer, err := listener.ReadFrom(received)
	if err != nil {
		t.Fatalf("UDP server ReadFrom() failed: %v", err)
	}
	if got := netAddrIP(t, peer); got != wantSource {
		t.Fatalf("UDP server peer for %s = %s, want %s", destination, got, wantSource)
	}
	if !bytes.Equal(received[:n], request) {
		t.Fatalf("UDP server received %q, want %q", received[:n], request)
	}

	reply := []byte("udp reply from " + destination.String())
	if _, err := listener.WriteTo(reply, peer); err != nil {
		t.Fatalf("UDP server WriteTo() failed: %v", err)
	}
	n, err = clientConn.Read(received)
	if err != nil {
		t.Fatalf("UDP client Read() failed: %v", err)
	}
	if !bytes.Equal(received[:n], reply) {
		t.Fatalf("UDP client received %q, want %q", received[:n], reply)
	}
}

// runPingEcho verifies source selection and an end-to-end ICMP echo exchange.
func runPingEcho(
	t *testing.T,
	client *vtun.VTun,
	destination, wantSource netip.Addr,
) {
	t.Helper()

	conn, err := client.DialPingAddr(netip.Addr{}, destination)
	if err != nil {
		t.Fatalf("DialPingAddr(%s) failed: %v", destination, err)
	}
	defer closeTestResource(t, conn)
	if got := conn.LocalAddr().(vtun.PingAddr).Addr; got != wantSource {
		t.Fatalf("ICMP source for %s = %s, want %s", destination, got, wantSource)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("ICMP SetReadDeadline() failed: %v", err)
	}
	payload := []byte("icmp request for " + destination.String())
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("ICMP Write() failed: %v", err)
	}
	received := make([]byte, len(payload))
	n, peer, err := conn.ReadFrom(received)
	if err != nil {
		t.Fatalf("ICMP ReadFrom() failed: %v", err)
	}
	if got := peer.(*vtun.PingAddr).Addr; got != destination {
		t.Fatalf("ICMP reply source = %s, want %s", got, destination)
	}
	if !bytes.Equal(received[:n], payload) {
		t.Fatalf("ICMP reply = %q, want %q", received[:n], payload)
	}
}

func TestSourceRoutesIntegrationOverlappingIPv4Identities(t *testing.T) {
	defaultSource := netip.MustParseAddr("10.20.0.2")
	carrierSource := netip.MustParseAddr("100.64.0.2")
	specificSource := netip.MustParseAddr("172.16.0.2")
	overrideSource := netip.MustParseAddr("192.168.50.2")
	specificDestination := netip.MustParseAddr("100.80.10.1")
	carrierDestination := netip.MustParseAddr("100.100.10.1")
	defaultDestination := netip.MustParseAddr("198.51.100.10")

	client, server := connectSourceRouteVTuns(t, vtun.Opts{
		LocalAddrs: []netip.Addr{
			defaultSource,
			carrierSource,
			specificSource,
			overrideSource,
		},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("100.64.0.0/10"), Source: carrierSource},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: defaultSource},
			{Destination: netip.MustParsePrefix("100.80.0.0/16"), Source: specificSource},
		},
	}, vtun.Opts{
		LocalAddrs: []netip.Addr{
			specificDestination,
			carrierDestination,
			defaultDestination,
		},
	})

	tests := []struct {
		name        string
		destination netip.Addr
		wantSource  netip.Addr
	}{
		{name: "most specific route", destination: specificDestination, wantSource: specificSource},
		{name: "broader route", destination: carrierDestination, wantSource: carrierSource},
		{name: "default route", destination: defaultDestination, wantSource: defaultSource},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := uint16(44000 + i*10)
			runTCPEcho(t, client, server, test.destination, port, test.wantSource, netip.Addr{})
			runUDPEcho(t, client, server, test.destination, port+1, test.wantSource, netip.Addr{})
		})
	}

	// A caller-selected local address has priority even for a destination that
	// matches the most-specific source route.
	runTCPEcho(t, client, server, specificDestination, 44080, overrideSource, overrideSource)
	runUDPEcho(t, client, server, specificDestination, 44081, overrideSource, overrideSource)
}

func TestSourceRoutesIntegrationDualStackPolicyReplacement(t *testing.T) {
	v4DefaultSource := netip.MustParseAddr("10.100.0.2")
	v4PolicySource := netip.MustParseAddr("198.18.0.2")
	v6DefaultSource := netip.MustParseAddr("2001:db8:200::2")
	v6PolicySource := netip.MustParseAddr("2001:db8:ffff::2")
	v4Destination := netip.MustParseAddr("203.0.113.200")
	v6Destination := netip.MustParseAddr("2001:db8:200::200")

	initialRoutes := []vtun.SourceRoute{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: v4DefaultSource},
		{Destination: netip.MustParsePrefix("203.0.113.0/24"), Source: v4PolicySource},
		{Destination: netip.MustParsePrefix("::/0"), Source: v6DefaultSource},
		{Destination: netip.MustParsePrefix("2001:db8:200::/48"), Source: v6PolicySource},
	}
	client, server := connectSourceRouteVTuns(t, vtun.Opts{
		LocalAddrs: []netip.Addr{
			v4DefaultSource,
			v4PolicySource,
			v6DefaultSource,
			v6PolicySource,
		},
		SourceRoutes: initialRoutes,
	}, vtun.Opts{LocalAddrs: []netip.Addr{v4Destination, v6Destination}})

	runTCPEcho(t, client, server, v4Destination, 44100, v4PolicySource, netip.Addr{})
	runUDPEcho(t, client, server, v6Destination, 44101, v6PolicySource, netip.Addr{})
	runPingEcho(t, client, v4Destination, v4PolicySource)
	runPingEcho(t, client, v6Destination, v6PolicySource)

	// Replace both family policies in one operation. The IPv4 route changes,
	// while the IPv6 route stays stable.
	replacement := slices.Clone(initialRoutes)
	replacement[1].Source = v4DefaultSource
	if err := client.SetSourceRoutes(replacement); err != nil {
		t.Fatalf("SetSourceRoutes() failed: %v", err)
	}
	runUDPEcho(t, client, server, v4Destination, 44110, v4DefaultSource, netip.Addr{})
	runTCPEcho(t, client, server, v6Destination, 44111, v6PolicySource, netip.Addr{})
}

func successfulIPv6DNSResponse(query []byte, answer [16]byte) []byte {
	response := slices.Clone(query)
	response[2] |= 0x80 // Set the response bit.
	response[3] |= 0x80 // Set recursion available.
	response[6] = 0
	response[7] = 1
	response = append(response,
		0xc0, 0x0c, // Compressed answer name.
		0x00, 0x1c, // AAAA record.
		0x00, 0x01, // Internet class.
		0x00, 0x00, 0x00, 0x3c, // 60-second TTL.
		0x00, 0x10, // Sixteen-byte record data.
	)
	return append(response, answer[:]...)
}

func TestSourceRoutesIntegrationIPv6DNSUDPAndTCPFallback(t *testing.T) {
	defaultSource := netip.MustParseAddr("2001:db8:5300::2")
	dnsSource := netip.MustParseAddr("2001:db8:ffff::2")
	dnsServer := netip.MustParseAddr("2001:db8:5300::53")
	answer := netip.MustParseAddr("2001:db8:abcd::90")
	client, server := connectSourceRouteVTuns(t, vtun.Opts{
		LocalAddrs:     []netip.Addr{defaultSource, dnsSource},
		NoLoopbackAddr: true,
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("::/0"), Source: defaultSource},
			{Destination: netip.MustParsePrefix("2001:db8:5300::/64"), Source: dnsSource},
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
		response := successfulIPv6DNSResponse(query, answer.As16())
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := conn.Write(append(length[:], response...)); err != nil {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := client.LookupIP(ctx, "ip6", "source-route-v6.example")
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IP(answer.AsSlice())) {
		t.Fatalf("LookupIP() = %v, want [%s]", ips, answer)
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

func ExampleSourceRoute_dualStack() {
	options := vtun.Opts{
		LocalAddrs: []netip.Addr{
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("2001:db8::2"),
		},
		SourceRoutes: []vtun.SourceRoute{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: netip.MustParseAddr("10.0.0.2")},
			{Destination: netip.MustParsePrefix("::/0"), Source: netip.MustParseAddr("2001:db8::2")},
		},
	}
	fmt.Println(len(options.SourceRoutes))
	// Output: 2
}
