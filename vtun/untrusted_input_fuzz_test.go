package vtun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fuzzConn struct {
	*bytes.Reader
}

func (c *fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) LocalAddr() net.Addr              { return nil }
func (c *fuzzConn) RemoteAddr() net.Addr             { return nil }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }

type discardFuzzDispatcher struct{}

func (*discardFuzzDispatcher) DeliverNetworkPacket(
	tcpip.NetworkProtocolNumber,
	*stack.PacketBuffer,
) {
}

func (*discardFuzzDispatcher) DeliverLinkPacket(
	tcpip.NetworkProtocolNumber,
	*stack.PacketBuffer,
) {
}

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte{}, 0, uint16(0), false)
	f.Add([]byte{}, 0, uint16(4), false)
	f.Add([]byte("example.com:443"), 0, uint16(64), true)
	f.Add([]byte{0x45, 0, 0, 20}, 0, uint16(4), false)
	f.Add([]byte{0x60, 0, 0, 0}, -1, uint16(2), true)
	f.Add([]byte{0, 12, 0x12, 0x34, 0x81, 0x80}, 1, uint16(512), false)

	queryName, err := dnsmessage.NewName("example.com.")
	if err != nil {
		f.Fatal(err)
	}
	query := dnsmessage.Question{
		Name:  queryName,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	udpResponse := validFuzzDNSResponse(f, query)
	tcpResponse := make([]byte, len(udpResponse)+2)
	tcpResponse[0] = byte(len(udpResponse) >> 8)
	tcpResponse[1] = byte(len(udpResponse))
	copy(tcpResponse[2:], udpResponse)
	f.Add(udpResponse, 0, uint16(512), false)
	f.Add(tcpResponse, 0, uint16(512), false)

	f.Fuzz(func(t *testing.T, input []byte, offset int, bufferSize uint16, omitSizes bool) {
		if len(input) > 65537 {
			return
		}

		value := string(input)
		_ = isDomainName(value)
		_, _, _ = splitTCPAddress(value, false)
		_, _, _ = splitTCPAddress(value, true)
		_, _ = parseOptionalAddrPort(value)
		fuzzDialInputs(t, value, omitSizes)

		fuzzSourceRoutes(t, input)
		fuzzICMP(input)
		fuzzDNS(input, query)
		fuzzVTunWrite(t, input, offset)
		fuzzVTunRead(t, input, offset, int(bufferSize), omitSizes)
	})
}

func validFuzzDNSResponse(f *testing.F, query dnsmessage.Question) []byte {
	f.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 0x1234,
		Response:           true,
		RecursionAvailable: true,
	})
	if err := b.StartQuestions(); err != nil {
		f.Fatal(err)
	}
	if err := b.Question(query); err != nil {
		f.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		f.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{
		Name:  query.Name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}); err != nil {
		f.Fatal(err)
	}
	response, err := b.Finish()
	if err != nil {
		f.Fatal(err)
	}
	return response
}

func fuzzDialInputs(t *testing.T, value string, omitLocal bool) {
	t.Helper()
	vt := &VTun{
		hasV4: true,
		hasV6: true,
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{
				net.ParseIP("2001:db8::2"),
				net.ParseIP("192.0.2.2"),
			}, nil
		},
	}
	local := value
	if omitLocal {
		local = ""
	}
	candidates, err := vt.tcpDialCandidates(context.Background(), "tcp", local, value)
	if err == nil {
		for _, candidate := range candidates {
			if _, err := netip.ParseAddrPort(candidate.remote); err != nil {
				t.Fatalf("invalid remote candidate %q: %v", candidate.remote, err)
			}
			if candidate.local != "" {
				if _, err := netip.ParseAddrPort(candidate.local); err != nil {
					t.Fatalf("invalid local candidate %q: %v", candidate.local, err)
				}
			}
		}
	}
	_, _ = vt.LookupHost(context.Background(), value)
	_ = vt.runWithLookup(
		context.Background(),
		"udp",
		local,
		value,
		io.EOF,
		func(string, string) (bool, error) { return true, nil },
	)
}

func fuzzSourceRoutes(t *testing.T, input []byte) {
	t.Helper()
	local := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	selector := byte(0)
	bits := 24
	if len(input) > 0 {
		selector = input[0]
		bits = int(input[len(input)-1]) - 32
	}

	var destination netip.Addr
	var source netip.Addr
	if selector&1 == 0 {
		destination = netip.AddrFrom4([4]byte{198, 51, 100, selector})
		source = local[int(selector>>1)%len(local)]
	} else {
		var raw [16]byte
		copy(raw[:], input)
		destination = netip.AddrFrom16(raw)
		source = local[int(selector>>1)%len(local)]
	}
	routes := []SourceRoute{{Destination: netip.PrefixFrom(destination, bits), Source: source}}
	if selector&4 != 0 {
		routes = append(routes, routes[0])
	}
	normalized, err := normalizeSourceRoutes(routes, local)
	if err != nil {
		return
	}
	for _, route := range normalized {
		if route.Destination != route.Destination.Masked() {
			t.Fatalf("destination %s is not masked", route.Destination)
		}
		if route.Destination.Addr().Is4() != route.Source.Is4() {
			t.Fatalf("route has mixed families: %+v", route)
		}
	}
	if _, err := sourceRouteTable(1, true, true, normalized); err != nil {
		t.Fatalf("normalized routes produced an invalid table: %v", err)
	}
}

func fuzzICMP(input []byte) {
	for _, addr := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		pc := &PingConn{laddr: PingAddr{Addr: addr}}
		_, _ = pc.echoPayload(input)
	}
}

func fuzzDNS(input []byte, query dnsmessage.Question) {
	if p, h, err := dnsPacketRoundTrip(
		&fuzzConn{Reader: bytes.NewReader(input)},
		0x1234,
		query,
		nil,
	); err == nil {
		_ = checkHeader(&p, h)
		_ = skipToAnswer(&p, dnsmessage.TypeA)
	}
	if p, h, err := dnsStreamRoundTrip(
		&fuzzConn{Reader: bytes.NewReader(input)},
		0x1234,
		query,
		nil,
	); err == nil {
		_ = checkHeader(&p, h)
		_ = skipToAnswer(&p, dnsmessage.TypeA)
	}
}

func fuzzVTunWrite(t *testing.T, input []byte, offset int) {
	t.Helper()
	ep := channel.New(1, 65535, "")
	ep.Attach(&discardFuzzDispatcher{})
	vt := &VTun{ep: ep}
	_, _ = vt.Write([][]byte{input}, offset)
	ep.Close()
}

func fuzzVTunRead(t *testing.T, input []byte, offset, bufferSize int, omitSizes bool) {
	t.Helper()
	incoming := make(chan *buffer.View, 1)
	incoming <- buffer.NewViewWithData(input)
	vt := &VTun{
		incomingPacket: incoming,
		mtu:            max(len(input), 1),
	}
	bufs := [][]byte{make([]byte, bufferSize)}
	sizes := make([]int, 1)
	if omitSizes {
		sizes = nil
	}
	_, err := vt.Read(bufs, sizes, offset)
	if err != nil && err != io.ErrShortBuffer && err != io.EOF {
		t.Fatalf("Read returned unexpected error: %v", err)
	}
}
