package vtun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/asciimoth/gonnect-netstack/helpers"
	xicmp "golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	xipv6 "golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// PingConn sends ICMP Echo Request messages and reads Echo Reply payloads.
type PingConn struct {
	laddr    PingAddr
	raddr    PingAddr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
	seq      uint32
}

// PingAddr represents an ICMP ping address.
type PingAddr struct {
	netip.Addr
}

// String returns the string representation of the ping address.
func (ia PingAddr) String() string {
	return ia.Addr.String()
}

// Network returns the network type for the ping address (ping4 or ping6).
func (ia PingAddr) Network() string {
	if ia.Is4() {
		return "ping4"
	} else if ia.Is6() {
		return "ping6"
	}
	return "ping"
}

// LocalAddr returns the local address of the ping connection.
func (pc *PingConn) LocalAddr() net.Addr {
	return pc.laddr
}

// RemoteAddr returns the remote address of the ping connection.
func (pc *PingConn) RemoteAddr() net.Addr {
	return pc.raddr
}

// Close closes the ping connection.
func (pc *PingConn) Close() error {
	pc.deadline.Reset(0)
	pc.ep.Close()
	return nil
}

// SetWriteDeadline sets the write deadline for the ping connection (unimplemented).
func (pc *PingConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

// WriteTo sends p as the payload of an ICMP Echo Request to addr.
func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var na netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		na = v.Addr
	case *net.IPAddr:
		na, _ = netip.AddrFromSlice(v.IP)
		na = na.Unmap()
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	if na.Is4() != pc.laddr.Is4() || na.Is6() != pc.laddr.Is6() {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	msg, err := pc.echoRequest(p, na)
	if err != nil {
		return 0, err
	}

	buf := bytes.NewReader(msg)
	rfa, _ := helpers.ConvertToFullAddr(netip.AddrPortFrom(na, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &rfa,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return len(p), nil
}

// Write sends p as the payload of an ICMP Echo Request to the remote address.
func (pc *PingConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.raddr)
}

func (pc *PingConn) echoRequest(p []byte, dst netip.Addr) ([]byte, error) {
	typ := xicmp.Type(xipv4.ICMPTypeEcho)
	if pc.laddr.Is6() {
		typ = xipv6.ICMPTypeEchoRequest
	}

	msg := &xicmp.Message{
		Type: typ,
		Code: 0,
		Body: &xicmp.Echo{
			Seq:  int(atomic.AddUint32(&pc.seq, 1) & 0xffff),
			Data: p,
		},
	}

	var pseudoHeader []byte
	if pc.laddr.Is6() {
		src := pc.laddr.Addr
		if !src.IsValid() || src.IsUnspecified() {
			src = netip.IPv6Unspecified()
		}
		pseudoHeader = xicmp.IPv6PseudoHeader(net.IP(src.AsSlice()), net.IP(dst.AsSlice()))
	}

	msgBytes, err := msg.Marshal(pseudoHeader)
	if err != nil {
		return nil, fmt.Errorf("ping write: marshal: %w", err)
	}
	return msgBytes, nil
}

// ReadFrom reads an ICMP Echo Reply payload and returns the remote address.
func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	raw := make([]byte, len(p)+8)
	w := tcpip.SliceWriter(raw)

	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	payload, err := pc.echoPayload(raw[:res.Count])
	if err != nil {
		return 0, nil, err
	}

	return copy(p, payload), &PingAddr{remoteAddr}, nil
}

func (pc *PingConn) echoPayload(raw []byte) ([]byte, error) {
	proto := xipv4.ICMPTypeEchoReply.Protocol()
	if pc.laddr.Is6() {
		proto = xipv6.ICMPTypeEchoReply.Protocol()
	}
	msg, err := xicmp.ParseMessage(proto, raw)
	if err != nil {
		return nil, fmt.Errorf("ping read: parse: %w", err)
	}
	echo, ok := msg.Body.(*xicmp.Echo)
	if !ok {
		return nil, fmt.Errorf("ping read: unexpected ICMP body %T", msg.Body)
	}
	return echo.Data, nil
}

// Read reads an ICMP Echo Reply payload.
func (pc *PingConn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return
}

// SetDeadline sets both read and write deadlines for the ping connection.
func (pc *PingConn) SetDeadline(t time.Time) error {
	// pc.SetWriteDeadline is unimplemented

	return pc.SetReadDeadline(t)
}

// SetReadDeadline sets the read deadline for the ping connection.
func (pc *PingConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}
