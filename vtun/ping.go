package vtun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/asciimoth/gonnectnetstack/helpers"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// PingConn represents a connection for sending and receiving ICMP ping packets.
type PingConn struct {
	laddr    PingAddr
	raddr    PingAddr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
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

// WriteTo writes data to the specified address through the ping connection.
func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var na netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		na = v.Addr
	case *net.IPAddr:
		na, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	if na.Is4() != pc.laddr.Is4() || na.Is6() != pc.laddr.Is6() {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	buf := bytes.NewReader(p)
	rfa, _ := helpers.ConvertToFullAddr(netip.AddrPortFrom(na, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &rfa,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return int(n64), nil
}

// Write writes data to the remote address of the ping connection.
func (pc *PingConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.raddr)
}

// ReadFrom reads data from the ping connection and returns the remote address.
func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)

	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	return res.Count, &PingAddr{remoteAddr}, nil
}

// Read reads data from the ping connection.
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
