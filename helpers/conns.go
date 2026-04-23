package helpers

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/asciimoth/gonnect"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Static type assertions
var (
	_ gonnect.TCPConn     = &TCPConn{}
	_ gonnect.TCPListener = &TCPListener{}
	_ gonnect.UDPConn     = &UDPConn{}
)

// TCPConn wraps a gonet.TCPConn and implements the gonnect.TCPConn interface.
// It provides methods for reading, writing, and configuring TCP connection
// parameters (though most configuration methods are no-ops for this implementation).
type TCPConn struct {
	*gonet.TCPConn
	Laddr, Raddr net.Addr
}

func (t *TCPConn) LocalAddr() net.Addr {
	laddr := t.TCPConn.LocalAddr()
	if laddr == nil {
		laddr = t.Laddr
	}
	return laddr
}

func (t *TCPConn) RemoteAddr() net.Addr {
	raddr := t.TCPConn.RemoteAddr()
	if raddr == nil {
		raddr = t.Raddr
	}
	return raddr
}

// ReadFrom copies data from the provided reader to the TCP connection.
func (t *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(t.TCPConn, r)
}

// WriteTo copies data from the TCP connection to the provided writer.
func (t *TCPConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, t.TCPConn)
}

// SetKeepAlive enables or disables TCP keep-alive (no-op for this implementation).
func (t *TCPConn) SetKeepAlive(keepalive bool) error {
	// noop for this type
	return nil
}

// SetKeepAliveConfig configures TCP keep-alive parameters (no-op for this implementation).
func (t *TCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	// noop for this type
	return nil
}

// SetKeepAlivePeriod sets the TCP keep-alive period (no-op for this implementation).
func (t *TCPConn) SetKeepAlivePeriod(d time.Duration) error {
	// noop for this type
	return nil
}

// SetLinger sets the linger behavior for socket close (no-op for this implementation).
func (t *TCPConn) SetLinger(sec int) error {
	// noop for this type
	return nil
}

// SetNoDelay enables or disables Nagle's algorithm (no-op for this implementation).
func (t *TCPConn) SetNoDelay(noDelay bool) error {
	// noop for this type
	return nil
}

// UDPConn wraps a gonet.UDPConn and implements the gonnect.UDPConn interface.
// It provides methods for reading and writing UDP packets with various address
// formats (net.UDPAddr and netip.AddrPort).
type UDPConn struct {
	*gonet.UDPConn
	Laddr, Raddr net.Addr
}

// ReadFromUDP reads a UDP packet and returns the number of bytes read, the remote
// address, and any error that occurred.
func (u *UDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	n, a, err := u.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	if udpAddr, ok := a.(*net.UDPAddr); ok {
		return n, udpAddr, nil
	}
	return 0, nil, ErrNotUDP
}

// ReadFromUDPAddrPort reads a UDP packet and returns the number of bytes read,
// the remote address as a netip.AddrPort, and any error that occurred.
func (u *UDPConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	n, a, err := u.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if udpAddr, ok := a.(*net.UDPAddr); ok {
		addrPort, _ := netip.AddrFromSlice(udpAddr.IP)
		return n, netip.AddrPortFrom(addrPort, uint16(udpAddr.Port)), nil
	}
	return 0, netip.AddrPort{}, ErrNotUDP
}

// WriteToUDP writes a UDP packet to the specified remote address.
func (u *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return u.WriteTo(b, addr)
}

// WriteToUDPAddrPort writes a UDP packet to the specified remote address given
// as a netip.AddrPort.
func (u *UDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	udpAddr := &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	}
	return u.WriteTo(b, udpAddr)
}

// ReadMsgUDP reads a UDP packet with out-of-band data and returns the number of
// bytes read, out-of-band bytes read, flags, remote address, and any error.
// Note: Out-of-band data is not supported.
func (u *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	// gonet.UDPConn doesn't support out-of-band data, so return what we can
	n, a, err := u.ReadFrom(b)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if udpAddr, ok := a.(*net.UDPAddr); ok {
		return n, 0, 0, udpAddr, nil
	}
	return 0, 0, 0, nil, ErrNotUDP
}

// ReadMsgUDPAddrPort reads a UDP packet with out-of-band data and returns the
// number of bytes read, out-of-band bytes read, flags, remote address as
// netip.AddrPort, and any error. Note: Out-of-band data is not supported.
func (u *UDPConn) ReadMsgUDPAddrPort(
	b, oob []byte,
) (n, oobn, flags int, addr netip.AddrPort, err error) {
	// gonet.UDPConn doesn't support out-of-band data, so return what we can
	n, a, err := u.ReadFrom(b)
	if err != nil {
		return 0, 0, 0, netip.AddrPort{}, err
	}
	if udpAddr, ok := a.(*net.UDPAddr); ok {
		addrPort, _ := netip.AddrFromSlice(udpAddr.IP)
		return n, 0, 0, netip.AddrPortFrom(addrPort, uint16(udpAddr.Port)), nil
	}
	return 0, 0, 0, netip.AddrPort{}, ErrNotUDP
}

// WriteMsgUDP writes a UDP packet with optional out-of-band data to the specified
// remote address. Note: Out-of-band data is not supported and will return an error
// if provided.
func (u *UDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	// gonet.UDPConn doesn't support out-of-band data
	if len(oob) > 0 {
		return 0, 0, &net.OpError{
			Op:  "write",
			Net: "udp",
			Err: fmt.Errorf("oob not supported"),
		}
	}
	n, err = u.WriteTo(b, addr)
	return n, 0, err
}

// WriteMsgUDPAddrPort writes a UDP packet with optional out-of-band data to the
// specified remote address given as netip.AddrPort. Note: Out-of-band data is not
// supported and will return an error if provided.
func (u *UDPConn) WriteMsgUDPAddrPort(
	b, oob []byte,
	addr netip.AddrPort,
) (n, oobn int, err error) {
	// gonet.UDPConn doesn't support out-of-band data
	if len(oob) > 0 {
		return 0, 0, &net.OpError{
			Op:  "write",
			Net: "udp",
			Err: fmt.Errorf("oob not supported"),
		}
	}
	udpAddr := &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	}
	n, err = u.WriteTo(b, udpAddr)
	return n, 0, err
}

func (u *UDPConn) LocalAddr() net.Addr {
	laddr := u.UDPConn.LocalAddr()
	if laddr == nil {
		laddr = u.Laddr
	}
	return laddr
}

func (u *UDPConn) RemoteAddr() net.Addr {
	raddr := u.UDPConn.RemoteAddr()
	if raddr == nil {
		raddr = u.Raddr
	}
	return raddr
}

// TCPListener wraps a gonet.TCPListener and implements the gonnect.TCPListener
// interface. It provides methods for accepting TCP connections.
type TCPListener struct {
	*gonet.TCPListener
	Address net.Addr
}

func (l *TCPListener) Addr() net.Addr {
	addr := l.TCPListener.Addr()
	if addr == nil {
		addr = l.Address
	}
	return addr
}

// Accept accepts the next incoming connection and returns it wrapped as a TCPConn.
func (l *TCPListener) Accept() (net.Conn, error) {
	c, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*gonet.TCPConn); ok {
		return &TCPConn{
			TCPConn: tc,
			Laddr:   l.Addr(),
		}, nil
	}
	return c, nil
}

// AcceptTCP accepts the next incoming TCP connection and returns it.
func (l *TCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	c, err := l.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*TCPConn); ok {
		return tc, nil
	}
	return nil, ErrNotTCP
}

func (l *TCPListener) SetDeadline(t time.Time) error {
	// noop for this type
	return nil
}
