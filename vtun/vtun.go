// Package vtun provides a virtual tunnel implementation built on gVisor's netstack.
// It creates userspace network interfaces that support TCP, UDP, and ICMP protocols,
// with built-in DNS resolution capabilities. VTun implements multiple gonnect
// interfaces including Network, Resolver, InterfaceNetwork, UpDown, and tun.Tun.
package vtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	"net/netip"
	"os"

	"sync"
	"syscall"

	"github.com/asciimoth/gonnect"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/asciimoth/gonnect-netstack/helpers"
	ge "github.com/asciimoth/gonnect/errors"
	gh "github.com/asciimoth/gonnect/helpers"
	"github.com/asciimoth/gonnect/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TODO: Use complete DNS resolver instead of adhoc one

// Static type assertions
var (
	_ gonnect.Network          = &VTun{}
	_ gonnect.Resolver         = &VTun{}
	_ gonnect.InterfaceNetwork = &VTun{}
	_ gonnect.UpDown           = &VTun{}
	_ tun.Tun                  = &VTun{}

	_ gonnect.LookupHost = (&VTun{}).LookupHost
)

// Opts contains configuration options for creating a VTun virtual tunnel.
type Opts struct {
	// EndpointCh specifies the size of the endpoint channel buffer. Defaults to 1024.
	EndpointCh int
	// EventCh specifies the size of the event channel buffer. Defaults to 10.
	EventCh int

	// LocalAddrs contains the local IP addresses to assign to the tunnel.
	// If not provided, a random address from rarely used subnets will be generated.
	LocalAddrs []netip.Addr
	// DnsServers contains the DNS servers to use for name resolution.
	// Default: 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9
	DnsServers []netip.Addr
	// Lookup provides a custom DNS lookup function.
	// If not set, uses the built-in simple DNS resolver.
	Lookup gonnect.LookupIP

	// Name specifies the name of the tunnel interface. Default: "vtun".
	Name string

	// NoLoopbackAddr prevents adding loopback addresses (127.0.0.1 and ::1) to the
	// local addresses. This is useful when using the spoofer to prevent "martian
	// packet" errors when the stack chooses a loopback address as the source.
	NoLoopbackAddr bool

	// NetStackOpts provides additional netstack configuration options.
	NetStackOpts *helpers.Opts

	MWO, MRO int
}

func (o *Opts) name() string {
	if o != nil && o.Name != "" {
		return o.Name
	}
	return "vtun"
}

func (o *Opts) dns() []netip.Addr {
	if o != nil && o.DnsServers != nil {
		return o.DnsServers
	}
	return []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.4.4"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.0.0.1"),
		netip.MustParseAddr("9.9.9.9"),
	}
}

func (o *Opts) mwo() int {
	if o != nil {
		return o.MWO
	}
	return 0
}

func (o *Opts) mro() int {
	if o != nil {
		return o.MRO
	}
	return 0
}

func (o *Opts) lookup() gonnect.LookupIP {
	if o != nil {
		return o.Lookup
	}
	return nil
}

func (o *Opts) laddrs() []netip.Addr {
	loopback4 := netip.MustParseAddr("127.0.0.1")
	loopback6 := netip.MustParseAddr("::1")
	if o != nil && len(o.LocalAddrs) > 0 {
		addlb4 := !o.NoLoopbackAddr
		addlb6 := !o.NoLoopbackAddr
		laddrs := make([]netip.Addr, 0, len(o.LocalAddrs)+1)
		for _, addr := range o.LocalAddrs {
			laddrs = append(laddrs, addr)
			if addr.Compare(loopback4) == 0 {
				addlb4 = false
			} else if addr.Compare(loopback6) == 0 {
				addlb6 = false
			}
		}
		if addlb4 {
			laddrs = append(laddrs, loopback4)
		}
		if addlb6 {
			laddrs = append(laddrs, loopback6)
		}
		return laddrs
	}
	laddrs := []netip.Addr{}
	if ip4 := o.opts().GetIPAlloc().Alloc4(); ip4 != nil && ip4.To4() != nil {
		laddrs = append(laddrs, netip.AddrFrom4([4]byte(ip4.To4())))
	}
	if ip6 := o.opts().GetIPAlloc().Alloc6(); ip6 != nil && ip6.To16() != nil {
		laddrs = append(laddrs, netip.AddrFrom16([16]byte(ip6.To16())))
	}
	if !o.NoLoopbackAddr {
		laddrs = append(laddrs, loopback4)
		laddrs = append(laddrs, loopback6)
	}
	return laddrs
}

func (o *Opts) epch() int {
	if o != nil && o.EndpointCh != 0 {
		return o.EndpointCh
	}
	return 1024
}

func (o *Opts) evch() int {
	if o != nil && o.EventCh != 0 {
		return o.EventCh
	}
	return 10
}

func (o *Opts) opts() *helpers.Opts {
	if o != nil && o.NetStackOpts != nil {
		return o.NetStackOpts
	}
	return &helpers.Opts{}
}

// Build creates and initializes a new VTun virtual tunnel with the configured
// options. It sets up the network stack, creates a NIC,
// adds protocol addresses, and sets up routing for IPv4 and/or IPv6.
// Returns the initialized VTun instance or an error.
func (o *Opts) Build() (*VTun, error) {
	no := o.opts()
	st, err := no.BuildStack(true)
	if err != nil {
		return nil, err
	}
	localAddrs := o.laddrs()
	vt := &VTun{
		ep:             channel.New(o.epch(), uint32(no.GetMTU()), ""),
		stack:          st,
		events:         make(chan tun.Event, o.evch()),
		incomingPacket: make(chan *buffer.View, 256), // Buffered to prevent blocking WriteNotify
		dnsServers:     o.dns(),
		mtu:            no.GetMTU(),
		name:           o.name(),
		lookup:         o.lookup(),
		localAddrs:     localAddrs,
		mwo:            o.mwo(),
		mro:            o.mro(),
	}
	vt.notifyHandle = vt.ep.AddNotify(vt)
	nid, err := helpers.CreateNIC(st, nil, vt.ep)
	if err != nil {
		return nil, err
	}
	vt.nid = nid

	for _, ip := range localAddrs {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		{
			err := vt.stack.AddProtocolAddress(nid, protoAddr, stack.AddressProperties{})
			if err != nil {
				return nil, helpers.WrapErr(helpers.ErrNewAddr, err)
			}
		}
		if ip.Is4() {
			vt.hasV4 = true
		} else if ip.Is6() {
			vt.hasV6 = true
		}
	}
	if vt.hasV4 {
		vt.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nid})
	}
	if vt.hasV6 {
		vt.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nid})
	}

	vt.events <- tun.EventUp
	return vt, nil
}

// VTun represents a virtual tunnel network interface built on gVisor's netstack.
// It provides TCP/UDP dialing and listening capabilities, DNS resolution,
// ICMP ping support, and implements the gonnect Network and Resolver interfaces.
// It was originally borrowed from wireguard-go and then significantly modified
// to fit the gonnect ecosystem.
type VTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	name           string
	hasV4, hasV6   bool
	localAddrs     []netip.Addr

	lookupMu   sync.RWMutex
	dnsServers []netip.Addr
	lookup     gonnect.LookupIP

	mu      sync.RWMutex
	closed  bool
	down    bool
	nid     tcpip.NICID
	nextID  uint64
	closers map[uint64]io.Closer

	mwo, mro int
}

func (vt *VTun) MWO() int { return vt.mwo }
func (vt *VTun) MRO() int { return vt.mro }

// SetLookup sets a custom DNS lookup function for the VTun.
func (vt *VTun) SetLookup(fn gonnect.LookupIP) {
	vt.lookupMu.Lock()
	defer vt.lookupMu.Unlock()
	vt.lookup = fn
}

// getID returns the next unique ID for registering a connection/listener.
// Caller must hold vt.mu lock.
func (vt *VTun) getID() uint64 {
	id := vt.nextID
	vt.nextID++
	return id
}

// register stores a connection/listener in the registry for tracking.
// Caller must hold vt.mu lock.
func (vt *VTun) register(id uint64, c io.Closer) {
	if vt.closers == nil {
		vt.closers = make(map[uint64]io.Closer)
	}
	vt.closers[id] = c
}

// unregister removes a connection/listener from the registry.
func (vt *VTun) unregister(id uint64) {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	delete(vt.closers, id)
}

// buildUnregCallback returns a callback function that unregisters by ID.
func (vt *VTun) buildUnregCallback(id uint64) func() {
	return func() {
		vt.unregister(id)
	}
}

// registerConnCallback registers an accepted connection and wraps it with callbacks.
// Returns an error if the VTun is down.
func (vt *VTun) registerConnCallback(conn net.Conn, laddr, raddr net.Addr) (net.Conn, error) {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	if vt.down {
		return nil, errors.New("vtun is down")
	}

	// Wrap with helpers types first if needed
	var wrappedConn net.Conn
	if tc, ok := conn.(*gonet.TCPConn); ok {
		wrappedConn = &helpers.TCPConn{
			TCPConn: tc,
			Laddr:   laddr,
			Raddr:   raddr,
		}
	} else if uc, ok := conn.(*gonet.UDPConn); ok {
		wrappedConn = &helpers.UDPConn{
			UDPConn: uc,
			Laddr:   laddr,
			Raddr:   raddr,
		}
	} else {
		wrappedConn = conn
	}

	id := vt.getID()
	callbackWrapped := gonnect.ConnWithCallbacks(wrappedConn, &gonnect.Callbacks{
		BeforeClose: vt.buildUnregCallback(id),
	})
	vt.register(id, callbackWrapped)
	return callbackWrapped, nil
}

// GetDnsServers returns the list of configured DNS servers.
func (vt *VTun) GetDnsServers() []netip.Addr {
	vt.lookupMu.RLock()
	defer vt.lookupMu.RUnlock()
	return vt.dnsServers
}

// dialAddr returns the first non-loopback address for the given IP version,
// falling back to unspecified if none found. Used for outgoing connections
// to prevent "martian packet" errors when loopback addresses are configured.
func (vt *VTun) dialAddr(isV6 bool) netip.Addr {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	for _, addr := range vt.localAddrs {
		if addr.IsLoopback() {
			continue
		}
		if isV6 && addr.Is6() {
			return addr
		}
		if !isV6 && addr.Is4() {
			return addr
		}
	}

	// Fallback to unspecified if no non-loopback address found
	if isV6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

// SetDnsServers configures the DNS servers to use for name resolution.
func (vt *VTun) SetDnsServers(servers []netip.Addr) {
	vt.lookupMu.Lock()
	defer vt.lookupMu.Unlock()
	vt.dnsServers = servers
}

// WriteNotify is called when the endpoint has data available. It reads a packet
// from the endpoint and sends it to the incomingPacket channel.
func (vt *VTun) WriteNotify() {
	for {
		pkt := vt.ep.Read()
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		pkt.DecRef()
		vt.enqueueIncomingView(view)
	}
}

func (vt *VTun) enqueueIncomingView(view *buffer.View) {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	if vt.closed {
		view.Release()
		return
	}

	select {
	case vt.incomingPacket <- view:
	default:
		view.Release()
	}
}

// Name returns the name of the tun device.
func (vt *VTun) Name() (string, error) {
	return vt.name, nil
}

// File returns nil as the netTun device does not have an associated file descriptor.
func (vt *VTun) File() *os.File {
	return nil
}

// MTU returns the maximum transmission unit of the device.
func (vt *VTun) MTU() (int, error) {
	return vt.mtu, nil
}

// BatchSize returns the preferred number of packets that can be read or written
// in a single call. For netTun, this is always 1.
func (vt *VTun) BatchSize() int {
	return 1
}

// Events returns the channel through which device events are communicated.
func (vt *VTun) Events() <-chan tun.Event {
	return vt.events
}

// Read reads a single packet from the incomingPacket channel and writes it
// to the first buffer. It returns 1 for one packet read and the size of the packet.
func (vt *VTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-vt.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	defer view.Release()

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write writes packets to the device endpoint. It determines the IP version
// from the first nibble of each packet and injects it as an inbound packet
// to the appropriate protocol handler.
func (vt *VTun) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			vt.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			vt.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

// Close closes the netTun device by removing the NIC, closing the stack,
// removing notifications, closing the endpoint, and closing the channels.
func (vt *VTun) Close() error {
	vt.mu.Lock()
	if vt.closed {
		vt.mu.Unlock()
		return nil
	}
	vt.closed = true
	events := vt.events
	incomingPacket := vt.incomingPacket
	vt.mu.Unlock()

	vt.ep.RemoveNotify(vt.notifyHandle)
	vt.ep.Close()
	vt.stack.RemoveNIC(vt.nid)
	vt.stack.Close()

	if events != nil {
		close(events)
	}

	if incomingPacket != nil {
		for {
			select {
			case view := <-incomingPacket:
				if view != nil {
					view.Release()
				}
			default:
				close(incomingPacket)
				return nil
			}
		}
	}
	return nil
}

// DialTCPAddrPort establishes a TCP connection to the specified address and port.
// The connection is created through the VTun's network stack.
func (vt *VTun) DialTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	if err := vt.checkUp(); err != nil {
		return nil, err
	}
	fa, pn := helpers.ConvertToFullAddr(addr)

	var wq waiter.Queue
	ep, tcpipErr := vt.stack.NewEndpoint(tcp.ProtocolNumber, pn, &wq)
	if tcpipErr != nil {
		return nil, fmt.Errorf("tcp endpoint: %s", tcpipErr)
	}

	// Bind to a non-loopback address to prevent martian packet errors
	localAddr := vt.dialAddr(addr.Addr().Is6())
	bindFA := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(localAddr.AsSlice()),
		Port: 0,
		NIC:  vt.nid,
	}
	if tcpipErr = ep.Bind(bindFA); tcpipErr != nil {
		ep.Close()
		return nil, fmt.Errorf("tcp bind: %s", tcpipErr)
	}

	// Connect to remote address
	tcpipErr = ep.Connect(fa)
	if tcpipErr != nil {
		// ErrConnectStarted is expected for non-blocking TCP connect
		if _, ok := tcpipErr.(*tcpip.ErrConnectStarted); !ok {
			ep.Close()
			return nil, fmt.Errorf("tcp connect: %s", tcpipErr)
		}
	}

	return gonet.NewTCPConn(&wq, ep), nil
}

func (vt *VTun) dialTCP(
	ctx context.Context,
	network, raddr string,
) (gonnect.TCPConn, error) {
	var err error
	addr := netip.AddrPort{}
	if raddr != "" {
		addr, err = netip.ParseAddrPort(raddr)
		if err != nil {
			return nil, err
		}
	}

	conn, err := vt.DialTCPAddrPort(ctx, addr)
	if err != nil {
		return nil, err
	}

	// Wrap with helpers.TCPConn first
	wrapped := &helpers.TCPConn{
		TCPConn: conn,
		Laddr:   fallbackConnAddr(network, ""),
		Raddr:   fallbackConnAddr(network, raddr),
	}

	// Register with callbacks
	vt.mu.Lock()
	id := vt.getID()
	callbackWrapped := gonnect.ConnWithCallbacks(wrapped, &gonnect.Callbacks{
		BeforeClose: vt.buildUnregCallback(id),
	})
	vt.register(id, callbackWrapped)
	vt.mu.Unlock()

	// Return the callback-wrapped version
	return callbackWrapped.(gonnect.TCPConn), nil
}

// DialTCPAddrPort establishes a TCP connection to the specified address and port.
// Laddr is always ignored.
func (vt *VTun) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (conn gonnect.TCPConn, err error) {
	if !gh.IsTCPNetwork(network) {
		return nil, net.UnknownNetworkError(network)
	}
	err = vt.runWithLookup(
		ctx, network, "", raddr, ge.ConnRefused(network, raddr),
		func(laddr, raddr string) (bool, error) {
			conn, err = vt.dialTCP(ctx, network, raddr)
			if err != nil {
				return false, err
			}
			return true, nil
		},
	)
	return
}

// ListenTCPAddrPort listens for incoming TCP connections on the specified address and port.
// Supports wildcard binding:
//   - 0.0.0.0:port or :port binds to first local IPv4 address
//   - [::]:port binds to first local IPv6 address
func (vt *VTun) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	if err := vt.checkUp(); err != nil {
		return nil, err
	}
	// For wildcard addresses, bind to first local address
	if addr.Addr().IsUnspecified() || !addr.Addr().IsValid() {
		var bindAddr netip.Addr
		if addr.Addr().Is6() {
			for _, a := range vt.getLocalAddrs() {
				if a.Is6() {
					bindAddr = a
					break
				}
			}
			if !bindAddr.IsValid() {
				bindAddr = netip.IPv6Unspecified()
			}
		} else {
			for _, a := range vt.getLocalAddrs() {
				if a.Is4() {
					bindAddr = a
					break
				}
			}
			if !bindAddr.IsValid() {
				bindAddr = netip.IPv4Unspecified()
			}
		}
		addr = netip.AddrPortFrom(bindAddr, addr.Port())
	}

	fa, pn := helpers.ConvertToFullAddr(addr)
	return gonet.ListenTCP(vt.stack, fa, pn)
}

func (vt *VTun) listenTCP(
	network, laddr string,
) (gonnect.TCPListener, error) {
	addr, err := helpers.AddrPortFromString(laddr)
	if err != nil {
		return nil, err
	}

	l, err := vt.ListenTCPAddrPort(addr)
	if err != nil {
		return nil, err
	}

	vt.mu.Lock()
	id := vt.getID()
	// Wrap with helpers.TCPListener first so ListenerWithCallbacks detects it as TCPListener
	wrapped := &helpers.TCPListener{
		TCPListener: l,
		Address:     fallbackListenerAddr(network, addr.String()),
	}
	listener := gonnect.ListenerWithCallbacks(wrapped, &gonnect.Callbacks{
		BeforeClose: vt.buildUnregCallback(id),
		OnAccept: func(c net.Conn) (net.Conn, error) {
			raddr := c.RemoteAddr()
			if raddr == nil {
				raddr = fallbackConnAddr(network, "")
			}
			return vt.registerConnCallback(c, fallbackConnAddr(network, addr.String()), raddr)
		},
	})
	vt.register(id, listener)
	vt.mu.Unlock()

	return listener.(gonnect.TCPListener), nil
}

func (vt *VTun) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (listener gonnect.TCPListener, err error) {
	if !gh.IsTCPNetwork(network) {
		return nil, net.UnknownNetworkError(network)
	}
	err = vt.runWithLookup(
		ctx, network, laddr, "", ge.ListenDeniedErr(network, laddr),
		func(laddr, raddr string) (bool, error) {
			listener, err = vt.listenTCP(network, laddr)
			if err != nil {
				return false, err
			}
			return true, nil
		},
	)
	return
}

// DialUDPAddrPort establishes a UDP connection with the specified local and
// remote addresses and ports. The connection can be used for sending and
// receiving UDP packets through the VTun's network stack.
func (vt *VTun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	if err := vt.checkUp(); err != nil {
		return nil, err
	}
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber

	// If no local address specified, use non-loopback address to prevent martian packets
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = helpers.ConvertToFullAddr(laddr)
		lfa = &addr
	} else {
		// Auto-select a non-loopback address
		isV6 := raddr.Addr().Is6()
		localAddr := vt.dialAddr(isV6)
		pn = ipv4.ProtocolNumber
		if isV6 {
			pn = ipv6.ProtocolNumber
		}
		lfa = &tcpip.FullAddress{
			Addr: tcpip.AddrFromSlice(localAddr.AsSlice()),
			Port: 0,
			NIC:  vt.nid,
		}
	}

	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = helpers.ConvertToFullAddr(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(vt.stack, lfa, rfa, pn)
}

// ListenUDPAddrPort listens for incoming UDP packets on the specified local address and port.
// Supports wildcard binding:
//   - 0.0.0.0:port or :port binds to first local IPv4 address
//   - [::]:port binds to first local IPv6 address
//   - Port-only addresses (e.g., netip.AddrPortFrom(netip.IPv4Unspecified(), 53)) bind to first local address
func (vt *VTun) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	if err := vt.checkUp(); err != nil {
		return nil, err
	}
	// For wildcard or unspecified addresses, bind to first local address
	if laddr.Addr().IsUnspecified() || !laddr.Addr().IsValid() {
		var bindAddr netip.Addr
		if laddr.Addr().Is6() {
			for _, a := range vt.getLocalAddrs() {
				if a.Is6() {
					bindAddr = a
					break
				}
			}
			if !bindAddr.IsValid() {
				bindAddr = netip.IPv6Unspecified()
			}
		} else {
			// IPv4 or invalid/empty address - prefer IPv4
			for _, a := range vt.getLocalAddrs() {
				if a.Is4() {
					bindAddr = a
					break
				}
			}
			if !bindAddr.IsValid() {
				bindAddr = netip.IPv4Unspecified()
			}
		}
		laddr = netip.AddrPortFrom(bindAddr, laddr.Port())
	}
	return vt.DialUDPAddrPort(laddr, netip.AddrPort{})
}

// getLocalAddrs returns the list of local addresses configured on this VTun.
func (vt *VTun) getLocalAddrs() []netip.Addr {
	return vt.localAddrs
}

// LocalAddrs returns a copy of the local addresses configured on this VTun.
// This is useful for dial operations where you need to know the VTun's address
// instead of using hardcoded constants.
func (vt *VTun) LocalAddrs() []netip.Addr {
	vt.mu.RLock()
	defer vt.mu.RUnlock()
	return slices.Clone(vt.localAddrs)
}

func (vt *VTun) dialUDP(
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	var err error
	lap := netip.AddrPort{}
	rap := netip.AddrPort{}
	if laddr != "" {
		// Check if laddr has a port; if not, treat it as address-only and let stack auto-bind
		if _, _, err := net.SplitHostPort(laddr); err == nil {
			lap, err = helpers.AddrPortFromString(laddr)
			if err != nil {
				return nil, err
			}
		}
		// If no port in laddr, leave lap empty for auto-bind
	}
	if raddr != "" {
		rap, err = helpers.AddrPortFromString(raddr)
		if err != nil {
			return nil, err
		}
	}

	c, err := vt.DialUDPAddrPort(lap, rap)
	if err != nil {
		return nil, err
	}

	// Wrap with helpers.UDPConn first
	wrapped := &helpers.UDPConn{
		UDPConn: c,
		Laddr:   fallbackConnAddr(network, laddr),
		Raddr:   fallbackConnAddr(network, raddr),
	}

	// Register with callbacks
	vt.mu.Lock()
	id := vt.getID()
	callbackWrapped := gonnect.ConnWithCallbacks(wrapped, &gonnect.Callbacks{
		BeforeClose: vt.buildUnregCallback(id),
	})
	vt.register(id, callbackWrapped)
	vt.mu.Unlock()

	// Return the callback-wrapped version
	return callbackWrapped.(gonnect.UDPConn), nil
}

func (vt *VTun) PacketDial(
	ctx context.Context,
	network, raddr string,
) (conn gonnect.PacketConn, err error) {
	return vt.DialUDP(ctx, network, "", raddr)
}

func (vt *VTun) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (conn gonnect.UDPConn, err error) {
	if !gh.IsUDPNetwork(network) {
		return nil, net.UnknownNetworkError(network)
	}
	err = vt.runWithLookup(
		ctx, network, laddr, raddr, ge.ConnRefused(network, raddr),
		func(laddr, raddr string) (bool, error) {
			conn, err = vt.dialUDP(network, laddr, raddr)
			if err != nil {
				return false, err
			}
			return true, nil
		},
	)
	return
}

func (vt *VTun) listenUDP(
	network, laddr string,
) (gonnect.UDPConn, error) {
	addr, err := helpers.AddrPortFromString(laddr)
	if err != nil {
		return nil, err
	}

	c, err := vt.ListenUDPAddrPort(addr)
	if err != nil {
		return nil, err
	}

	// Wrap with helpers.UDPConn first
	wrapped := &helpers.UDPConn{
		UDPConn: c,
		Laddr:   fallbackConnAddr(network, addr.String()),
		Raddr:   fallbackConnAddr(network, ""),
	}

	// Register with callbacks
	vt.mu.Lock()
	id := vt.getID()
	callbackWrapped := gonnect.ConnWithCallbacks(wrapped, &gonnect.Callbacks{
		BeforeClose: vt.buildUnregCallback(id),
	})
	vt.register(id, callbackWrapped)
	vt.mu.Unlock()

	// Return the callback-wrapped version
	return callbackWrapped.(gonnect.UDPConn), nil
}

func (vt *VTun) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (conn gonnect.UDPConn, err error) {
	if !gh.IsUDPNetwork(network) {
		return nil, net.UnknownNetworkError(network)
	}
	err = vt.runWithLookup(
		ctx, network, laddr, "", ge.ListenDeniedErr(network, laddr),
		func(laddr, raddr string) (bool, error) {
			conn, err = vt.listenUDP(network, laddr)
			if err != nil {
				return false, err
			}
			return true, nil
		},
	)
	return
}

func fallbackConnAddr(network, addr string) net.Addr {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return &gh.NetAddr{
		Net:  network,
		Addr: addr,
	}
}

func fallbackListenerAddr(network, addr string) net.Addr {
	if addr == "" {
		addr = "0.0.0.0:0"
	}
	return &gh.NetAddr{
		Net:  network,
		Addr: addr,
	}
}

func (vt *VTun) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if gh.IsTCPNetwork(network) {
		return vt.DialTCP(ctx, network, "", address)
	}
	if gh.IsUDPNetwork(network) {
		return vt.DialUDP(ctx, network, "", address)
	}
	// TODO: Handle Ping dialing also
	return nil, net.UnknownNetworkError(network)
}

func (vt *VTun) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return vt.ListenTCP(ctx, network, address)
}

func (vt *VTun) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return vt.ListenUDP(ctx, network, address)
}

// DialPingAddr creates an ICMP ping connection with the specified local and
// remote addresses. This can be used to send and receive ICMP echo requests
// and replies.
func (vt *VTun) DialPingAddr(laddr, raddr netip.Addr) (*PingConn, error) {
	if err := vt.checkUp(); err != nil {
		return nil, err
	}
	if !laddr.IsValid() && !raddr.IsValid() {
		return nil, errors.New("ping dial: invalid address")
	}
	v6 := laddr.Is6() || raddr.Is6()
	bind := laddr.IsValid()
	if !bind {
		if v6 {
			laddr = netip.IPv6Unspecified()
		} else {
			laddr = netip.IPv4Unspecified()
		}
	}

	tn := icmp.ProtocolNumber4
	pn := ipv4.ProtocolNumber
	if v6 {
		tn = icmp.ProtocolNumber6
		pn = ipv6.ProtocolNumber
	}

	pc := &PingConn{
		laddr:    PingAddr{laddr},
		deadline: time.NewTimer(time.Hour << 10),
	}
	pc.deadline.Stop()

	ep, tcpipErr := vt.stack.NewEndpoint(tn, pn, &pc.wq)
	if tcpipErr != nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
	}
	pc.ep = ep

	if bind {
		fa, _ := helpers.ConvertToFullAddr(netip.AddrPortFrom(laddr, 0))
		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
		}
	}

	if raddr.IsValid() {
		pc.raddr = PingAddr{raddr}
		fa, _ := helpers.ConvertToFullAddr(netip.AddrPortFrom(raddr, 0))
		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
		}
	}

	// Track this connection for cleanup on Down()
	vt.mu.Lock()
	id := vt.getID()
	vt.register(id, pc)
	vt.mu.Unlock()

	return pc, nil
}

// ListenPingAddr creates an ICMP ping listener bound to the specified local address.
// It can be used to receive ICMP echo requests and send replies.
func (vt *VTun) ListenPingAddr(laddr netip.Addr) (*PingConn, error) {
	return vt.DialPingAddr(laddr, netip.Addr{})
}

// DialPing creates an ICMP ping connection with the specified local and remote PingAddr.
func (vt *VTun) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var la, ra netip.Addr
	if laddr != nil {
		la = laddr.Addr
	}
	if raddr != nil {
		ra = raddr.Addr
	}
	return vt.DialPingAddr(la, ra)
}

// ListenPing creates an ICMP ping listener bound to the specified local PingAddr.
func (vt *VTun) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var la netip.Addr
	if laddr != nil {
		la = laddr.Addr
	}
	return vt.ListenPingAddr(la)
}

// exchange performs a DNS query with the specified server, attempting UDP first
// then falling back to TCP if the response is truncated.
func (vt *VTun) exchangeDNS(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	// Use a non-loopback source address to prevent "martian packet" errors
	isV6 := server.Is6()
	localAddr := vt.dialAddr(isV6)

	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var c net.Conn
		// TODO: Close c on ctx cancellation
		var err error
		if useUDP {
			c, err = vt.DialUDPAddrPort(netip.AddrPortFrom(localAddr, 0), netip.AddrPortFrom(server, 53))
		} else {
			c, err = vt.DialTCPAddrPort(ctx, netip.AddrPortFrom(server, 53))
		}

		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		_ = c.Close()
		if err != nil {
			switch err {
			case context.Canceled:
				err = errCanceled
			case context.DeadlineExceeded:
				err = errTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

// tryOneName attempts to resolve a single name using all configured DNS servers,
// retrying once if no successful response is received.
func (vt *VTun) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for range 2 {
		for _, server := range vt.dnsServers {
			p, h, err := vt.exchangeDNS(ctx, server, q, time.Second*5)
			if err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == errNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr
				}
				lastErr = dnsErr
				continue
			}

			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil
			}
			lastErr = &net.DNSError{
				Err:    err.Error(),
				Name:   name,
				Server: server.String(),
			}
			if err == errNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

func (vt *VTun) runWithLookup(
	ctx context.Context, network, laddr, raddr string,
	fail error,
	fn func(laddr, raddr string) (bool, error),
) error {
	// For listen operations, if address contains a port, pass it through directly
	// This handles cases like "0.0.0.0:80" which shouldn't go through DNS lookup
	if _, _, err := net.SplitHostPort(laddr); err == nil && raddr == "" {
		_, err := fn(laddr, "")
		return err
	}

	// For dial operations, validate that remote address has a port
	if raddr != "" {
		if _, _, err := net.SplitHostPort(raddr); err != nil {
			return &net.AddrError{Addr: raddr, Err: "missing port in address"}
		}
	}
	// For local address with port (if provided), validate format
	if laddr != "" {
		if _, _, err := net.SplitHostPort(laddr); err != nil {
			return &net.AddrError{Addr: laddr, Err: "missing port in address"}
		}
	}

	// Strip port from addresses before DNS lookup
	laddrHost := laddr
	laddrPort := ""
	if host, port, err := net.SplitHostPort(laddr); err == nil {
		laddrHost = host
		laddrPort = port
	}

	raddrHost := raddr
	raddrPort := ""
	if host, port, err := net.SplitHostPort(raddr); err == nil {
		raddrHost = host
		raddrPort = port
	}

	var laddrs []net.IP
	var err error
	if laddrHost == "" {
		// Empty local address - use unspecified address
		laddrs = []net.IP{net.IPv4zero}
	} else {
		laddrs, err = vt.LookupIP(ctx, network, laddrHost)
		if err != nil {
			return err
		}
	}

	raddrs, err := vt.LookupIP(ctx, network, raddrHost)
	if err != nil {
		return err
	}

	for _, laddr := range laddrs {
		for _, raddr := range raddrs {
			select {
			case <-ctx.Done():
				err := fail
				switch err {
				case context.Canceled:
					err = errCanceled
				case context.DeadlineExceeded:
					err = errTimeout
				}
				return err
			default:
			}
			// Reconstruct addresses with ports
			finalLaddr := laddr.String()
			if laddrPort != "" {
				finalLaddr = net.JoinHostPort(laddr.String(), laddrPort)
			}
			finalRaddr := raddr.String()
			if raddrPort != "" {
				finalRaddr = net.JoinHostPort(raddr.String(), raddrPort)
			}

			ok, err := fn(finalLaddr, finalRaddr)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}

	return fail
}

func (vt *VTun) LookupIP(
	ctx context.Context, network, address string,
) ([]net.IP, error) {
	fam := gh.FamilyFromNetwork(network)
	v4 := fam == "ip4" || fam == "ip"
	v6 := fam == "ip6" || fam == "ip"
	ips := []net.IP{}

	addrs, err := vt.LookupHost(ctx, address)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if (ip.To4() != nil && v4) || (ip.To16() != nil && v6) {
			ips = append(ips, ip)
		}
	}

	if len(ips) < 1 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}
	return ips, nil
}

func (vt *VTun) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	hosts, err := vt.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, 0, len(hosts))
	for _, h := range hosts {
		ip := net.ParseIP(h)
		if ip != nil {
			addrs = append(addrs, net.IPAddr{
				IP: ip,
			})
		}
	}
	return addrs, nil
}

func (vt *VTun) LookupNetIP(
	ctx context.Context, network, host string,
) ([]netip.Addr, error) {
	ips, err := vt.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

func (vt *VTun) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	return nil, ge.DnsReqErr(addr, "unsupported")
}

func (vt *VTun) LookupCNAME(ctx context.Context, host string) (cname string, err error) {
	return "", ge.DnsReqErr(host, "unsupported")
}

func (vt *VTun) LookupPort(
	ctx context.Context,
	network, service string,
) (port int, err error) {
	return gonnect.LookupPortOffline(network, service)
}

func (vt *VTun) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	// Check custom lookup first
	vt.lookupMu.RLock()
	lookup := vt.lookup
	vt.lookupMu.RUnlock()
	if lookup != nil {
		ips, err := lookup(ctx, "ip", name)
		if err != nil {
			// Return as not found for custom lookup errors
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		// If we get IPs, it's not MX-specific - return not found
		// (we don't support actual MX lookups)
		_ = ips
	}
	return nil, ge.DnsReqErr(name, "unsupported")
}

func (vt *VTun) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	// Check custom lookup first
	vt.lookupMu.RLock()
	lookup := vt.lookup
	vt.lookupMu.RUnlock()
	if lookup != nil {
		_, err := lookup(ctx, "ip", name)
		if err != nil {
			// Return as not found for custom lookup errors
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
	}
	return nil, ge.DnsReqErr(name, "unsupported")
}

func (vt *VTun) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	// Check custom lookup first
	vt.lookupMu.RLock()
	lookup := vt.lookup
	vt.lookupMu.RUnlock()
	if lookup != nil {
		// For SRV, the full name includes service and proto
		fullName := fmt.Sprintf("_%s._%s.%s", service, proto, name)
		_, err := lookup(ctx, "ip", name)
		if err != nil {
			// Return as not found for custom lookup errors
			return "", nil, &net.DNSError{Err: "no such host", Name: fullName, IsNotFound: true}
		}
	}
	return "", nil, ge.DnsReqErr(name, "unsupported")
}

func (vt *VTun) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	// Check custom lookup first
	vt.lookupMu.RLock()
	lookup := vt.lookup
	vt.lookupMu.RUnlock()
	if lookup != nil {
		_, err := lookup(ctx, "ip", name)
		if err != nil {
			// Return as not found for custom lookup errors
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
	}
	return nil, ge.DnsReqErr(name, "unsupported")
}

// LookupHost performs a DNS lookup for the given host name and returns a list
// of IP addresses. It resolves both A and AAAA records in parallel if both
// IPv4 and IPv6 are enabled on the VTun.
func (vt *VTun) LookupHost(ctx context.Context, host string) ([]string, error) {
	if host == "" {
		return []string{""}, nil
	}
	if !isDomainName(host) {
		return []string{host}, nil
	}

	if host == "" || (!vt.hasV6 && !vt.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}

	vt.lookupMu.RLock()
	defer vt.lookupMu.RUnlock()

	if vt.lookup != nil {
		ips, err := vt.lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		strs := []string{}
		for _, ip := range ips {
			strs = append(strs, ip.String())
		}
		return strs, nil
	}

	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}
	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if vt.hasV4 {
		lanes++
	}
	if vt.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	if vt.hasV4 {
		go func() {
			p, server, err := vt.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if vt.hasV6 {
		go func() {
			p, server, err := vt.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	for l := 0; l < lanes; l++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))

			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))

			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				continue
			}
		}
	}
	// We don't do RFC6724. Instead just put V6 addresses first if an IPv6 address is enabled
	var addrs []netip.Addr
	if vt.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}

	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	saddrs := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		saddrs = append(saddrs, ip.String())
	}
	return saddrs, nil
}

func (vt *VTun) Interfaces() ([]gonnect.NetworkInterface, error) {
	ifs := []gonnect.NetworkInterface{}
	for k, v := range vt.stack.NICInfo() {
		ifs = append(ifs, helpers.NIC2Iface(k, v))
	}
	return ifs, nil
}

func (vt *VTun) InterfaceAddrs() ([]net.Addr, error) {
	addrs := []net.Addr{}
	for k, v := range vt.stack.NICInfo() {
		ads, _ := helpers.NIC2Iface(k, v).Addrs()
		addrs = append(addrs, ads...)
	}
	return slices.Compact(addrs), nil
}

func (vt *VTun) InterfacesByIndex(index int) ([]gonnect.NetworkInterface, error) {
	if index > math.MaxInt32 {
		index = math.MaxInt32
	}
	if index < math.MinInt32 {
		index = math.MinInt32
	}
	id := tcpip.NICID(int32(index))
	if info, ok := vt.stack.NICInfo()[id]; ok {
		return []gonnect.NetworkInterface{helpers.NIC2Iface(id, info)}, nil
	}
	return nil, &net.OpError{Op: "interface", Net: fmt.Sprintf("index %d", index), Err: errors.New("no such network interface")}
}

func (vt *VTun) InterfacesByName(name string) ([]gonnect.NetworkInterface, error) {
	res := []gonnect.NetworkInterface{}
	ifs, _ := vt.Interfaces()
	for _, ifc := range ifs {
		if ifc.Name() == name {
			res = append(res, ifc)
		}
	}
	if len(res) == 0 {
		return nil, &net.OpError{Op: "interface", Net: fmt.Sprintf("name %q", name), Err: errors.New("no such network interface")}
	}
	return res, nil
}

func (vt *VTun) Up() error {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	if vt.down && !vt.closed {
		vt.down = false
		vt.events <- tun.EventUp
		return helpers.WrapErr(helpers.ErrUp, vt.stack.EnableNIC(vt.nid))
	}
	return nil
}

func (vt *VTun) Down() error {
	vt.mu.Lock()
	if vt.down || vt.closed {
		vt.mu.Unlock()
		return nil
	}
	vt.down = true

	// Collect all tracked connections/listeners
	closers := make([]io.Closer, 0, len(vt.closers))
	for _, c := range vt.closers {
		closers = append(closers, c)
	}
	// Clear the map since we're closing everything
	vt.closers = nil
	vt.mu.Unlock()

	// Close all tracked connections/listeners
	for _, c := range closers {
		_ = c.Close()
	}

	vt.events <- tun.EventDown
	return helpers.WrapErr(helpers.ErrDown, vt.stack.DisableNIC(vt.nid))
}

// IsUp returns true if the VTun is up and operational.
func (vt *VTun) IsUp() (bool, error) {
	vt.mu.RLock()
	defer vt.mu.RUnlock()
	return !vt.down, nil
}

// checkUp returns an error if the VTun is down or closed.
func (vt *VTun) checkUp() error {
	vt.mu.RLock()
	defer vt.mu.RUnlock()
	if vt.closed {
		return os.ErrClosed
	}
	if vt.down {
		return errors.New("vtun is down")
	}
	return nil
}
