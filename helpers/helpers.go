// Package helpers provides utility functions and types for working with gVisor's
// netstack. It includes helpers for creating and managing network interfaces,
// converting between address formats, wrapping netstack errors to implement the
// error interface, and managing NIC (Network Interface Card) creation.
package helpers

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	// ErrSack is returned when setting TCP SACK (Selective Acknowledgment) fails.
	ErrSack = errors.New("set tcp sack")
	// ErrNIC is returned when creating a network interface card fails.
	ErrNIC = errors.New("create nic")
	// ErrNewAddr is returned when adding a protocol address fails.
	ErrNewAddr = errors.New("add protocol address")
	// ErrProm is returned when setting promiscuous mode fails.
	ErrProm = errors.New("set promiscuous mode")
	// ErrNotTCP is returned when a connection is expected to be TCP but is not.
	ErrNotTCP = errors.New("not a tcp conn")
	// ErrNotUDP is returned when a connection is expected to be UDP but is not.
	ErrNotUDP = errors.New("not a udp conn")
	// ErrUp is returned when bringing the stack up fails.
	ErrUp = errors.New("bring stack up")
	// ErrDown is returned when bringing the stack down fails.
	ErrDown = errors.New("bring stack down")
)

// NetstackErr is an interface for netstack error types that do not implement
// the standard error interface. It provides a String() method to retrieve
// the error message.
type NetstackErr interface {
	String() string
}

// WrapErr wraps a netstack error with a standard error to create a joined error.
// If either err or ne is nil, it returns nil.
func WrapErr(err error, ne NetstackErr) error {
	if err == nil || ne == nil {
		return nil
	}
	return errors.Join(err, errors.New(ne.String()))
}

// CreateNIC creates a network interface card (NIC) on the given stack. If id is
// nil, it generates a new NIC ID automatically. Returns the NIC ID and any error
// that occurred during creation.
func CreateNIC(st *stack.Stack, id *tcpip.NICID, ep stack.LinkEndpoint) (tcpip.NICID, error) {
	if id == nil {
		nid := st.NextNICID()
		id = &nid
	}
	err := st.CreateNIC(*id, ep)
	return *id, WrapErr(ErrNIC, err)
}

// ConvertToFullAddr converts a netip.AddrPort to a tcpip.FullAddress and the
// corresponding network protocol number (IPv4 or IPv6).
func ConvertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

// NIC2Iface converts a gVisor NIC ID and its associated information into a
// gonnect.NetworkInterface implementation. It extracts protocol addresses
// (IPv4/IPv6) and populates the interface with standard network properties.
func NIC2Iface(id tcpip.NICID, info stack.NICInfo) gonnect.NetworkInterface {
	paddrs := info.ProtocolAddresses
	addrs := []net.Addr{}
loop:
	for _, paddr := range paddrs {
		var network string
		switch paddr.Protocol {
		case ipv4.ProtocolNumber:
			network = "ip4"
		case ipv6.ProtocolNumber:
			network = "ip6"
		default:
			continue loop
		}
		addrs = append(addrs, &helpers.NetAddr{
			Net:  network,
			Addr: paddr.AddressWithPrefix.Address.String(),
		})
	}
	return &gonnect.LiteralInterface{
		IDVal:             strconv.Itoa(int(id)),
		IndexVal:          int(id),
		NameVal:           info.Name,
		MTUVal:            int(info.MTU),
		AddrsVal:          addrs,
		MulticastAddrsVal: []net.Addr{},
	}
}

func AddrPortFromString(hostport string) (netip.AddrPort, error) {
	host, sport, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}

	// Handle 0.0.0.0 and so on
	if addr.IsUnspecified() {
		addr, _ = netip.AddrFromSlice(nil)
	}

	port, err := strconv.Atoi(sport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port %q: %w", sport, err)
	}
	if port > math.MaxUint16 {
		port = math.MaxUint16
	} else if port < 0 {
		port = 0
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}
