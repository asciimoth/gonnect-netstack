package helpers

import (
	"github.com/asciimoth/gonnect/subnet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Opts contains configuration options for building a gVisor netstack.
type Opts struct {
	// MTU specifies the maximum transmission unit size. Defaults to 1500 if not set.
	MTU int

	// DisableSACK disables TCP Selective Acknowledgment when set to true.
	DisableSACK bool

	// IPAlloc provides IP address allocation for the network interfaces.
	IPAlloc subnet.IPAllocator

	// TODO: More config options
}

// GetMTU returns the configured MTU value, or the default value of 1500 if not set.
func (o *Opts) GetMTU() int {
	if o != nil && o.MTU != 0 {
		return o.MTU
	}
	return 1500
}

// GetIPAlloc returns the configured IP allocator, or creates a new random one if not set.
func (o *Opts) GetIPAlloc() subnet.IPAllocator {
	if o != nil && o.IPAlloc != nil {
		return o.IPAlloc
	}
	return subnet.NewRandomIPAllocator(&subnet.RandomIPAllocatorConfig{
		IPv4Config: &subnet.RandomAllocatorConfig{},
	})
}

func (o *Opts) sack() bool {
	if o != nil {
		return !o.DisableSACK
	}
	return true
}

// BuildStack creates and configures a new gVisor network stack with IPv4, IPv6,
// TCP, UDP, and ICMP protocols enabled. It applies the configured options for
// TCP SACK and returns the initialized stack.
func (o *Opts) BuildStack(local bool) (*stack.Stack, error) {
	st := stack.New(stack.Options{
		HandleLocal: local,
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	{
		opt := tcpip.TCPSACKEnabled(o.sack())
		if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, WrapErr(ErrSack, err)
		}
	}

	return st, nil
}
