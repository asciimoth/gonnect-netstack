// Package spoofer provides a network stack spoofer built on top of gVisor's
// netstack. It enables intercepting and forwarding TCP/UDP traffic from a
// TUN device or arbitrary io.ReadWriteCloser, with support for address
// spoofing, promiscuous mode, and extensive TCP tuning options.
package spoofer

import (
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/helpers"
	"github.com/asciimoth/gonnect/tun"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Opts holds configuration options for the spoofer.
// It controls network stack behavior, TCP/UDP forwarding, and endpoint setup.
type Opts struct {
	// OnTCPConn is called when a new TCP connection is forwarded.
	// The callback receives the connection and the transport endpoint ID
	// containing local/remote addresses and ports.
	OnTCPConn func(net.Conn, stack.TransportEndpointID)
	// OnUDPConn is called when a new UDP stream is forwarded.
	// The callback receives a packet connection and the transport endpoint ID.
	OnUDPConn func(gonnect.PacketConn, stack.TransportEndpointID)

	// Endpoint is the link-layer endpoint used by the netstack.
	// Set it via WithRWCEndpoint or WithTunEndpoint before calling Launch.
	Endpoint stack.LinkEndpoint

	// TCPSendBufferSize sets the default TCP send buffer size.
	TCPSendBufferSize int
	// TCPReceiveBufferSize sets the default TCP receive buffer size.
	TCPReceiveBufferSize int
	// TTL sets the default TTL for outgoing packets.
	TTL int
	// ICMPBurst sets the ICMP rate limiter burst size.
	ICMPBurst int
	// ICMPLimit sets the ICMP rate limit (packets per second).
	ICMPLimit float64
	// CongestionControlAlg sets the TCP congestion control algorithm name
	// (e.g., "cubic", "reno").
	CongestionControlAlg string
	// DisableNagle disables Nagle's algorithm (TCP_NODELAY).
	DisableNagle bool
	// DisableTCPModRecBuff disables TCP moderate receive buffer auto-tuning.
	DisableTCPModRecBuff bool
	// TCPRec sets the TCP recovery option for tail loss probe.
	TCPRec *tcpip.TCPRecovery

	// TCPKeepAlive enables TCP keep-alive on forwarded connections.
	TCPKeepAlive bool
	// TCPKeepAliveIdle sets the time before sending keep-alive probes.
	TCPKeepAliveIdle time.Duration
	// TCPKeepaliveInterval sets the interval between keep-alive probes.
	TCPKeepaliveInterval time.Duration
	// TCPKeepaliveCount sets the maximum number of unacknowledged keep-alive probes.
	TCPKeepaliveCount int

	// TCPForwardWnd sets the TCP receive window size for forwarded connections.
	TCPForwardWnd int
	// TCPForwardAttempts sets the maximum concurrent TCP connection forwarding attempts.
	TCPForwardAttempts int

	// NetStackOpts provides additional netstack configuration options.
	NetStackOpts *helpers.Opts
}

// WithRWCEndpoint configures the spoofer to use an io.ReadWriteCloser as the
// link-layer endpoint. It wraps the RWC in an IOEndpoint with the given MTU
// and queue length. If mtu is 0, it defaults to 1500. If qlen is less than 1,
// it defaults to 1024. Returns the Opts for method chaining.
func (o *Opts) WithRWCEndpoint(rwc io.ReadWriteCloser, qlen int) *Opts {
	mtu := o.NetStackOpts.GetMTU()
	if mtu > math.MaxUint32 {
		mtu = math.MaxUint32
	} else if mtu < 0 {
		mtu = 0
	}
	o.Endpoint = NewIOEndpoint(rwc, uint32(mtu), qlen)
	return o
}

// WithTunEndpoint configures the spoofer to use a TUN device as the
// link-layer endpoint. It creates a TunEndpoint with the given queue length.
// If qlen is less than 1, it defaults to 1024. Returns the Opts for method chaining.
func (o *Opts) WithTunEndpoint(tun tun.Tun, qlen int) *Opts {
	ep := NewTunEndpoint(tun, qlen)
	o.Endpoint = ep
	return o
}

func (o *Opts) opts() *helpers.Opts {
	if o != nil && o.NetStackOpts != nil {
		return o.NetStackOpts
	}
	return &helpers.Opts{}
}

// Launch initializes and starts the network stack with the configured options.
// It creates a NIC, sets up TCP and UDP forwarders, enables promiscuous mode
// and spoofing, and configures routing for IPv4 and IPv6.
// Returns the initialized stack or an error if setup fails.
func (o *Opts) Launch() (*stack.Stack, error) {
	no := o.opts()
	st, err := no.BuildStack(false)
	if err != nil {
		return nil, err
	}

	nicID := st.NextNICID()

	if err := o.setupTCPOptions(st); err != nil {
		return nil, err
	}

	TCPForwardAttempts := o.TCPForwardAttempts
	if TCPForwardAttempts == 0 {
		TCPForwardAttempts = 2 << 10
	}
	tcpForwarder := tcp.NewForwarder(
		st, o.TCPForwardWnd, TCPForwardAttempts, func(r *tcp.ForwarderRequest) {
			var queue waiter.Queue
			endpoint, err := r.CreateEndpoint(&queue)
			if err != nil {
				r.Complete(true) // With reset
				return
			}
			defer r.Complete(false) // Without reset
			o.setTCPSocketOptions(endpoint)
			o.OnTCPConn(gonet.NewTCPConn(&queue, endpoint), r.ID())
		})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(st, func(r *udp.ForwarderRequest) bool {
		var queue waiter.Queue
		endpoint, err := r.CreateEndpoint(&queue)
		if err != nil {
			return false
		}
		o.OnUDPConn(gonet.NewUDPConn(&queue, endpoint), r.ID())
		return true
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	if err := st.CreateNIC(nicID, o.Endpoint); err != nil {
		return nil, fmt.Errorf("create NIC: %s", err)
	}

	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}

	if err := st.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}

	st.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	return st, nil
}

func (o *Opts) setupTCPOptions(s *stack.Stack) error {
	if o.TTL != 0 {
		opt := tcpip.DefaultTTLOption(o.TTL)
		if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv4 default TTL: %s", err)
		}
		if err := s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set ipv6 default TTL: %s", err)
		}
	}

	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		return fmt.Errorf("set ipv4 forwarding: %s", err)
	}

	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		return fmt.Errorf("set ipv6 forwarding: %s", err)
	}
	if o.ICMPBurst != 0 {
		s.SetICMPBurst(o.ICMPBurst)
	}

	if o.ICMPLimit != 0 {
		s.SetICMPLimit(rate.Limit(o.ICMPLimit))
	}

	if o.TCPSendBufferSize != 0 {
		sndOpt := tcpip.TCPSendBufferSizeRangeOption{
			Min: tcp.MinBufferSize, Default: o.TCPReceiveBufferSize, Max: tcp.MaxBufferSize,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt); err != nil {
			return fmt.Errorf("set TCP send buffer size range: %s", err)
		}
	}

	if o.TCPReceiveBufferSize != 0 {
		rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
			Min: tcp.MinBufferSize, Default: o.TCPReceiveBufferSize, Max: tcp.MaxBufferSize,
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt); err != nil {
			return fmt.Errorf("set TCP receive buffer size range: %s", err)
		}
	}

	if o.CongestionControlAlg != "" {
		opt := tcpip.CongestionControlOption(o.CongestionControlAlg)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP congestion control algorithm: %s", err)
		}
	}

	if o.DisableNagle {
		opt := tcpip.TCPDelayEnabled(false)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP delay: %s", err)
		}
	}

	if o.DisableTCPModRecBuff {
		opt := tcpip.TCPModerateReceiveBufferOption(false)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("set TCP moderate receive buffer: %s", err)
		}
	}

	if o.TCPRec != nil {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, o.TCPRec); err != nil {
			return fmt.Errorf("set TCP Recovery: %s", err)
		}
	}

	return nil
}

func (o *Opts) setTCPSocketOptions(ep tcpip.Endpoint) tcpip.Error {
	if o.TCPKeepAlive {
		ep.SocketOptions().SetKeepAlive(true)

		if o.TCPKeepAliveIdle != 0 {
			idle := tcpip.KeepaliveIdleOption(o.TCPKeepAliveIdle)
			if err := ep.SetSockOpt(&idle); err != nil {
				return err
			}
		}

		if o.TCPKeepaliveInterval != 0 {
			interval := tcpip.KeepaliveIntervalOption(o.TCPKeepaliveInterval)
			if err := ep.SetSockOpt(&interval); err != nil {
				return err
			}
		}

		if o.TCPKeepaliveCount != 0 {
			if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, o.TCPKeepaliveCount); err != nil {
				return err
			}
		}
	}
	return nil
}
