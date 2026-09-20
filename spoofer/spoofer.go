// Package spoofer provides a network stack spoofer built on top of gVisor's
// netstack. It can intercept and forward TCP and UDP traffic from a TUN device
// or an io.ReadWriteCloser.
//
// OnTCPConn is an eager compatibility API: the intercepted client handshake is
// complete before the callback runs. PrepareTCP is the connection-gated API:
// it lets a forward proxy connect its upstream before Spoofer accepts the
// client connection.
package spoofer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
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

const defaultTCPPrepareTimeout = 30 * time.Second

// PreparedTCPHandler owns an upstream resource that is ready for use. Spoofer
// calls HandleTCP only after it completes the intercepted client handshake.
// Ownership passes to HandleTCP at that point. Spoofer calls Close instead if
// it cannot create the client endpoint.
type PreparedTCPHandler interface {
	HandleTCP(net.Conn)
	Close() error
}

// PreparedTCPHandlerFuncs adapts functions to PreparedTCPHandler.
type PreparedTCPHandlerFuncs struct {
	HandleFunc func(net.Conn)
	CloseFunc  func() error
}

// HandleTCP calls HandleFunc when it is not nil.
func (h PreparedTCPHandlerFuncs) HandleTCP(conn net.Conn) {
	if h.HandleFunc != nil {
		h.HandleFunc(conn)
	}
}

// Close calls CloseFunc when it is not nil.
func (h PreparedTCPHandlerFuncs) Close() error {
	if h.CloseFunc == nil {
		return nil
	}
	return h.CloseFunc()
}

type cancelOnCloseEndpoint struct {
	stack.LinkEndpoint
	cancel context.CancelFunc
	once   sync.Once
}

type tcpForwarderRequest interface {
	ID() stack.TransportEndpointID
	CreateEndpoint(*waiter.Queue) (tcpip.Endpoint, tcpip.Error)
	Complete(bool)
}

func (e *cancelOnCloseEndpoint) Close() {
	e.once.Do(e.cancel)
	e.LinkEndpoint.Close()
}

// Opts holds configuration options for the spoofer.
// It controls network stack behavior, TCP/UDP forwarding, and endpoint setup.
type Opts struct {
	// OnTCPConn is the eager, compatibility TCP callback. Spoofer completes the
	// intercepted client handshake before it calls this function. A failure to
	// connect the real upstream can therefore not make the original Dial fail.
	// Forward proxies that need correct connection results must use PrepareTCP.
	OnTCPConn func(net.Conn, stack.TransportEndpointID)
	// PrepareTCP prepares the real upstream before Spoofer accepts an
	// intercepted TCP connection. If preparation fails, Spoofer resets the
	// client flow and calls OnTCPError. If it succeeds, Spoofer completes the
	// client handshake and passes the connection to the prepared handler.
	// PrepareTCP takes priority when both TCP callbacks are set.
	PrepareTCP func(context.Context, stack.TransportEndpointID) (PreparedTCPHandler, error)
	// OnTCPError reports preparation and client-endpoint errors from the
	// connection-gated PrepareTCP path. Spoofer calls it from a forwarding
	// goroutine. The callback must be safe for concurrent use.
	OnTCPError func(stack.TransportEndpointID, error)
	// TCPPrepareTimeout limits each PrepareTCP call. The default is 30 seconds.
	// Values less than or equal to zero use the default. PrepareTCP must stop
	// work and release partial resources when its context is done.
	TCPPrepareTimeout time.Duration
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
//
// PrepareTCP calls always have their individual timeout. Use LaunchContext
// when shutdown must also cancel pending preparation calls.
// Returns the initialized stack or an error if setup fails.
func (o *Opts) Launch() (*stack.Stack, error) {
	return o.LaunchContext(context.Background())
}

// LaunchContext is like Launch, and it also uses ctx as the Spoofer lifetime.
// Cancel ctx before stack shutdown to stop all pending PrepareTCP calls.
// Removing the Spoofer NIC also cancels these calls.
func (o *Opts) LaunchContext(ctx context.Context) (*stack.Stack, error) {
	if o == nil {
		return nil, errors.New("spoofer: nil options")
	}
	if ctx == nil {
		return nil, errors.New("spoofer: nil launch context")
	}
	lifetimeCtx, cancelLifetime := context.WithCancel(ctx)
	if o.Endpoint == nil {
		cancelLifetime()
		return nil, errors.New("spoofer: link endpoint is nil")
	}

	no := o.opts()
	st, err := no.BuildStack(false)
	if err != nil {
		cancelLifetime()
		return nil, err
	}

	nicID := st.NextNICID()

	if err := o.setupTCPOptions(st); err != nil {
		cancelLifetime()
		return nil, err
	}

	TCPForwardAttempts := o.TCPForwardAttempts
	if TCPForwardAttempts == 0 {
		TCPForwardAttempts = 2 << 10
	}
	tcpForwarder := tcp.NewForwarder(
		st, o.TCPForwardWnd, TCPForwardAttempts, func(r *tcp.ForwarderRequest) {
			if o.PrepareTCP != nil {
				o.handlePreparedTCP(lifetimeCtx, r)
				return
			}
			o.handleEagerTCP(r)
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

	endpoint := &cancelOnCloseEndpoint{LinkEndpoint: o.Endpoint, cancel: cancelLifetime}
	if err := st.CreateNIC(nicID, endpoint); err != nil {
		cancelLifetime()
		return nil, fmt.Errorf("create NIC: %s", err)
	}

	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		cancelLifetime()
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}

	if err := st.SetSpoofing(nicID, true); err != nil {
		cancelLifetime()
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

func (o *Opts) handleEagerTCP(r tcpForwarderRequest) {
	id := r.ID()
	if o.OnTCPConn == nil {
		r.Complete(true)
		o.reportTCPError(id, errors.New("spoofer: no TCP forwarding callback is configured"))
		return
	}

	var queue waiter.Queue
	endpoint, err := r.CreateEndpoint(&queue)
	if err != nil {
		r.Complete(true)
		o.reportTCPError(id, fmt.Errorf("create intercepted TCP endpoint: %s", err))
		return
	}
	r.Complete(false)
	o.setTCPSocketOptions(endpoint)
	o.OnTCPConn(gonet.NewTCPConn(&queue, endpoint), id)
}

func (o *Opts) handlePreparedTCP(parent context.Context, r tcpForwarderRequest) {
	id := r.ID()
	timeout := o.TCPPrepareTimeout
	if timeout <= 0 {
		timeout = defaultTCPPrepareTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	prepared, err := o.PrepareTCP(ctx, id)
	if err == nil {
		err = ctx.Err()
	}
	cancel()
	if err == nil && prepared == nil {
		err = errors.New("PrepareTCP returned a nil handler")
	}
	if err != nil {
		if prepared != nil {
			if closeErr := prepared.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close prepared TCP handler: %w", closeErr))
			}
		}
		r.Complete(true)
		o.reportTCPError(id, fmt.Errorf("prepare TCP upstream: %w", err))
		return
	}

	var queue waiter.Queue
	endpoint, endpointErr := r.CreateEndpoint(&queue)
	if endpointErr != nil {
		err := fmt.Errorf("create intercepted TCP endpoint: %s", endpointErr)
		if closeErr := prepared.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close prepared TCP handler: %w", closeErr))
		}
		r.Complete(true)
		o.reportTCPError(id, err)
		return
	}

	r.Complete(false)
	o.setTCPSocketOptions(endpoint)
	prepared.HandleTCP(gonet.NewTCPConn(&queue, endpoint))
}

func (o *Opts) reportTCPError(id stack.TransportEndpointID, err error) {
	if o.OnTCPError != nil {
		o.OnTCPError(id, err)
	}
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
