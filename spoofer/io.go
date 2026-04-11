package spoofer

import (
	"context"
	"io"
	"sync"

	"github.com/asciimoth/gonnect/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ioEndpoint implements stack.LinkEndpoint from io.ReadWriteCloser.
type ioEndpoint struct {
	*channel.Endpoint

	RWC io.ReadWriteCloser

	mtu int

	// once is used to perform the init action once when attaching.
	once sync.Once
	wg   sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

// NewIOEndpoint creates a new link-layer endpoint that wraps an
// io.ReadWriteCloser. Packets are read from the RWC and injected into the
// netstack, and outbound packets are written to the RWC.
// If mtu is 0, it defaults to 1500. If qlen is less than 1, it defaults to 1024.
func NewIOEndpoint(rwc io.ReadWriteCloser, mtu uint32, qlen int) *ioEndpoint {
	if mtu == 0 {
		mtu = 1500
	}
	if qlen < 1 {
		// default packets queue length
		qlen = 1024
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &ioEndpoint{
		Endpoint: channel.New(qlen, mtu, ""),
		RWC:      rwc,
		mtu:      int(mtu),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Attach launches reader and writer
func (e *ioEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		e.wg.Add(2)
		go func() {
			e.reader()
			e.wg.Done()
		}()
		go func() {
			e.writer()
			e.wg.Done()
		}()
	})
}

// Close is called when the endpoint is removed from a stack.
func (e *ioEndpoint) Close() {
	e.cancel()
	_ = e.RWC.Close()
	e.Endpoint.Close()
}

// Wait waits for any worker goroutines owned by the endpoint to stop.
func (e *ioEndpoint) Wait() {
	e.wg.Wait()
	e.Endpoint.Wait()
}

func (e *ioEndpoint) reader() {
	defer e.cancel()

	for {
		data := make([]byte, e.mtu)

		n, err := e.RWC.Read(data)
		if err != nil {
			break
		}

		if n == 0 {
			// drop
			continue
		}

		if !e.IsAttached() {
			// drop
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data[:n]),
		})

		switch header.IPVersion(data) {
		case header.IPv4Version:
			e.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case header.IPv6Version:
			e.InjectInbound(header.IPv6ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
}

func (e *ioEndpoint) writer() {
	defer e.cancel()
	for {
		pkt := e.ReadContext(e.ctx)
		if pkt == nil {
			break
		}
		// TODO: How we should handle errors here?
		if err := e.writePacket(pkt); err != nil {
			break
		}
	}
}

func (e *ioEndpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	defer buf.Release()

	if _, err := e.RWC.Write(buf.Flatten()); err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}

// tunEndpoint implements stack.LinkEndpoint from gonnect.Tun directly.
// This avoids the overhead of the io.ReadWriteCloser wrapper and provides
// access to the full TUN interface (batch operations, MTU queries, etc.).
type tunEndpoint struct {
	*channel.Endpoint

	tun tun.Tun

	// once is used to perform the init action once when attaching.
	once sync.Once
	wg   sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

// NewTunEndpoint creates a new link-layer endpoint that wraps a TUN device
// directly. It uses the TUN's native batch operations and MTU for better
// performance compared to the io.ReadWriteCloser wrapper.
// If qlen is less than 1, it defaults to 1024.
func NewTunEndpoint(tun tun.Tun, qlen int) *tunEndpoint {
	mtu, err := tun.MTU()
	if err != nil {
		mtu = 1500
	}
	if mtu <= 0 {
		mtu = 1500
	}
	if qlen < 1 {
		qlen = 1024
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &tunEndpoint{
		Endpoint: channel.New(qlen, uint32(mtu), ""),
		tun:      tun,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Attach launches reader and writer
func (e *tunEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	e.once.Do(func() {
		e.wg.Add(2)
		go func() {
			e.reader()
			e.wg.Done()
		}()
		go func() {
			e.writer()
			e.wg.Done()
		}()
	})
}

// Close is called when the endpoint is removed from a stack.
func (e *tunEndpoint) Close() {
	e.cancel()
	_ = e.tun.Close()
	e.Endpoint.Close()
}

// Wait waits for any worker goroutines owned by the endpoint to stop.
func (e *tunEndpoint) Wait() {
	e.wg.Wait()
	e.Endpoint.Wait()
}

func (e *tunEndpoint) reader() {
	defer e.cancel()

	batchSize := e.tun.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}

	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, e.MTU())
	}

	for {
		n, err := e.tun.Read(bufs, sizes, 0)
		if err != nil {
			break
		}

		if !e.IsAttached() {
			continue
		}

		for i := range n {
			if sizes[i] == 0 {
				continue
			}

			data := bufs[i][:sizes[i]]

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})

			switch header.IPVersion(data) {
			case header.IPv4Version:
				e.InjectInbound(header.IPv4ProtocolNumber, pkt)
			case header.IPv6Version:
				e.InjectInbound(header.IPv6ProtocolNumber, pkt)
			}
			pkt.DecRef()
		}
	}
}

func (e *tunEndpoint) writer() {
	defer e.cancel()
	for {
		pkt := e.ReadContext(e.ctx)
		if pkt == nil {
			break
		}
		if err := e.writePacket(pkt); err != nil {
			break
		}
	}
}

func (e *tunEndpoint) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	defer buf.Release()

	flat := buf.Flatten()
	_, err := e.tun.Write([][]byte{flat}, 0)
	if err != nil {
		return &tcpip.ErrInvalidEndpointState{}
	}
	return nil
}
