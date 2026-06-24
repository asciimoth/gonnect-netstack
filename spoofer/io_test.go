package spoofer

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type offsetTun struct {
	readOffset  int
	writeOffset int

	reads  chan []byte
	writes chan offsetTunWrite
	events chan tun.Event

	closeOnce sync.Once

	mu             sync.Mutex
	lastReadOffset int
}

type offsetTunWrite struct {
	offset int
	packet []byte
	raw    []byte
}

func newOffsetTun(readOffset, writeOffset int) *offsetTun {
	return &offsetTun{
		readOffset:  readOffset,
		writeOffset: writeOffset,
		reads:       make(chan []byte, 1),
		writes:      make(chan offsetTunWrite, 1),
		events:      make(chan tun.Event),
	}
}

func (*offsetTun) File() *os.File { return nil }

func (*offsetTun) IsNative() bool { return false }

func (t *offsetTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.mu.Lock()
	t.lastReadOffset = offset
	t.mu.Unlock()

	packet, ok := <-t.reads
	if !ok {
		return 0, os.ErrClosed
	}
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	copy(bufs[0][offset:], packet)
	sizes[0] = len(packet)
	return 1, nil
}

func (t *offsetTun) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	packet := bytes.Clone(bufs[0][offset:])
	raw := bytes.Clone(bufs[0])
	t.writes <- offsetTunWrite{
		offset: offset,
		packet: packet,
		raw:    raw,
	}
	return 1, nil
}

func (t *offsetTun) MWO() int { return t.writeOffset }

func (t *offsetTun) MRO() int { return t.readOffset }

func (*offsetTun) MTU() (int, error) { return 64, nil }

func (*offsetTun) Name() (string, error) { return "offset-tun", nil }

func (t *offsetTun) Events() <-chan tun.Event { return t.events }

func (t *offsetTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.reads)
		close(t.events)
	})
	return nil
}

func (*offsetTun) BatchSize() int { return 1 }

func (t *offsetTun) readCallOffset() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastReadOffset
}

type recordingDispatcher struct {
	packets chan deliveredPacket
}

type deliveredPacket struct {
	protocol tcpip.NetworkProtocolNumber
	packet   []byte
}

func (d *recordingDispatcher) DeliverNetworkPacket(
	protocol tcpip.NetworkProtocolNumber,
	pkt *stack.PacketBuffer,
) {
	buf := pkt.ToBuffer()
	defer buf.Release()
	d.packets <- deliveredPacket{
		protocol: protocol,
		packet:   buf.Flatten(),
	}
}

func (*recordingDispatcher) DeliverLinkPacket(
	tcpip.NetworkProtocolNumber,
	*stack.PacketBuffer,
) {
}

func TestTunEndpointUsesReadOffset(t *testing.T) {
	const readOffset = 6

	tn := newOffsetTun(readOffset, 10)
	ep := NewTunEndpoint(tn, 1)
	dispatcher := &recordingDispatcher{
		packets: make(chan deliveredPacket, 1),
	}
	ep.Attach(dispatcher)
	t.Cleanup(func() {
		ep.Close()
		ep.Wait()
	})

	packet := ipv4TestPacket()
	tn.reads <- packet

	var got deliveredPacket
	select {
	case got = <-dispatcher.packets:
	case <-time.After(2 * time.Second):
		t.Fatal("endpoint did not deliver inbound packet")
	}

	if offset := tn.readCallOffset(); offset != readOffset {
		t.Fatalf("Read offset = %d, want %d", offset, readOffset)
	}
	if got.protocol != header.IPv4ProtocolNumber {
		t.Fatalf("protocol = %d, want %d", got.protocol, header.IPv4ProtocolNumber)
	}
	if !bytes.Equal(got.packet, packet) {
		t.Fatalf("delivered packet = %x, want %x", got.packet, packet)
	}
}

func TestTunEndpointUsesWriteOffset(t *testing.T) {
	const writeOffset = 10

	tn := newOffsetTun(6, writeOffset)
	ep := NewTunEndpoint(tn, 1)

	packet := ipv4TestPacket()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	if err := ep.writePacket(pkt); err != nil {
		t.Fatalf("writePacket failed: %v", err)
	}

	var got offsetTunWrite
	select {
	case got = <-tn.writes:
	default:
		t.Fatal("endpoint did not write outbound packet")
	}

	if got.offset != writeOffset {
		t.Fatalf("Write offset = %d, want %d", got.offset, writeOffset)
	}
	if !bytes.Equal(got.packet, packet) {
		t.Fatalf("written packet = %x, want %x", got.packet, packet)
	}
	if len(got.raw) != writeOffset+len(packet) {
		t.Fatalf("raw write length = %d, want %d", len(got.raw), writeOffset+len(packet))
	}
}

func ipv4TestPacket() []byte {
	return []byte{
		0x45, 0, 0, 20,
		0, 0, 0, 0,
		64, 1, 0, 0,
		192, 0, 2, 1,
		192, 0, 2, 2,
	}
}
