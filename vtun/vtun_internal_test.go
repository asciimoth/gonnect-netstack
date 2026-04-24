package vtun

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestVTun(t *testing.T) *VTun {
	t.Helper()

	vt, err := (&Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.210.1")},
	}).Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	select {
	case <-vt.Events():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for EventUp")
	}

	t.Cleanup(func() {
		_ = vt.Close()
	})

	return vt
}

func queueOutboundPacket(t *testing.T, vt *VTun, payload []byte) {
	t.Helper()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)

	if n, err := vt.ep.WritePackets(pkts); err != nil {
		t.Fatalf("WritePackets() failed: n=%d err=%v", n, err)
	} else if n != 1 {
		t.Fatalf("WritePackets() wrote %d packets, want 1", n)
	}
}

func TestVTunWriteNotifyDoesNotBlockWhenIncomingQueueFull(t *testing.T) {
	vt := newTestVTun(t)

	for range cap(vt.incomingPacket) {
		vt.incomingPacket <- buffer.NewViewWithData([]byte{0})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		queueOutboundPacket(t, vt, []byte{1, 2, 3, 4})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteNotify blocked while incomingPacket was full")
	}

	if queued := vt.ep.NumQueued(); queued != 0 {
		t.Fatalf("ep.NumQueued() = %d, want 0", queued)
	}

	for {
		select {
		case view := <-vt.incomingPacket:
			view.Release()
		default:
			return
		}
	}
}

func TestVTunReadReleasesIncomingView(t *testing.T) {
	vt := newTestVTun(t)

	view := buffer.NewViewWithData([]byte{1, 2, 3, 4})
	vt.incomingPacket <- view

	buf := [][]byte{make([]byte, 8)}
	sizes := make([]int, 1)

	n, err := vt.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("Read() packet count = %d, want 1", n)
	}
	if sizes[0] != 4 {
		t.Fatalf("Read() size = %d, want 4", sizes[0])
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected view to be released by Read()")
		}
	}()
	view.Release()
}

func TestVTunWriteNotifyAfterIncomingQueueClosed(t *testing.T) {
	vt := newTestVTun(t)

	vt.ep.RemoveNotify(vt.notifyHandle)
	queueOutboundPacket(t, vt, []byte{9, 8, 7, 6})
	vt.mu.Lock()
	close(vt.incomingPacket)
	vt.closed = true
	vt.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("WriteNotify() panicked after incomingPacket close: %v", r)
		}
	}()

	vt.WriteNotify()
}
