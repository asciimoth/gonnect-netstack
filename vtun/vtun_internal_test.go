package vtun

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
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

func TestVTunSetMTUUpdatesInPlace(t *testing.T) {
	vt := newTestVTun(t)

	if err := vt.SetMTU(1280); err != nil {
		t.Fatalf("SetMTU() failed: %v", err)
	}
	if got, err := vt.MTU(); err != nil || got != 1280 {
		t.Fatalf("MTU() = %d, %v; want 1280, nil", got, err)
	}
	if got := vt.ep.MTU(); got != 1280 {
		t.Fatalf("endpoint MTU = %d, want 1280", got)
	}
	select {
	case event := <-vt.Events():
		if event != tun.EventMTUUpdate {
			t.Fatalf("event = %v, want EventMTUUpdate", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for EventMTUUpdate")
	}

	if err := vt.SetMTU(1280); err != nil {
		t.Fatalf("equal SetMTU() failed: %v", err)
	}
	select {
	case event := <-vt.Events():
		t.Fatalf("equal SetMTU() emitted event %v", event)
	default:
	}
}

func TestVTunSetMTUDropsQueuedOversizePacket(t *testing.T) {
	vt := newTestVTun(t)
	vt.incomingPacket <- buffer.NewViewWithData(make([]byte, 1281))
	vt.incomingPacket <- buffer.NewViewWithData(make([]byte, 1280))

	if err := vt.SetMTU(1280); err != nil {
		t.Fatalf("SetMTU() failed: %v", err)
	}
	bufs := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	if n, err := vt.Read(bufs, sizes, 0); err != nil || n != 1 {
		t.Fatalf("Read() = %d, %v; want 1, nil", n, err)
	}
	if sizes[0] != 1280 {
		t.Fatalf("Read() size = %d, want 1280", sizes[0])
	}
}

func TestVTunSetMTURejectsInvalidValue(t *testing.T) {
	vt := newTestVTun(t)
	if err := vt.SetMTU(0); err == nil {
		t.Fatal("SetMTU(0) succeeded")
	}
}

func TestVTunSetMTUConcurrentLifecycle(t *testing.T) {
	vt := newTestVTun(t)
	start := make(chan struct{})
	errs := make(chan error, 4)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 500; iteration++ {
				if worker%2 == 0 {
					if err := vt.SetMTU(1200 + ((worker + iteration) % 200)); err != nil {
						select {
						case errs <- err:
						default:
						}
						return
					}
					continue
				}
				if _, err := vt.MTU(); err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent MTU operation failed: %v", err)
	}

	if err := vt.SetMTU(1280); err != nil {
		t.Fatalf("final SetMTU() failed: %v", err)
	}
	if mtu, err := vt.MTU(); err != nil || mtu != 1280 {
		t.Fatalf("final MTU() = %d, %v; want 1280, nil", mtu, err)
	}
	if mtu := vt.ep.MTU(); mtu != 1280 {
		t.Fatalf("final endpoint MTU = %d, want 1280", mtu)
	}
	if err := vt.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if err := vt.SetMTU(1290); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("SetMTU() after Close() error = %v, want os.ErrClosed", err)
	}
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
