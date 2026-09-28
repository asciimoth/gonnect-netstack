package spoofer

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

type scriptedRead struct {
	packet   []byte
	sizeHint int
	err      error
}

type scriptedTun struct {
	mu         sync.Mutex
	reads      []scriptedRead
	capacities []int
	mtu        int
	batchSize  int
	readOffset int
	events     chan tun.Event
}

func newScriptedTun(mtu int, reads ...scriptedRead) *scriptedTun {
	return &scriptedTun{
		reads:     reads,
		mtu:       mtu,
		batchSize: 1,
		events:    make(chan tun.Event),
	}
}

func (*scriptedTun) File() *os.File        { return nil }
func (*scriptedTun) IsNative() bool        { return false }
func (*scriptedTun) MWO() int              { return 0 }
func (t *scriptedTun) MRO() int            { return t.readOffset }
func (t *scriptedTun) MTU() (int, error)   { return t.mtu, nil }
func (*scriptedTun) Name() (string, error) { return "scripted", nil }
func (t *scriptedTun) Events() <-chan tun.Event {
	return t.events
}
func (*scriptedTun) Close() error { return nil }
func (t *scriptedTun) BatchSize() int {
	return t.batchSize
}
func (*scriptedTun) Write(bufs [][]byte, _ int) (int, error) {
	return len(bufs), nil
}

func (t *scriptedTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.capacities = append(t.capacities, len(bufs[0])-offset)
	if len(t.reads) == 0 {
		return 0, os.ErrClosed
	}
	result := t.reads[0]
	t.reads = t.reads[1:]
	if result.sizeHint != 0 {
		sizes[0] = result.sizeHint
	}
	if result.packet == nil {
		return 0, result.err
	}
	copy(bufs[0][offset:], result.packet)
	sizes[0] = len(result.packet)
	return 1, result.err
}

func (t *scriptedTun) readCapacities() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]int(nil), t.capacities...)
}

type temporaryReadError struct{}

func (temporaryReadError) Error() string   { return "temporary read error" }
func (temporaryReadError) Temporary() bool { return true }

func TestTunEndpointRetriesRecoverableReadErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		sizeHint   int
		wantSecond int
	}{
		{
			name:       "short buffer",
			err:        io.ErrShortBuffer,
			sizeHint:   1500,
			wantSecond: 1500,
		},
		{
			name:       "short buffer without size hint",
			err:        io.ErrShortBuffer,
			wantSecond: 40,
		},
		{
			name:       "wrapped short buffer",
			err:        errors.Join(errors.New("read failed"), io.ErrShortBuffer),
			sizeHint:   1500,
			wantSecond: 1500,
		},
		{
			name:       "temporary",
			err:        temporaryReadError{},
			wantSecond: 20,
		},
		{
			name:       "deadline",
			err:        os.ErrDeadlineExceeded,
			wantSecond: 20,
		},
		{
			name:       "legacy capacity error",
			err:        errors.New("device: need more buffers"),
			wantSecond: 20,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := ipv4TestPacket()
			device := newScriptedTun(
				len(packet),
				scriptedRead{err: test.err, sizeHint: test.sizeHint},
				scriptedRead{packet: packet},
			)
			dispatcher := &recordingDispatcher{
				packets: make(chan deliveredPacket, 1),
			}
			endpoint := NewTunEndpoint(device, 1)
			endpoint.Attach(dispatcher)
			endpoint.Wait()

			select {
			case got := <-dispatcher.packets:
				if !bytes.Equal(got.packet, packet) {
					t.Fatalf("delivered packet = %x, want %x", got.packet, packet)
				}
			default:
				t.Fatal("endpoint did not deliver the packet after a recoverable error")
			}
			capacities := device.readCapacities()
			if len(capacities) != 3 {
				t.Fatalf("Read calls = %d, want 3", len(capacities))
			}
			if capacities[1] != test.wantSecond {
				t.Fatalf("second read capacity = %d, want %d", capacities[1], test.wantSecond)
			}
		})
	}
}

func TestTunEndpointDeliversPacketsReturnedWithRecoverableError(t *testing.T) {
	packet := ipv4TestPacket()
	device := newScriptedTun(
		len(packet),
		scriptedRead{packet: packet, err: temporaryReadError{}},
	)
	dispatcher := &recordingDispatcher{
		packets: make(chan deliveredPacket, 1),
	}
	endpoint := NewTunEndpoint(device, 1)
	endpoint.Attach(dispatcher)
	endpoint.Wait()

	select {
	case got := <-dispatcher.packets:
		if !bytes.Equal(got.packet, packet) {
			t.Fatalf("delivered packet = %x, want %x", got.packet, packet)
		}
	default:
		t.Fatal("endpoint discarded a packet returned with a recoverable error")
	}
}

func TestTunEndpointGrowsAfterRepeatedShortBufferErrors(t *testing.T) {
	packet := ipv4TestPacket()
	device := newScriptedTun(
		len(packet),
		scriptedRead{err: io.ErrShortBuffer},
		scriptedRead{err: io.ErrShortBuffer},
		scriptedRead{err: io.ErrShortBuffer},
		scriptedRead{packet: packet},
	)
	dispatcher := &recordingDispatcher{
		packets: make(chan deliveredPacket, 1),
	}
	endpoint := NewTunEndpoint(device, 1)
	endpoint.Attach(dispatcher)
	endpoint.Wait()

	select {
	case <-dispatcher.packets:
	default:
		t.Fatal("endpoint did not deliver a packet after repeated capacity errors")
	}
	want := []int{20, 40, 80, 160, 160}
	if got := device.readCapacities(); !slices.Equal(got, want) {
		t.Fatalf("read capacities = %v, want %v", got, want)
	}
}

func TestTunEndpointStopsAfterTerminalReadError(t *testing.T) {
	device := newScriptedTun(
		1500,
		scriptedRead{err: errors.New("terminal read error")},
		scriptedRead{packet: ipv4TestPacket()},
	)
	endpoint := NewTunEndpoint(device, 1)
	endpoint.Attach(&recordingDispatcher{packets: make(chan deliveredPacket, 1)})
	endpoint.Wait()

	if got := len(device.readCapacities()); got != 1 {
		t.Fatalf("Read calls = %d, want 1", got)
	}
}

func TestTunEndpointDoesNotReadAfterCancellation(t *testing.T) {
	device := newScriptedTun(1500, scriptedRead{packet: ipv4TestPacket()})
	endpoint := NewTunEndpoint(device, 1)
	endpoint.cancel()
	endpoint.Attach(&recordingDispatcher{packets: make(chan deliveredPacket, 1)})
	endpoint.Wait()

	if got := len(device.readCapacities()); got != 0 {
		t.Fatalf("Read calls = %d, want 0", got)
	}
}

func TestTunEndpointReadBufferGrowthIsBounded(t *testing.T) {
	device := newScriptedTun(1500)
	device.batchSize = 2
	device.readOffset = 7
	endpoint := NewTunEndpoint(device, 1)

	bufs := [][]byte{
		make([]byte, device.readOffset+1500),
		make([]byte, device.readOffset+1500),
	}
	bufs = endpoint.growReadBuffers(bufs, []int{0, 5000})
	for i, buf := range bufs {
		if got := len(buf) - device.readOffset; got != 5000 {
			t.Fatalf("buffer %d packet capacity = %d, want 5000", i, got)
		}
	}

	bufs = endpoint.growReadBuffers(bufs, []int{maxTunReadPacketSize + 1, 0})
	for i, buf := range bufs {
		if got := len(buf) - device.readOffset; got != maxTunReadPacketSize {
			t.Fatalf(
				"buffer %d packet capacity = %d, want maximum %d",
				i,
				got,
				maxTunReadPacketSize,
			)
		}
	}

	bufs = endpoint.growReadBuffers(bufs, []int{maxTunReadPacketSize + 1, 0})
	if got := len(bufs[0]) - device.readOffset; got != maxTunReadPacketSize {
		t.Fatalf("capacity after maximum = %d, want %d", got, maxTunReadPacketSize)
	}
}

func TestTunEndpointRecoversFromJoinerMixedMTUs(t *testing.T) {
	defaultInput, defaultPeer := tun.Pipe(1, 1420, 0, 0)
	secondaryInput, secondaryPeer := tun.Pipe(1, 1500, 0, 0)
	joiner := tun.NewJoiner(nil, nil)
	if err := joiner.AttachDefault(defaultInput); err != nil {
		t.Fatalf("AttachDefault: %v", err)
	}
	if err := joiner.AttachSecondary(secondaryInput); err != nil {
		t.Fatalf("AttachSecondary: %v", err)
	}
	if mtu, err := joiner.MTU(); err != nil || mtu != 1420 {
		t.Fatalf("Joiner MTU = %d, %v; want 1420, nil", mtu, err)
	}
	endpoint := NewTunEndpoint(joiner, 1)
	t.Cleanup(func() {
		endpoint.Close()
		endpoint.Wait()
		_ = defaultPeer.Close()
		_ = secondaryPeer.Close()
	})
	dispatcher := &recordingDispatcher{
		packets: make(chan deliveredPacket, 1),
	}
	endpoint.Attach(dispatcher)

	packet := make([]byte, 1500)
	copy(packet, ipv4TestPacket())
	written := make(chan error, 1)
	go func() {
		_, err := secondaryPeer.Write([][]byte{packet}, 0)
		written <- err
	}()

	select {
	case got := <-dispatcher.packets:
		if !bytes.Equal(got.packet, packet) {
			t.Fatalf("delivered packet differs from the input packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("endpoint did not recover and deliver the larger Joiner packet")
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not complete")
	}
}
