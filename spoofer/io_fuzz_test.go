package spoofer

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fuzzDispatcher struct {
	packets []deliveredPacket
}

func (d *fuzzDispatcher) DeliverNetworkPacket(
	protocol tcpip.NetworkProtocolNumber,
	pkt *stack.PacketBuffer,
) {
	buf := pkt.ToBuffer()
	defer buf.Release()
	d.packets = append(d.packets, deliveredPacket{
		protocol: protocol,
		packet:   bytes.Clone(buf.Flatten()),
	})
}

func (*fuzzDispatcher) DeliverLinkPacket(
	tcpip.NetworkProtocolNumber,
	*stack.PacketBuffer,
) {
}

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte{}, 0, 0, uint8(0))
	f.Add([]byte{0x45, 0, 0, 20}, 4, 1, uint8(4))
	f.Add([]byte{0x60, 0, 0, 0}, 4, 1, uint8(8))
	f.Add([]byte{0x45, 0x99}, 1, 1, uint8(0))
	f.Add([]byte{0x70}, 1, 2, uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, size, count int, readOffset uint8) {
		if len(data) > maxTunReadPacketSize {
			return
		}

		ioDispatcher := &fuzzDispatcher{}
		ioEP := &ioEndpoint{Endpoint: channel.New(1, 1500, "")}
		ioEP.Endpoint.Attach(ioDispatcher)
		ioEP.deliverPacket(data, size)
		checkFuzzDelivery(t, ioDispatcher.packets, data, size, size > 0 && size <= len(data))
		ioEP.Endpoint.Close()

		offset := int(readOffset)
		packetBuffer := make([]byte, offset+len(data))
		copy(packetBuffer[offset:], data)
		tunDispatcher := &fuzzDispatcher{}
		tunEP := &tunEndpoint{
			Endpoint:   channel.New(1, 1500, ""),
			readOffset: offset,
		}
		tunEP.Endpoint.Attach(tunDispatcher)
		tunEP.deliverPackets([][]byte{packetBuffer}, []int{size}, count)
		valid := count > 0 && size > 0 && size <= len(data)
		checkFuzzDelivery(t, tunDispatcher.packets, data, size, valid)
		tunEP.Endpoint.Close()
	})
}

func checkFuzzDelivery(
	t *testing.T,
	packets []deliveredPacket,
	data []byte,
	size int,
	validSize bool,
) {
	t.Helper()
	wantProtocol := tcpip.NetworkProtocolNumber(0)
	if validSize {
		switch header.IPVersion(data[:size]) {
		case header.IPv4Version:
			wantProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			wantProtocol = header.IPv6ProtocolNumber
		}
	}
	if wantProtocol == 0 {
		if len(packets) != 0 {
			t.Fatalf("delivered %d invalid packets", len(packets))
		}
		return
	}
	if len(packets) != 1 {
		t.Fatalf("delivered %d packets, want 1", len(packets))
	}
	if packets[0].protocol != wantProtocol {
		t.Fatalf("protocol = %d, want %d", packets[0].protocol, wantProtocol)
	}
	if !bytes.Equal(packets[0].packet, data[:size]) {
		t.Fatalf("delivered packet %x, want %x", packets[0].packet, data[:size])
	}
}
