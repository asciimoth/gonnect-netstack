//go:build ignore

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/spoofer"
	"github.com/asciimoth/gonnect-netstack/vtun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func main() {
	tunOpts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.4.29")},
		DnsServers: []netip.Addr{netip.MustParseAddr("8.8.8.8")},

		// NetStackOpts: &helpers.Opts{
		// 	DisableSACK: true,
		// },
	}
	tn, err := tunOpts.Build()
	if err != nil {
		panic(err)
	}
	// Get addresses for cross-tun communication
	tun2Addrs := tn.LocalAddrs()
	var tunAddr netip.Addr
	for _, addr := range tun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			tunAddr = addr
			break
		}
	}
	if !tunAddr.IsValid() {
		panic("Failed to find IPv4 address for tun")
	}
	log.Println("tun addr", tunAddr)

	sp := (&spoofer.Opts{
		OnTCPConn: func(c net.Conn, ep stack.TransportEndpointID) {
			fmt.Println("TCP", ep.RemoteAddress, ep.RemotePort, "->", ep.LocalAddress, ep.LocalPort)
			c2, err := net.Dial("tcp", net.JoinHostPort(
				ep.LocalAddress.String(), strconv.Itoa(int(ep.LocalPort)),
			))
			if err != nil {
				fmt.Println("TCP dial error:", err)
				c.Close()
				return
			}
			fmt.Println("TCP connected, starting copy")
			go func() {
				io.Copy(c, c2)
				c.Close()
				c2.Close()
			}()
			go func() {
				io.Copy(c2, c)
				c.Close()
				c2.Close()
			}()
		},
		OnUDPConn: func(c gonnect.PacketConn, ep stack.TransportEndpointID) {
			dstAddr, _ := netip.AddrFromSlice(ep.LocalAddress.AsSlice())
			remote := &net.UDPAddr{
				IP:   net.IP(dstAddr.AsSlice()),
				Port: int(ep.LocalPort),
			}
			fmt.Println("UDP", ep.RemoteAddress, ep.RemotePort, "->", ep.LocalAddress, ep.LocalPort)

			c2, err := net.ListenPacket("udp", "")
			// c2, err := net.DialUDP("udp", nil, remote)
			if err != nil {
				fmt.Println("UDP", err)
				c.Close()
				return
			}
			go func() {
				defer c2.Close()
				defer c.Close()
				for {
					buf := make([]byte, 4096)
					n, _, err := c.ReadFrom(buf)
					if err != nil {
						fmt.Println(err)
						return
					}
					if _, err := c2.WriteTo(buf[:n], remote); err != nil {
						fmt.Println(err)
						return
					}
					fmt.Println("UDP local -> remote")
				}
			}()
			go func() {
				defer c.Close()
				defer c2.Close()
				for {
					buf := make([]byte, 4096)
					n, _, err := c2.ReadFrom(buf)
					if err != nil {
						fmt.Println(err)
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						fmt.Println(err)
						return
					}
					fmt.Println("UDP local <- remote")
				}
			}()
		},
	}).WithTunEndpoint(tn, 0) // Or WithRWCEndpoint(tun.NewIO(tn), 0)

	stack, err := sp.Launch()
	if err != nil {
		log.Panic(err)
	}
	_ = stack // Can be used to Shutdown background goroutines

	// Use VTun's dialer for outgoing connections (VTun has the proper stack with addresses and DNS)
	// Prefer IPv4 to match original wireguard-go behavior
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tn.DialTCP(ctx, "tcp4", "", addr)
		},
	}
	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))

	// ListenUDP using VTun's stack
	conn, err := tn.ListenUDP(
		context.Background(),
		"udp",
		"0.0.0.0:7777",
	)
	if err != nil {
		log.Panic(err)
	}

	go func() {
		buf := make([]byte, 4098)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(addr, buf[:n])
		}
	}()

	// DNS query for example.com (A record)
	req := []byte{
		// Header
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// Question: example.com
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,          // null terminator
		0x00, 0x01, // QTYPE: A record
		0x00, 0x01, // QCLASS: IN
	}

	_, err = conn.WriteTo(req, &net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8).To4(),
		Port: 53,
	})
	if err != nil {
		log.Panic(err)
	}
	_, err = conn.WriteTo(req, &net.UDPAddr{
		IP:   net.IPv4(1, 1, 1, 1).To4(),
		Port: 53,
	})
	if err != nil {
		log.Panic(err)
	}

	time.Sleep(2 * time.Second)
}
