//go:build ignore

package main

import (
	"bytes"
	"log"
	"math/rand"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/gonnect/tun"
)

func main() {
	optsServer := vtun.Opts{
		LocalAddrs: []netip.Addr{
			netip.MustParseAddr("192.168.4.29"),
		},
	}
	tunServer, err := optsServer.Build()
	if err != nil {
		log.Panic(err)
	}
	tun2Addrs := tunServer.LocalAddrs()
	var tun2Addr netip.Addr
	for _, addr := range tun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			tun2Addr = addr
			break
		}
	}
	if !tun2Addr.IsValid() {
		panic("Failed to find IPv4 address for tun2")
	}
	log.Println("server addr", tun2Addr)

	optsClient := vtun.Opts{
		LocalAddrs: []netip.Addr{
			netip.MustParseAddr("192.168.4.28"),
		},
		DnsServers: []netip.Addr{tun2Addr},
	}
	tunClient, err := optsClient.Build()
	if err != nil {
		log.Panic(err)
	}

	// Wait for both tunnels to be up
	<-tunClient.Events()
	<-tunServer.Events()

	p2p := tun.NewP2P(nil)
	defer p2p.Stop()
	p2p.SetA(tunClient)
	p2p.SetB(tunServer)

	// Start packet forwarding
	// go func() {
	// 	if err := tun.Copy(tunClient, tunServer); err != nil {
	// 		log.Printf("Copy error: %v", err)
	// 	}
	// }()

	// Start server
	go func() {
		serve(tunServer, tun2Addr)
	}()

	// Start client (blocks)
	client(tunClient, tun2Addr)
	log.Println("Stopping")
}

func client(tnet *vtun.VTun, serverAddr netip.Addr) {
	time.Sleep(1 * time.Second)
	log.Println("starting ping client")

	socket, err := tnet.DialPingAddr(netip.Addr{}, serverAddr)
	if err != nil {
		log.Panic(err)
	}
	defer socket.Close()

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("gopher burrow"),
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	socket.SetReadDeadline(time.Now().Add(time.Second * 10))
	start := time.Now()
	_, err = socket.Write(icmpBytes)
	if err != nil {
		log.Panic(err)
	}
	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		log.Panic(err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		log.Panic(err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		log.Panicf("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		log.Panicf("invalid ping reply: %v", replyPing)
	}
	log.Printf("Ping latency: %v", time.Since(start))
}

func serve(tnet *vtun.VTun, serverAddr netip.Addr) {
	listener, err := tnet.ListenPingAddr(serverAddr)
	if err != nil {
		log.Panicln(err)
	}

	log.Println("ping server up")

	buf := make([]byte, 1024)
	for {
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			log.Println("read error:", err)
			continue
		}
		log.Println("ping packet received")

		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil {
			log.Println("parse error:", err)
			continue
		}

		switch msg.Type {
		case ipv4.ICMPTypeEcho:
			echo := msg.Body.(*icmp.Echo)
			log.Printf("Ping received from %s: id=%d, seq=%d, data=%q", addr, echo.ID, echo.Seq, string(echo.Data))

			reply := icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Code: 0,
				Body: &icmp.Echo{
					ID:   echo.ID,
					Seq:  echo.Seq,
					Data: echo.Data,
				},
			}
			replyBytes, err := reply.Marshal(nil)
			if err != nil {
				log.Println("marshal error:", err)
				continue
			}
			_, err = listener.WriteTo(replyBytes, addr)
			if err != nil {
				log.Println("write error:", err)
			}
			log.Printf("Ping reply sent to %s", addr)
		}
	}
}
