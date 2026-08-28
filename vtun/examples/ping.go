//go:build ignore

package main

import (
	"log"
	"net/netip"
	"time"

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

	p2p := tun.NewP2P(nil, nil)
	defer p2p.Stop()
	p2p.SetA(tunClient)
	p2p.SetB(tunServer)

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

	payload := []byte("gopher burrow")
	buf := make([]byte, 1024)
	socket.SetReadDeadline(time.Now().Add(time.Second * 10))
	start := time.Now()
	_, err = socket.Write(payload)
	if err != nil {
		log.Panic(err)
	}
	n, err := socket.Read(buf)
	if err != nil {
		log.Panic(err)
	}
	if string(buf[:n]) != string(payload) {
		log.Panicf("invalid ping reply: %q", buf[:n])
	}
	log.Printf("Ping latency: %v", time.Since(start))
}
