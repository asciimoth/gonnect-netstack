//go:build ignore

package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/gonnectnetstack/vtun"
)

func main() {
	optsServer := vtun.Opts{
		// LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.4.29")},
	}
	tunServer, err := optsServer.Build()
	if err != nil {
		panic(err)
	}
	// Get addresses for cross-tun communication
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
		DnsServers: []netip.Addr{tun2Addr},
	}
	tunClient, err := optsClient.Build()
	if err != nil {
		panic(err)
	}

	// Wait for both tunnels to be up
	<-tunClient.Events()
	<-tunServer.Events()

	// Start packet forwarding
	go func() {
		if err := tun.Copy(tunClient, tunServer); err != nil {
			log.Printf("Copy error: %v", err)
		}
	}()

	// Start client
	go func() {
		client(tunClient, tun2Addr)
	}()

	// Start server (blocks)
	serve(tunServer, tun2Addr)
}

func client(tnet *vtun.VTun, serverAddr netip.Addr) {
	time.Sleep(1 * time.Second)
	log.Println("starting client")

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.Dial,
		},
	}
	serverURL := "http://" + netip.AddrPortFrom(serverAddr, 80).String()
	resp, err := client.Get(serverURL)
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))
}

func serve(tnet *vtun.VTun, serverAddr netip.Addr) {
	// Use wildcard addresses - automatically binds to first local address
	dnsAddrPort := netip.AddrPortFrom(serverAddr, 53)
	dnsl, err := tnet.ListenUDPAddrPort(dnsAddrPort)
	if err != nil {
		log.Panicln(err)
	}

	listener, err := tnet.ListenTCP(
		context.Background(),
		"tcp4",
		"0.0.0.0:80",
		// netip.AddrPortFrom(serverAddr, 80).String(),
	)
	if err != nil {
		log.Panicln(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsl.ReadFrom(buf)
			if err != nil {
				continue
			}

			resp := handleDNS(buf[:n], serverAddr)
			_, err = dnsl.WriteTo(resp, addr)
			if err != nil {
				log.Println("write error:", err)
			}

			log.Printf("Dns request served")
		}
	}()
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("> %s - %s - %s", request.RemoteAddr, request.URL.String(), request.UserAgent())
		io.WriteString(writer, "Hello from userspace TCP!")
	})
	log.Println("starting server")
	err = http.Serve(listener, nil)
	if err != nil {
		log.Panicln(err)
	}
}

// Extra simple dns server.
// Responding with fixed hardcoded IPv4 addr for any response.
func handleDNS(query []byte, serverAddr netip.Addr) []byte {
	// Copy query into response buffer
	resp := make([]byte, len(query)+16) // extra for answer
	copy(resp, query)

	resp[2] = 0x81
	resp[3] = 0x80

	// ANCOUNT = 1
	binary.BigEndian.PutUint16(resp[6:8], 1)

	// NSCOUNT, ARCOUNT = 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0

	// Find end of question section
	offset := 12
	for {
		l := int(query[offset])
		offset++
		if l == 0 {
			break
		}
		offset += l
	}
	offset += 4 // QTYPE + QCLASS

	ans := resp[offset:]

	// Name: pointer to question (0xC00C)
	ans[0] = 0xC0
	ans[1] = 0x0C

	// TYPE A (1), CLASS IN (1)
	binary.BigEndian.PutUint16(ans[2:4], 1)
	binary.BigEndian.PutUint16(ans[4:6], 1)

	// TTL = 60
	binary.BigEndian.PutUint32(ans[6:10], 60)

	// RDLENGTH = 4
	binary.BigEndian.PutUint16(ans[10:12], 4)

	// RDATA = server address
	addrBytes := serverAddr.As4()
	ans[12] = addrBytes[0]
	ans[13] = addrBytes[1]
	ans[14] = addrBytes[2]
	ans[15] = addrBytes[3]

	return resp[:offset+16]
}
