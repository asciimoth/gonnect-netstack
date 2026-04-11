//go:build ignore

package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/asciimoth/gonnect-netstack/vtun"
)

func main() {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{
			netip.MustParseAddr("192.168.4.28"),
		},
	}
	tun, err := opts.Build()
	if err != nil {
		panic(err)
	}

	// Wait for both tunnels to be up
	<-tun.Events()

	// Get the local address for client to connect to
	localAddrs := tun.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range localAddrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		panic("No IPv4 address found")
	}

	// Start client
	go func() {
		client(tun, serverAddr)
	}()

	// Start server (blocks)
	serve(tun)
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

func serve(tnet *vtun.VTun) {
	listener, err := tnet.ListenTCP(context.Background(), "tcp4", "0.0.0.0:80")
	if err != nil {
		log.Panicln(err)
	}
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
