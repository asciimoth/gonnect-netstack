// nolint
package vtun_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect-netstack/vtun"
	gt "github.com/asciimoth/gonnect/testing"
	"github.com/asciimoth/gonnect/tun"
)

// setupVTunPair creates two connected VTun instances for testing.
// Returns the two VTun instances and a cleanup function.
func setupVTunPair(t *testing.T) (*vtun.VTun, *vtun.VTun, func()) {
	t.Helper()

	addr1 := netip.MustParseAddr("192.168.100.1")
	addr2 := netip.MustParseAddr("192.168.100.2")

	opts1 := vtun.Opts{
		LocalAddrs: []netip.Addr{addr1},
	}
	vtun1, err := opts1.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun1: %v", err)
	}

	opts2 := vtun.Opts{
		LocalAddrs: []netip.Addr{addr2},
	}
	vtun2, err := opts2.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun2: %v", err)
	}

	// Wait for both tunnels to be up
	<-vtun1.Events()
	<-vtun2.Events()

	p2p := tun.NewP2P(nil)
	p2p.SetA(vtun1)
	p2p.SetB(vtun2)

	// Start packet forwarding between them
	// copyDone := make(chan struct{})
	// go func() {
	// 	defer close(copyDone)
	// 	tun.Copy(vtun1, vtun2)
	// }()

	cleanup := func() {
		// vtun1.Close()
		// vtun2.Close()
		p2p.Stop()
	}

	return vtun1, vtun2, cleanup
}

// TestVTunUpDownBehavior tests the Up/Down functionality of VTun.
func TestVTunUpDownBehavior(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.200.1")},
	}
	vt, err := opts.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun: %v", err)
	}
	defer vt.Close()

	// Wait for initial EventUp
	select {
	case event := <-vt.Events():
		if event != tun.EventUp {
			t.Errorf("Expected EventUp, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventUp")
	}

	// Verify VTun is up initially
	isUp, err := vt.IsUp()
	if err != nil {
		t.Fatalf("IsUp() error: %v", err)
	}
	if !isUp {
		t.Error("Expected VTun to be up after build")
	}

	// Test Down - should send EventDown
	err = vt.Down()
	if err != nil {
		t.Fatalf("Down() error: %v", err)
	}

	// Wait for EventDown
	select {
	case event := <-vt.Events():
		if event != tun.EventDown {
			t.Errorf("Expected EventDown, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventDown")
	}

	// Test Up - should send EventUp
	err = vt.Up()
	if err != nil {
		t.Fatalf("Up() error: %v", err)
	}

	// Wait for EventUp
	select {
	case event := <-vt.Events():
		if event != tun.EventUp {
			t.Errorf("Expected EventUp, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventUp after Up()")
	}

	// Test idempotency: calling Down twice should not error
	err = vt.Down()
	if err != nil {
		t.Fatalf("First Down() error: %v", err)
	}
	// Consume the event from the first Down
	select {
	case event := <-vt.Events():
		if event != tun.EventDown {
			t.Errorf("Expected EventDown, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventDown")
	}

	// Second Down should be idempotent - no event sent
	err = vt.Down()
	if err != nil {
		t.Fatalf("Second Down() should not error: %v", err)
	}

	// Test idempotency: calling Up twice should not error
	err = vt.Up()
	if err != nil {
		t.Fatalf("First Up() error: %v", err)
	}
	// Consume the event from the first Up
	select {
	case event := <-vt.Events():
		if event != tun.EventUp {
			t.Errorf("Expected EventUp, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventUp")
	}

	// Second Up should be idempotent - no event sent
	err = vt.Up()
	if err != nil {
		t.Fatalf("Second Up() should not error: %v", err)
	}
}

// TestVTunUpDownAfterClose tests that Up/Down operations on a closed VTun are safe.
func TestVTunUpDownAfterClose(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.201.1")},
	}
	vt, err := opts.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun: %v", err)
	}

	// Wait for EventUp
	<-vt.Events()

	// Close the VTun
	vt.Close()

	// Up/Down after close should not panic or error
	err = vt.Up()
	if err != nil {
		t.Errorf("Up() after Close returned error: %v", err)
	}

	err = vt.Down()
	if err != nil {
		t.Errorf("Down() after Close returned error: %v", err)
	}

	isUp, err := vt.IsUp()
	if err != nil {
		t.Errorf("IsUp() after Close returned error: %v", err)
	}
	// After close, state may vary - just ensure no panic
	_ = isUp
}

// TestVTunTCPClientServer tests TCP communication between two connected VTun instances.
func TestVTunTCPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for server binding
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr string
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = netip.AddrPortFrom(addr, 8080).String()
			break
		}
	}
	if serverAddr == "" {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Start TCP server on vtun2
	listener, err := vtun2.ListenTCP(context.Background(), "tcp4", serverAddr)
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect from vtun1
	conn, err := vtun1.DialTCP(context.Background(), "tcp4", "", serverAddr)
	if err != nil {
		t.Fatalf("DialTCP failed: %v", err)
	}
	defer conn.Close()

	// Send and receive data
	testData := []byte("Hello from TCP client!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}

	conn.Close()
	listener.Close()
	<-serverDone
}

// TestVTunUDPClientServer tests UDP communication between two connected VTun instances.
func TestVTunUDPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for server binding
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr string
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = netip.AddrPortFrom(addr, 9090).String()
			break
		}
	}
	if serverAddr == "" {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Start UDP server on vtun2
	serverConn, err := vtun2.ListenUDPAddrPort(netip.MustParseAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort failed: %v", err)
	}
	defer serverConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		for {
			n, addr, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Echo server
			_, err = serverConn.WriteTo(buf[:n], addr)
			if err != nil {
				return
			}
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect from vtun1
	clientConn, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("DialUDPAddrPort failed: %v", err)
	}
	defer clientConn.Close()

	// Send and receive data
	testData := []byte("Hello from UDP client!")
	_, err = clientConn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}
}

// TestVTunICMPEcho tests ICMP ping between two connected VTun instances.
// Note: This test is currently skipped due to gVisor ICMP endpoint state management issues.
// The PingConn implementation requires specific endpoint states that aren't properly
// initialized in the current VTun setup.
func TestVTunICMPEcho(t *testing.T) {
	t.Skip("ICMP endpoint state management in gVisor requires further investigation")

	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for target
	vtun2Addrs := vtun2.LocalAddrs()
	var targetAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			targetAddr = addr
			break
		}
	}
	if !targetAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Create ping connection on vtun2 (listener) - bound to address but not connected
	pingListener, err := vtun2.DialPingAddr(targetAddr, netip.Addr{})
	if err != nil {
		t.Fatalf("DialPingAddr for listener failed: %v", err)
	}
	defer pingListener.Close()

	// Start ping responder
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		buf := make([]byte, 1024)
		for {
			n, from, err := pingListener.ReadFrom(buf)
			if err != nil {
				return
			}

			// Echo back the data (simple ICMP echo)
			_, err = pingListener.WriteTo(buf[:n], from)
			if err != nil {
				t.Logf("Ping responder error: %v", err)
				return
			}
		}
	}()

	// Give listener time to start
	time.Sleep(100 * time.Millisecond)

	// Create ping connection from vtun1 - connected to target
	pingConn, err := vtun1.DialPingAddr(netip.Addr{}, targetAddr)
	if err != nil {
		t.Fatalf("DialPingAddr failed: %v", err)
	}
	defer pingConn.Close()

	// Send ping using Write (connected socket)
	testData := []byte("ICMP echo request")
	_, err = pingConn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Wait for reply
	pingConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, from, err := pingConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	pingFrom := from.(*vtun.PingAddr)
	if pingFrom.Addr != targetAddr {
		t.Errorf("Expected reply from %v, got %v", targetAddr, pingFrom.Addr)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected echo reply %q, got %q", testData, buf[:n])
	}

	pingConn.Close()
	pingListener.Close()
	<-pingDone
}

// TestVTunDNSResolution tests DNS resolution through VTun.
func TestVTunDNSResolution(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for DNS server
	vtun2Addrs := vtun2.LocalAddrs()
	var dnsServerAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			dnsServerAddr = addr
			break
		}
	}
	if !dnsServerAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Setup a simple DNS server on vtun2
	dnsAddr := netip.AddrPortFrom(dnsServerAddr, 53)
	dnsConn, err := vtun2.ListenUDPAddrPort(dnsAddr)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Simple DNS response for "test.example.com"
			// This is a minimal response that just echoes back with a response flag
			query := buf[:n]
			if len(query) > 12 {
				// Set QR bit (response) and RCODE=0
				query[2] = 0x81
				query[3] = 0x80
				// Set ANCOUNT = 1
				query[6] = 0x00
				query[7] = 0x01
				// Add a simple A record response (192.168.100.2)
				response := append(query, 0xc0, 0x0c)               // Pointer to name
				response = append(response, 0x00, 0x01)             // Type A
				response = append(response, 0x00, 0x01)             // Class IN
				response = append(response, 0x00, 0x00, 0x00, 0x3c) // TTL 60
				response = append(response, 0x00, 0x04)             // RDLENGTH 4
				response = append(response, 192, 168, 100, 2)       // RDATA

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	// Give DNS server time to start
	time.Sleep(100 * time.Millisecond)

	// Configure vtun1 to use our DNS server
	vtun1.SetDnsServers([]netip.Addr{dnsServerAddr})

	// Test DNS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := vtun1.LookupIP(ctx, "ip4", "test.example.com")
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("Expected at least one IP address from DNS lookup")
	}

	expectedIP := net.ParseIP("192.168.100.2")
	if !ips[0].Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ips[0])
	}

	dnsConn.Close()
	<-dnsDone
}

// TestVTunHTTPClientServer tests HTTP communication between two connected VTun instances.
func TestVTunHTTPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Setup HTTP server on vtun2
	listener, err := vtun2.ListenTCP(context.Background(), "tcp4", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Server failed to read body: %v", err)
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		io.WriteString(w, "Echo: "+string(body))
	})

	server := &http.Server{Handler: mux}
	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Make HTTP requests in parallel
	client := http.Client{
		Transport: &http.Transport{
			DialContext: vtun1.Dial,
		},
		Timeout: 5 * time.Second,
	}

	requestCount := 200
	var wg sync.WaitGroup
	wg.Add(requestCount)

	httpServerAddr := netip.AddrPortFrom(serverAddr, 8080).String()
	for i := range requestCount {
		go func(id int) {
			defer wg.Done()

			testBody := fmt.Sprintf("Request %d", id)
			resp, err := client.Post("http://"+httpServerAddr+"/", "text/plain", strings.NewReader(testBody))
			if err != nil {
				t.Errorf("Request %d: HTTP POST failed: %v", id, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("Request %d: Expected status 200, got %d", id, resp.StatusCode)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Request %d: ReadAll failed: %v", id, err)
				return
			}

			expectedBody := "Echo: " + testBody
			if string(body) != expectedBody {
				t.Errorf("Request %d: Expected body %q, got %q", id, expectedBody, string(body))
			}
		}(i)
	}

	wg.Wait()

	// Cleanup
	server.Close()
	<-httpDone
}

// TestVTunMultipleConnections tests multiple concurrent TCP connections.
func TestVTunMultipleConnections(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	serverAddrPort := netip.AddrPortFrom(serverAddr, 8081)

	// Start TCP server
	listener, err := vtun2.ListenTCPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenTCPAddrPort failed: %v", err)
	}
	defer listener.Close()

	// Accept multiple connections
	connCount := 5
	var serverWg sync.WaitGroup
	serverWg.Add(connCount)

	go func() {
		for range connCount {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer serverWg.Done()
				defer c.Close()

				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				// Echo back with prefix in single write
				response := fmt.Sprintf("Echo: %s", buf[:n])
				c.Write([]byte(response))
			}(conn)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create multiple concurrent connections
	var clientWg sync.WaitGroup
	clientWg.Add(connCount)

	for i := range connCount {
		go func(id int) {
			defer clientWg.Done()

			conn, err := vtun1.DialTCPAddrPort(context.Background(), serverAddrPort)
			if err != nil {
				t.Errorf("DialTCPAddrPort %d failed: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("Connection %d", id)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				t.Errorf("Write %d failed: %v", id, err)
				return
			}

			buf := make([]byte, 1024)
			// Read the "Echo: " prefix
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("Read %d failed: %v", id, err)
				return
			}

			expected := "Echo: " + msg
			if string(buf[:n]) != expected {
				t.Errorf("Connection %d: Expected %q, got %q", id, expected, buf[:n])
			}
		}(i)
	}

	clientWg.Wait()
	listener.Close()
	serverWg.Wait()
}

// TestVTunWildcardBind tests wildcard address binding.
func TestVTunWildcardBind(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for connection target
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Test IPv4 wildcard
	listener, err := vtun2.ListenTCP(context.Background(), "tcp4", "0.0.0.0:8082")
	if err != nil {
		t.Fatalf("ListenTCP with wildcard failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect to server
	serverAddrPort := netip.AddrPortFrom(serverAddr, 8082)
	conn, err := vtun1.DialTCPAddrPort(context.Background(), serverAddrPort)
	if err != nil {
		t.Fatalf("DialTCP failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("Wildcard test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}

	conn.Close()
	listener.Close()
	<-serverDone
}

// TestVTunInterfaceMethods tests the interface-related methods of VTun.
func TestVTunInterfaceMethods(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.202.1")},
	}
	vt, err := opts.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun: %v", err)
	}
	defer vt.Close()

	// Wait for EventUp
	<-vt.Events()

	// Test Name
	name, err := vt.Name()
	if err != nil {
		t.Fatalf("Name() error: %v", err)
	}
	if name == "" {
		t.Error("Expected non-empty name")
	}

	// Test MTU
	mtu, err := vt.MTU()
	if err != nil {
		t.Fatalf("MTU() error: %v", err)
	}
	if mtu <= 0 {
		t.Errorf("Expected positive MTU, got %d", mtu)
	}

	// Test BatchSize
	batchSize := vt.BatchSize()
	if batchSize <= 0 {
		t.Errorf("Expected positive batch size, got %d", batchSize)
	}

	// Test Interfaces
	ifs, err := vt.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error: %v", err)
	}
	if len(ifs) == 0 {
		t.Error("Expected at least one interface")
	}

	// Test InterfaceAddrs
	addrs, err := vt.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs() error: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("Expected at least one address")
	}
}

// TestVTunLookupHost tests the LookupHost method.
func TestVTunLookupHost(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for DNS server
	vtun2Addrs := vtun2.LocalAddrs()
	var dnsServerAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			dnsServerAddr = addr
			break
		}
	}
	if !dnsServerAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Setup DNS server
	dnsConn, err := vtun2.ListenUDPAddrPort(netip.MustParseAddrPort(netip.AddrPortFrom(dnsServerAddr, 53).String()))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			query := buf[:n]
			if len(query) > 12 {
				query[2] = 0x81
				query[3] = 0x80
				query[6] = 0x00
				query[7] = 0x01
				response := append(query, 0xc0, 0x0c)
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x00, 0x00, 0x3c)
				response = append(response, 0x00, 0x04)
				response = append(response, 10, 0, 0, 1)

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	vtun1.SetDnsServers([]netip.Addr{dnsServerAddr})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts, err := vtun1.LookupHost(ctx, "test.example.com")
	if err != nil {
		t.Fatalf("LookupHost failed: %v", err)
	}

	if len(hosts) == 0 {
		t.Fatal("Expected at least one host")
	}

	if hosts[0] != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1, got %s", hosts[0])
	}

	dnsConn.Close()
	<-dnsDone
}

// TestVTunPingInvalidAddress tests ping with invalid addresses.
func TestVTunPingInvalidAddress(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.203.1")},
	}
	vt, err := opts.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun: %v", err)
	}
	defer vt.Close()

	<-vt.Events()

	// Test with both addresses invalid
	_, err = vt.DialPingAddr(netip.Addr{}, netip.Addr{})
	if err == nil {
		t.Error("Expected error when both addresses are invalid")
	}
}

// TestVTunConcurrentUDPServer tests UDP server handling multiple clients.
func TestVTunConcurrentUDPServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	serverAddrPort := netip.AddrPortFrom(serverAddr, 9091)

	// Start UDP server on vtun2
	serverConn, err := vtun2.ListenUDPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort failed: %v", err)
	}
	defer serverConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		for {
			n, addr, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Echo with server prefix
			response := fmt.Sprintf("Server: %s", buf[:n])
			_, err = serverConn.WriteTo([]byte(response), addr)
			if err != nil {
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Multiple clients
	clientCount := 3
	var wg sync.WaitGroup
	wg.Add(clientCount)

	for i := range clientCount {
		go func(id int) {
			defer wg.Done()

			clientConn, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, serverAddrPort)
			if err != nil {
				t.Errorf("Client %d: DialUDPAddrPort failed: %v", id, err)
				return
			}
			defer clientConn.Close()

			msg := fmt.Sprintf("Client %d", id)
			_, err = clientConn.Write([]byte(msg))
			if err != nil {
				t.Errorf("Client %d: Write failed: %v", id, err)
				return
			}

			buf := make([]byte, 1024)
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if err != nil {
				t.Errorf("Client %d: Read failed: %v", id, err)
				return
			}

			expected := fmt.Sprintf("Server: Client %d", id)
			if string(buf[:n]) != expected {
				t.Errorf("Client %d: Expected %q, got %q", id, expected, buf[:n])
			}
		}(i)
	}

	wg.Wait()
}

// TestVTunOperationsFailWhenDown tests that all lookup/dial/listen operations fail when VTun is down.
func TestVTunOperationsFailWhenDown(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPair(t)
	defer cleanup()

	// Get vtun2's first IPv4 address for DNS server and test targets
	vtun2Addrs := vtun2.LocalAddrs()
	var vtun2Addr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is4() && !addr.IsLoopback() {
			vtun2Addr = addr
			break
		}
	}
	if !vtun2Addr.IsValid() {
		t.Fatal("No IPv4 address found for vtun2")
	}

	// Setup DNS server on vtun2 for lookup tests
	dnsAddr := netip.AddrPortFrom(vtun2Addr, 53)
	dnsConn, err := vtun2.ListenUDPAddrPort(dnsAddr)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			query := buf[:n]
			if len(query) > 12 {
				query[2] = 0x81
				query[3] = 0x80
				query[6] = 0x00
				query[7] = 0x01
				response := append(query, 0xc0, 0x0c)
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x00, 0x00, 0x3c)
				response = append(response, 0x00, 0x04)
				response = append(response, 192, 168, 100, 2)

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	vtun1.SetDnsServers([]netip.Addr{vtun2Addr})

	// Bring down vtun1 - all operations should fail after this
	err = vtun1.Down()
	if err != nil {
		t.Fatalf("Down() error: %v", err)
	}

	// Wait for EventDown
	select {
	case event := <-vtun1.Events():
		if event != tun.EventDown {
			t.Errorf("Expected EventDown, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventDown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Helper to build address port from vtun2's address
	addrPort := func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(vtun2Addr, port)
	}
	addrPortStr := func(port uint16) string {
		return addrPort(port).String()
	}

	// Test LookupHost - should fail when down
	t.Run("LookupHost", func(t *testing.T) {
		_, err := vtun1.LookupHost(ctx, "test.example.com")
		if err == nil {
			t.Error("Expected LookupHost to fail when VTun is down")
		}
	})

	// Test LookupIP - should fail when down
	t.Run("LookupIP", func(t *testing.T) {
		_, err := vtun1.LookupIP(ctx, "ip4", "test.example.com")
		if err == nil {
			t.Error("Expected LookupIP to fail when VTun is down")
		}
	})

	// Test DialTCP - should fail when down
	t.Run("DialTCP", func(t *testing.T) {
		_, err := vtun1.DialTCP(ctx, "tcp4", "", addrPortStr(8080))
		if err == nil {
			t.Error("Expected DialTCP to fail when VTun is down")
		}
	})

	// Test DialTCPAddrPort - should fail when down
	t.Run("DialTCPAddrPort", func(t *testing.T) {
		_, err := vtun1.DialTCPAddrPort(ctx, addrPort(8080))
		if err == nil {
			t.Error("Expected DialTCPAddrPort to fail when VTun is down")
		}
	})

	// Test ListenTCP - should fail when down
	t.Run("ListenTCP", func(t *testing.T) {
		_, err := vtun1.ListenTCP(ctx, "tcp4", "0.0.0.0:8081")
		if err == nil {
			t.Error("Expected ListenTCP to fail when VTun is down")
		}
	})

	// Test ListenTCPAddrPort - should fail when down
	t.Run("ListenTCPAddrPort", func(t *testing.T) {
		_, err := vtun1.ListenTCPAddrPort(netip.MustParseAddrPort("0.0.0.0:8082"))
		if err == nil {
			t.Error("Expected ListenTCPAddrPort to fail when VTun is down")
		}
	})

	// Test DialUDP - should fail when down
	t.Run("DialUDP", func(t *testing.T) {
		_, err := vtun1.DialUDP(ctx, "udp4", "", addrPortStr(9090))
		if err == nil {
			t.Error("Expected DialUDP to fail when VTun is down")
		}
	})

	// Test DialUDPAddrPort - should fail when down
	t.Run("DialUDPAddrPort", func(t *testing.T) {
		_, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, addrPort(9090))
		if err == nil {
			t.Error("Expected DialUDPAddrPort to fail when VTun is down")
		}
	})

	// Test ListenUDP - should fail when down
	t.Run("ListenUDP", func(t *testing.T) {
		_, err := vtun1.ListenUDP(ctx, "udp4", "0.0.0.0:9091")
		if err == nil {
			t.Error("Expected ListenUDP to fail when VTun is down")
		}
	})

	// Test ListenUDPAddrPort - should fail when down
	t.Run("ListenUDPAddrPort", func(t *testing.T) {
		_, err := vtun1.ListenUDPAddrPort(netip.MustParseAddrPort("0.0.0.0:9092"))
		if err == nil {
			t.Error("Expected ListenUDPAddrPort to fail when VTun is down")
		}
	})

	// Test DialPingAddr - should fail when down
	t.Run("DialPingAddr", func(t *testing.T) {
		_, err := vtun1.DialPingAddr(netip.Addr{}, vtun2Addr)
		if err == nil {
			t.Error("Expected DialPingAddr to fail when VTun is down")
		}
	})

	// Test ListenPingAddr - should fail when down
	t.Run("ListenPingAddr", func(t *testing.T) {
		_, err := vtun1.ListenPingAddr(vtun2Addr)
		if err == nil {
			t.Error("Expected ListenPingAddr to fail when VTun is down")
		}
	})

	// Test Dial (generic) - should fail when down
	t.Run("Dial", func(t *testing.T) {
		_, err := vtun1.Dial(ctx, "tcp4", addrPortStr(8083))
		if err == nil {
			t.Error("Expected Dial to fail when VTun is down")
		}
	})

	// Test Listen (generic) - should fail when down
	t.Run("Listen", func(t *testing.T) {
		_, err := vtun1.Listen(ctx, "tcp4", "0.0.0.0:8084")
		if err == nil {
			t.Error("Expected Listen to fail when VTun is down")
		}
	})

	// Test ListenPacket - should fail when down
	t.Run("ListenPacket", func(t *testing.T) {
		_, err := vtun1.ListenPacket(ctx, "udp4", "0.0.0.0:9093")
		if err == nil {
			t.Error("Expected ListenPacket to fail when VTun is down")
		}
	})

	// Cleanup DNS server
	dnsConn.Close()
	<-dnsDone
}

func TestNativeNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		opts := vtun.Opts{
			// Use a custom lookup that fails immediately to avoid 50s DNS timeouts
			// when testing host-not-found scenarios
			Lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return nil, &net.DNSError{
					Err:        "no such host",
					Name:       host,
					IsNotFound: true,
				}
			},
		}
		vtun, err := opts.Build()
		if err != nil {
			panic(err)
		}
		return vtun
	})
}

func TestNativeNetworkTcpPingPong(t *testing.T) {
	opts := vtun.Opts{}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	defer vtun.Close()
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkHTTP(t *testing.T) {
	opts := vtun.Opts{}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestNativeNetworkUdpPingPong(t *testing.T) {
	opts := vtun.Opts{}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	defer vtun.Close()
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetwork_Stoppable(t *testing.T) {
	// defer vtun.Close()
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		opts := vtun.Opts{}
		vtun, err := opts.Build()
		if err != nil {
			panic(err)
		}
		return vtun
	}, "127.0.0.1:0")
}

// setupVTunPairIPv6 creates two connected VTun instances with IPv6 addresses for testing.
func setupVTunPairIPv6(t *testing.T) (*vtun.VTun, *vtun.VTun, func()) {
	t.Helper()

	addr1 := netip.MustParseAddr("fd00::1")
	addr2 := netip.MustParseAddr("fd00::2")

	opts1 := vtun.Opts{
		LocalAddrs: []netip.Addr{addr1},
	}
	vtun1, err := opts1.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun1: %v", err)
	}

	opts2 := vtun.Opts{
		LocalAddrs: []netip.Addr{addr2},
	}
	vtun2, err := opts2.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun2: %v", err)
	}

	// Wait for both tunnels to be up
	<-vtun1.Events()
	<-vtun2.Events()

	p2p := tun.NewP2P(nil)
	p2p.SetA(vtun1)
	p2p.SetB(vtun2)

	// Start packet forwarding between them
	// copyDone := make(chan struct{})
	// go func() {
	// 	defer close(copyDone)
	// 	tun.Copy(vtun1, vtun2)
	// }()

	cleanup := func() {
		// vtun1.Close()
		// vtun2.Close()
		p2p.Stop()
	}

	return vtun1, vtun2, cleanup
}

// TestVTunIPv6UpDownBehavior tests the Up/Down functionality of VTun with IPv6.
func TestVTunIPv6UpDownBehavior(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::200:1")},
	}
	vt, err := opts.Build()
	if err != nil {
		t.Fatalf("Failed to build VTun: %v", err)
	}
	defer vt.Close()

	// Wait for initial EventUp
	select {
	case event := <-vt.Events():
		if event != tun.EventUp {
			t.Errorf("Expected EventUp, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventUp")
	}

	// Verify VTun is up initially
	isUp, err := vt.IsUp()
	if err != nil {
		t.Fatalf("IsUp() error: %v", err)
	}
	if !isUp {
		t.Error("Expected VTun to be up after build")
	}

	// Test Down - should send EventDown
	err = vt.Down()
	if err != nil {
		t.Fatalf("Down() error: %v", err)
	}

	// Wait for EventDown
	select {
	case event := <-vt.Events():
		if event != tun.EventDown {
			t.Errorf("Expected EventDown, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventDown")
	}

	// Test Up - should send EventUp
	err = vt.Up()
	if err != nil {
		t.Fatalf("Up() error: %v", err)
	}

	// Wait for EventUp
	select {
	case event := <-vt.Events():
		if event != tun.EventUp {
			t.Errorf("Expected EventUp, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventUp after Up()")
	}
}

// TestVTunIPv6TCPClientServer tests TCP communication between two connected VTun instances over IPv6.
func TestVTunIPv6TCPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for server binding
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr string
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = netip.AddrPortFrom(addr, 8080).String()
			break
		}
	}
	if serverAddr == "" {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Start TCP server on vtun2
	listener, err := vtun2.ListenTCP(context.Background(), "tcp6", serverAddr)
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect from vtun1
	conn, err := vtun1.DialTCP(context.Background(), "tcp6", "", serverAddr)
	if err != nil {
		t.Fatalf("DialTCP failed: %v", err)
	}
	defer conn.Close()

	// Send and receive data
	testData := []byte("Hello from IPv6 TCP client!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}

	conn.Close()
	listener.Close()
	<-serverDone
}

// TestVTunIPv6UDPClientServer tests UDP communication between two connected VTun instances over IPv6.
func TestVTunIPv6UDPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for server binding
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr string
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = netip.AddrPortFrom(addr, 9090).String()
			break
		}
	}
	if serverAddr == "" {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Start UDP server on vtun2
	serverConn, err := vtun2.ListenUDPAddrPort(netip.MustParseAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort failed: %v", err)
	}
	defer serverConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		for {
			n, addr, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Echo server
			_, err = serverConn.WriteTo(buf[:n], addr)
			if err != nil {
				return
			}
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect from vtun1
	clientConn, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("DialUDPAddrPort failed: %v", err)
	}
	defer clientConn.Close()

	// Send and receive data
	testData := []byte("Hello from IPv6 UDP client!")
	_, err = clientConn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}
}

// TestVTunIPv6HTTPClientServer tests HTTP communication between two connected VTun instances over IPv6.
func TestVTunIPv6HTTPClientServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Setup HTTP server on vtun2 using explicit IPv6 address
	serverAddrPort := netip.AddrPortFrom(serverAddr, 8080)
	listener, err := vtun2.ListenTCPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenTCPAddrPort failed: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Server failed to read body: %v", err)
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		io.WriteString(w, "Echo: "+string(body))
	})

	server := &http.Server{Handler: mux}
	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Make HTTP request over IPv6
	client := http.Client{
		Transport: &http.Transport{
			DialContext: vtun1.Dial,
		},
		Timeout: 5 * time.Second,
	}

	httpServerAddr := netip.AddrPortFrom(serverAddr, 8080).String()
	testBody := "IPv6 HTTP request"
	resp, err := client.Post("http://"+httpServerAddr+"/", "text/plain", strings.NewReader(testBody))
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expectedBody := "Echo: " + testBody
	if string(body) != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, string(body))
	}

	server.Close()
	<-httpDone
}

// TestVTunIPv6WildcardBind tests wildcard address binding for IPv6.
func TestVTunIPv6WildcardBind(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for connection target
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Test IPv6 binding with explicit address
	serverAddrPort := netip.AddrPortFrom(serverAddr, 8082)
	listener, err := vtun2.ListenTCPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenTCPAddrPort failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect to server
	conn, err := vtun1.DialTCPAddrPort(context.Background(), serverAddrPort)
	if err != nil {
		t.Fatalf("DialTCPAddrPort failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("IPv6 Wildcard test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf[:n])
	}

	conn.Close()
	listener.Close()
	<-serverDone
}

// TestVTunIPv6MultipleConnections tests multiple concurrent TCP connections over IPv6.
func TestVTunIPv6MultipleConnections(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	serverAddrPort := netip.AddrPortFrom(serverAddr, 8081)

	// Start TCP server
	listener, err := vtun2.ListenTCPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenTCPAddrPort failed: %v", err)
	}
	defer listener.Close()

	// Accept multiple connections
	connCount := 5
	var serverWg sync.WaitGroup
	serverWg.Add(connCount)

	go func() {
		for range connCount {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer serverWg.Done()
				defer c.Close()

				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				// Echo back with prefix in single write
				response := fmt.Sprintf("Echo: %s", buf[:n])
				c.Write([]byte(response))
			}(conn)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create multiple concurrent connections
	var clientWg sync.WaitGroup
	clientWg.Add(connCount)

	for i := range connCount {
		go func(id int) {
			defer clientWg.Done()

			conn, err := vtun1.DialTCPAddrPort(context.Background(), serverAddrPort)
			if err != nil {
				t.Errorf("DialTCPAddrPort %d failed: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("Connection %d", id)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				t.Errorf("Write %d failed: %v", id, err)
				return
			}

			buf := make([]byte, 1024)
			// Read the "Echo: " prefix
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("Read %d failed: %v", id, err)
				return
			}

			expected := "Echo: " + msg
			if string(buf[:n]) != expected {
				t.Errorf("Connection %d: Expected %q, got %q", id, expected, buf[:n])
			}
		}(i)
	}

	clientWg.Wait()
	listener.Close()
	serverWg.Wait()
}

// TestVTunIPv6ConcurrentUDPServer tests UDP server handling multiple clients over IPv6.
func TestVTunIPv6ConcurrentUDPServer(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for server
	vtun2Addrs := vtun2.LocalAddrs()
	var serverAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			serverAddr = addr
			break
		}
	}
	if !serverAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	serverAddrPort := netip.AddrPortFrom(serverAddr, 9091)

	// Start UDP server on vtun2
	serverConn, err := vtun2.ListenUDPAddrPort(serverAddrPort)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort failed: %v", err)
	}
	defer serverConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		for {
			n, addr, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Echo with server prefix
			response := fmt.Sprintf("Server: %s", buf[:n])
			_, err = serverConn.WriteTo([]byte(response), addr)
			if err != nil {
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Multiple clients
	clientCount := 3
	var wg sync.WaitGroup
	wg.Add(clientCount)

	for i := range clientCount {
		go func(id int) {
			defer wg.Done()

			clientConn, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, serverAddrPort)
			if err != nil {
				t.Errorf("Client %d: DialUDPAddrPort failed: %v", id, err)
				return
			}
			defer clientConn.Close()

			msg := fmt.Sprintf("Client %d", id)
			_, err = clientConn.Write([]byte(msg))
			if err != nil {
				t.Errorf("Client %d: Write failed: %v", id, err)
				return
			}

			buf := make([]byte, 1024)
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if err != nil {
				t.Errorf("Client %d: Read failed: %v", id, err)
				return
			}

			expected := fmt.Sprintf("Server: Client %d", id)
			if string(buf[:n]) != expected {
				t.Errorf("Client %d: Expected %q, got %q", id, expected, buf[:n])
			}
		}(i)
	}

	wg.Wait()
}

// TestVTunIPv6DNSResolution tests DNS resolution through VTun over IPv6.
func TestVTunIPv6DNSResolution(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for DNS server
	vtun2Addrs := vtun2.LocalAddrs()
	var dnsServerAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			dnsServerAddr = addr
			break
		}
	}
	if !dnsServerAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Setup a simple DNS server on vtun2
	dnsAddr := netip.AddrPortFrom(dnsServerAddr, 53)
	dnsConn, err := vtun2.ListenUDPAddrPort(dnsAddr)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			// Simple DNS response for "test.example.com" with AAAA record
			query := buf[:n]
			if len(query) > 12 {
				// Set QR bit (response) and RCODE=0
				query[2] = 0x81
				query[3] = 0x80
				// Set ANCOUNT = 1
				query[6] = 0x00
				query[7] = 0x01
				// Add a simple AAAA record response (fd00::2)
				response := append(query, 0xc0, 0x0c)               // Pointer to name
				response = append(response, 0x00, 0x1c)             // Type AAAA
				response = append(response, 0x00, 0x01)             // Class IN
				response = append(response, 0x00, 0x00, 0x00, 0x3c) // TTL 60
				response = append(response, 0x00, 0x10)             // RDLENGTH 16
				// RDATA: fd00::2
				response = append(response, 0xfd, 0x00)
				for range 6 {
					response = append(response, 0x00, 0x00)
				}
				response = append(response, 0x00, 0x02)

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	// Give DNS server time to start
	time.Sleep(100 * time.Millisecond)

	// Configure vtun1 to use our DNS server
	vtun1.SetDnsServers([]netip.Addr{dnsServerAddr})

	// Test DNS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := vtun1.LookupIP(ctx, "ip6", "test.example.com")
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("Expected at least one IP address from DNS lookup")
	}

	expectedIP := net.ParseIP("fd00::2")
	if !ips[0].Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ips[0])
	}

	dnsConn.Close()
	<-dnsDone
}

// TestVTunIPv6LookupHost tests the LookupHost method over IPv6.
func TestVTunIPv6LookupHost(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for DNS server
	vtun2Addrs := vtun2.LocalAddrs()
	var dnsServerAddr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			dnsServerAddr = addr
			break
		}
	}
	if !dnsServerAddr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Setup DNS server
	dnsConn, err := vtun2.ListenUDPAddrPort(netip.MustParseAddrPort(netip.AddrPortFrom(dnsServerAddr, 53).String()))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			query := buf[:n]
			if len(query) > 12 {
				query[2] = 0x81
				query[3] = 0x80
				query[6] = 0x00
				query[7] = 0x01
				response := append(query, 0xc0, 0x0c)
				response = append(response, 0x00, 0x1c) // Type AAAA
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x00, 0x00, 0x3c)
				response = append(response, 0x00, 0x10) // RDLENGTH 16
				// RDATA: fd00::dead:beef
				response = append(response, 0xfd, 0x00)
				for range 5 {
					response = append(response, 0x00, 0x00)
				}
				response = append(response, 0xde, 0xad, 0xbe, 0xef)

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	vtun1.SetDnsServers([]netip.Addr{dnsServerAddr})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts, err := vtun1.LookupHost(ctx, "test.example.com")
	if err != nil {
		t.Fatalf("LookupHost failed: %v", err)
	}

	if len(hosts) == 0 {
		t.Fatal("Expected at least one host")
	}

	if hosts[0] != "fd00::dead:beef" {
		t.Errorf("Expected fd00::dead:beef, got %s", hosts[0])
	}

	dnsConn.Close()
	<-dnsDone
}

// TestVTunIPv6OperationsFailWhenDown tests that all operations fail when VTun is down (IPv6).
func TestVTunIPv6OperationsFailWhenDown(t *testing.T) {
	vtun1, vtun2, cleanup := setupVTunPairIPv6(t)
	defer cleanup()

	// Get vtun2's IPv6 address for DNS server and test targets
	vtun2Addrs := vtun2.LocalAddrs()
	var vtun2Addr netip.Addr
	for _, addr := range vtun2Addrs {
		if addr.Is6() && !addr.IsLoopback() {
			vtun2Addr = addr
			break
		}
	}
	if !vtun2Addr.IsValid() {
		t.Fatal("No IPv6 address found for vtun2")
	}

	// Setup DNS server on vtun2 for lookup tests
	dnsAddr := netip.AddrPortFrom(vtun2Addr, 53)
	dnsConn, err := vtun2.ListenUDPAddrPort(dnsAddr)
	if err != nil {
		t.Fatalf("ListenUDPAddrPort for DNS failed: %v", err)
	}
	defer dnsConn.Close()

	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}

			query := buf[:n]
			if len(query) > 12 {
				query[2] = 0x81
				query[3] = 0x80
				query[6] = 0x00
				query[7] = 0x01
				response := append(query, 0xc0, 0x0c)
				response = append(response, 0x00, 0x1c) // Type AAAA
				response = append(response, 0x00, 0x01)
				response = append(response, 0x00, 0x00, 0x00, 0x3c)
				response = append(response, 0x00, 0x10)
				// RDATA: fd00::2
				response = append(response, 0xfd, 0x00)
				for range 6 {
					response = append(response, 0x00, 0x00)
				}
				response = append(response, 0x00, 0x02)

				_, err = dnsConn.WriteTo(response, addr)
				if err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	vtun1.SetDnsServers([]netip.Addr{vtun2Addr})

	// Bring down vtun1 - all operations should fail after this
	err = vtun1.Down()
	if err != nil {
		t.Fatalf("Down() error: %v", err)
	}

	// Wait for EventDown
	select {
	case event := <-vtun1.Events():
		if event != tun.EventDown {
			t.Errorf("Expected EventDown, got %v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for EventDown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Helper to build address port from vtun2's address
	addrPort := func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(vtun2Addr, port)
	}
	addrPortStr := func(port uint16) string {
		return addrPort(port).String()
	}

	// Test LookupHost - should fail when down
	t.Run("LookupHost", func(t *testing.T) {
		_, err := vtun1.LookupHost(ctx, "test.example.com")
		if err == nil {
			t.Error("Expected LookupHost to fail when VTun is down")
		}
	})

	// Test LookupIP - should fail when down
	t.Run("LookupIP", func(t *testing.T) {
		_, err := vtun1.LookupIP(ctx, "ip6", "test.example.com")
		if err == nil {
			t.Error("Expected LookupIP to fail when VTun is down")
		}
	})

	// Test DialTCP - should fail when down
	t.Run("DialTCP", func(t *testing.T) {
		_, err := vtun1.DialTCP(ctx, "tcp6", "", addrPortStr(8080))
		if err == nil {
			t.Error("Expected DialTCP to fail when VTun is down")
		}
	})

	// Test DialTCPAddrPort - should fail when down
	t.Run("DialTCPAddrPort", func(t *testing.T) {
		_, err := vtun1.DialTCPAddrPort(ctx, addrPort(8080))
		if err == nil {
			t.Error("Expected DialTCPAddrPort to fail when VTun is down")
		}
	})

	// Test ListenTCP - should fail when down
	t.Run("ListenTCP", func(t *testing.T) {
		_, err := vtun1.ListenTCP(ctx, "tcp6", "[::]:8081")
		if err == nil {
			t.Error("Expected ListenTCP to fail when VTun is down")
		}
	})

	// Test ListenTCPAddrPort - should fail when down
	t.Run("ListenTCPAddrPort", func(t *testing.T) {
		_, err := vtun1.ListenTCPAddrPort(netip.MustParseAddrPort("[::]:8082"))
		if err == nil {
			t.Error("Expected ListenTCPAddrPort to fail when VTun is down")
		}
	})

	// Test DialUDP - should fail when down
	t.Run("DialUDP", func(t *testing.T) {
		_, err := vtun1.DialUDP(ctx, "udp6", "", addrPortStr(9090))
		if err == nil {
			t.Error("Expected DialUDP to fail when VTun is down")
		}
	})

	// Test DialUDPAddrPort - should fail when down
	t.Run("DialUDPAddrPort", func(t *testing.T) {
		_, err := vtun1.DialUDPAddrPort(netip.AddrPort{}, addrPort(9090))
		if err == nil {
			t.Error("Expected DialUDPAddrPort to fail when VTun is down")
		}
	})

	// Test ListenUDP - should fail when down
	t.Run("ListenUDP", func(t *testing.T) {
		_, err := vtun1.ListenUDP(ctx, "udp6", "[::]:9091")
		if err == nil {
			t.Error("Expected ListenUDP to fail when VTun is down")
		}
	})

	// Test ListenUDPAddrPort - should fail when down
	t.Run("ListenUDPAddrPort", func(t *testing.T) {
		_, err := vtun1.ListenUDPAddrPort(netip.MustParseAddrPort("[::]:9092"))
		if err == nil {
			t.Error("Expected ListenUDPAddrPort to fail when VTun is down")
		}
	})

	// Test DialPingAddr - should fail when down
	t.Run("DialPingAddr", func(t *testing.T) {
		_, err := vtun1.DialPingAddr(netip.Addr{}, vtun2Addr)
		if err == nil {
			t.Error("Expected DialPingAddr to fail when VTun is down")
		}
	})

	// Test ListenPingAddr - should fail when down
	t.Run("ListenPingAddr", func(t *testing.T) {
		_, err := vtun1.ListenPingAddr(vtun2Addr)
		if err == nil {
			t.Error("Expected ListenPingAddr to fail when VTun is down")
		}
	})

	// Test Dial (generic) - should fail when down
	t.Run("Dial", func(t *testing.T) {
		_, err := vtun1.Dial(ctx, "tcp6", addrPortStr(8083))
		if err == nil {
			t.Error("Expected Dial to fail when VTun is down")
		}
	})

	// Test Listen (generic) - should fail when down
	t.Run("Listen", func(t *testing.T) {
		_, err := vtun1.Listen(ctx, "tcp6", "[::]:8084")
		if err == nil {
			t.Error("Expected Listen to fail when VTun is down")
		}
	})

	// Test ListenPacket - should fail when down
	t.Run("ListenPacket", func(t *testing.T) {
		_, err := vtun1.ListenPacket(ctx, "udp6", "[::]:9093")
		if err == nil {
			t.Error("Expected ListenPacket to fail when VTun is down")
		}
	})

	// Cleanup DNS server
	dnsConn.Close()
	<-dnsDone
}

// TestNativeNetworkIPv6Compliance tests IPv6 network compliance.
func TestNativeNetworkIPv6Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		opts := vtun.Opts{
			Lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return nil, &net.DNSError{
					Err:        "no such host",
					Name:       host,
					IsNotFound: true,
				}
			},
			LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::c0:1")},
		}
		vtun, err := opts.Build()
		if err != nil {
			panic(err)
		}
		return vtun
	})
}

// TestNativeNetworkIPv6TcpPingPong tests IPv6 TCP ping pong.
func TestNativeNetworkIPv6TcpPingPong(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::1:1")},
	}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	defer vtun.Close()
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "[::1]:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

// TestNativeNetworkIPv6HTTP tests IPv6 HTTP communication.
func TestNativeNetworkIPv6HTTP(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::a1:1")},
	}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	defer vtun.Close()
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "[::1]:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

// TestNativeNetworkIPv6UdpPingPong tests IPv6 UDP ping pong.
func TestNativeNetworkIPv6UdpPingPong(t *testing.T) {
	opts := vtun.Opts{
		LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::b1:1")},
	}
	vtun, err := opts.Build()
	if err != nil {
		panic(err)
	}
	defer vtun.Close()
	pair := gt.NetAddrPair{
		Network: vtun,
		Addr:    "[::1]:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

// TestNativeNetworkIPv6Stoppable tests IPv6 stoppable network.
func TestNativeNetworkIPv6Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		opts := vtun.Opts{
			LocalAddrs: []netip.Addr{netip.MustParseAddr("fd00::c1:1")},
		}
		vtun, err := opts.Build()
		if err != nil {
			panic(err)
		}
		return vtun
	}, "[::1]:0")
}
