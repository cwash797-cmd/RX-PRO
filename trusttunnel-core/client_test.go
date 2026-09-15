package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testEndpoint(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("test-user:test-password")) {
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		b := make([]byte, 8192)
		for {
			n, e := r.Body.Read(b)
			if n > 0 {
				w.Write(b[:n])
				w.(http.Flusher).Flush()
			}
			if e != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, e := newClient(Config{Server: srv.Listener.Addr().String(), Hostname: "example.com", Username: "test-user", Password: "test-password", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})), HasIPv6: true, ClientRandomPrefix: "12345678/ffffffff"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, srv
}
func TestHTTP2ConnectEchoAndMultiplex(t *testing.T) {
	c, _ := testEndpoint(t)
	for i := 0; i < 3; i++ {
		s, e := c.open(context.Background(), "example.net:443", "RX-PRO")
		if e != nil {
			t.Fatal(e)
		}
		s.SetDeadline(time.Now().Add(3 * time.Second))
		data := bytes.Repeat([]byte("tunnel-data"), 20000)
		go func() { s.Write(data); s.CloseWrite() }()
		got, e := io.ReadAll(s)
		s.Close()
		if e != nil || !bytes.Equal(data, got) {
			t.Fatalf("echo failed: %v (%d bytes)", e, len(got))
		}
	}
}
func TestCertificateValidation(t *testing.T) {
	c, _ := testEndpoint(t)
	c.cfg.Hostname = "wrong.invalid"
	if s, e := c.open(context.Background(), "example.net:443", "RX-PRO"); e == nil {
		s.Close()
		t.Fatal("hostname mismatch accepted")
	}
}
func TestUnknownCARejected(t *testing.T) {
	c, srv := testEndpoint(t)
	other, e := newClient(Config{Server: srv.Listener.Addr().String(), Hostname: c.cfg.Hostname, Username: "test-user", Password: "test-password"})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if s, e := other.open(context.Background(), "example.net:443", "RX-PRO"); e == nil {
		s.Close()
		t.Fatal("untrusted certificate accepted")
	}
}
func TestBadAuthentication(t *testing.T) {
	c, _ := testEndpoint(t)
	c.cfg.Password = "wrong"
	if _, e := c.open(context.Background(), "example.net:443", "RX-PRO"); e == nil || !strings.Contains(e.Error(), "407") {
		t.Fatalf("expected authentication error: %v", e)
	}
}
func TestClientShutdown(t *testing.T) {
	c, _ := testEndpoint(t)
	s, e := c.open(context.Background(), "example.net:443", "RX-PRO")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	defer s.Close()
	if _, e = c.open(context.Background(), "example.net:443", "RX-PRO"); e == nil {
		t.Fatal("reopened stopped client")
	}
}
func TestRandomMask(t *testing.T) {
	for i := 0; i < 100; i++ {
		b, e := randomBytes("12345678/ff00ff00")
		if e != nil || len(b) != 32 || b[0] != 0x12 || b[2] != 0x56 {
			t.Fatal("incorrect mask")
		}
	}
	for _, v := range []string{"0", "gg", "1234/ff", "aa/bb/cc", strings.Repeat("ff", 33)} {
		if _, e := randomBytes(v); e == nil {
			t.Fatal("invalid prefix accepted")
		}
	}
}
func TestSOCKSFragmentedHandshake(t *testing.T) {
	c, _ := testEndpoint(t)
	server, client := net.Pipe()
	defer client.Close()
	go c.serve(server)
	client.SetDeadline(time.Now().Add(5 * time.Second))
	for _, v := range []byte{5, 1, 0} {
		if _, e := client.Write([]byte{v}); e != nil {
			t.Fatal(e)
		}
	}
	b := make([]byte, 2)
	if _, e := io.ReadFull(client, b); e != nil || !bytes.Equal(b, []byte{5, 0}) {
		t.Fatal("method negotiation failed")
	}
	request := append([]byte{5, 1, 0, 3, 11}, []byte("example.net")...)
	request = append(request, 1, 187)
	for _, v := range request {
		if _, e := client.Write([]byte{v}); e != nil {
			t.Fatal(e)
		}
	}
	b = make([]byte, 10)
	if _, e := io.ReadFull(client, b); e != nil || b[1] != 0 {
		t.Fatalf("SOCKS CONNECT failed: %v", e)
	}
	client.Write([]byte("echo"))
	b = make([]byte, 4)
	if _, e := io.ReadFull(client, b); e != nil || string(b) != "echo" {
		t.Fatalf("SOCKS echo failed: %v", e)
	}
}
func TestSOCKSUDPAssociation(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "_udp2" || r.Header.Get("User-Agent") != "android _udp2" {
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("test-user:test-password")) {
			w.WriteHeader(407)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			size := make([]byte, 4)
			if _, e := io.ReadFull(r.Body, size); e != nil {
				return
			}
			n := binary.BigEndian.Uint32(size)
			if n < 37 || n > 65578 {
				return
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(r.Body, b); e != nil {
				return
			}
			skip := 37 + int(b[36])
			if skip > len(b) {
				return
			}
			// Endpoint sends the remote address as source and original sender as destination.
			response := append([]byte{}, b[18:36]...)
			response = append(response, b[:18]...)
			response = append(response, b[skip:]...)
			response = append(binary.BigEndian.AppendUint32(nil, uint32(len(response))), response...)
			w.Write(response)
			w.(http.Flusher).Flush()
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	c, e := newClient(Config{Server: srv.Listener.Addr().String(), Hostname: "example.com", Username: "test-user", Password: "test-password", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	server, control := net.Pipe()
	defer control.Close()
	done := make(chan struct{})
	go func() { c.serve(server); close(done) }()
	control.SetDeadline(time.Now().Add(5 * time.Second))
	control.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, e = io.ReadFull(control, method); e != nil {
		t.Fatal(e)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, e = io.ReadFull(control, reply); e != nil || reply[1] != 0 {
		t.Fatalf("UDP associate: %v", e)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	udp, e := net.DialUDP("udp4", nil, relay)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	packet := append([]byte{0, 0, 0, 1, 192, 0, 2, 12, 0, 53}, []byte("test-datagram")...)
	for i := 0; i < 3; i++ {
		if _, e = udp.Write(packet); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 2048)
		n, e := udp.Read(buf)
		if e != nil || !bytes.Equal(packet, buf[:n]) {
			t.Fatalf("UDP echo mismatch: %v", e)
		}
	}
	control.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("association survives control closure")
	}
}

func TestHTTP2InitialStreamWindow(t *testing.T) {
	_, fixture := testEndpoint(t)
	listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: fixture.TLS.Certificates, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	window := make(chan uint32, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, e = io.ReadFull(conn, preface); e != nil {
			return
		}
		frame, e := http2.NewFramer(conn, conn).ReadFrame()
		if e != nil {
			return
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok {
			settings.ForeachSetting(func(s http2.Setting) error {
				if s.ID == http2.SettingInitialWindowSize {
					window <- s.Val
				}
				return nil
			})
		}
	}()
	c, e := newClient(Config{Server: listener.Addr().String(), Hostname: "example.com", Username: "test-user", Password: "test-password", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}))})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.session(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case value := <-window:
		if value != 131072 {
			t.Fatalf("unexpected stream window %d", value)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("no initial window setting")
	}
}

func TestClientHelloRandomOnWire(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	captured := make(chan []byte, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 5)
		if _, e = io.ReadFull(conn, header); e != nil {
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
		if _, e = io.ReadFull(conn, body); e != nil {
			return
		}
		captured <- body
	}()
	c, e := newClient(Config{Server: listener.Addr().String(), Hostname: "example.com", Username: "test-user", Password: "test-password", ClientRandomPrefix: "12345678/ff00ff00"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.open(context.Background(), "example.net:443", "RX-PRO")
	select {
	case body := <-captured:
		if len(body) < 38 || body[0] != 1 || body[6] != 0x12 || body[8] != 0x56 {
			t.Fatal("TLS ClientHello prefix not applied on wire")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("no ClientHello received")
	}
}

func TestUDPWireFormat(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210}
	dst := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53}
	wire := udpFrame(src, dst, []byte("dns"))
	if !bytes.Equal(wire[4:16], make([]byte, 12)) {
		t.Fatal("IPv4 padding is not zero")
	}
	if int(binary.BigEndian.Uint32(wire[:4])) != len(wire)-4 || wire[40] != 6 {
		t.Fatal("outgoing length/app field incorrect")
	}
	// Endpoint response omits the outgoing app-name field.
	response := append([]byte{}, wire[4:40]...)
	response = append(response, []byte("dns")...)
	response = append(binary.BigEndian.AppendUint32(nil, uint32(len(response))), response...)
	a, b, p, e := readUDPFrame(bytes.NewReader(response))
	if e != nil || !a.IP.Equal(src.IP) || b.Port != 53 || string(p) != "dns" {
		t.Fatal("UDP response decode failed")
	}
	for _, size := range []uint32{0, 35, 65572, 0xffffffff} {
		if _, _, _, e := readUDPFrame(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))); e == nil {
			t.Fatal("invalid UDP length accepted")
		}
	}
}
