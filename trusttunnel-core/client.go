// RX-PRO TrustTunnel HTTP/2 adapter, GPL-3.0-or-later.
// Wire format: https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type Config struct {
	Listen             string   `json:"listen"`
	Server             string   `json:"server"`
	Hostname           string   `json:"hostname"`
	SNI                string   `json:"sni"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	ClientRandomPrefix string   `json:"client_random_prefix"`
	Certificate        string   `json:"certificate"`
	SkipVerification   bool     `json:"skip_verification"`
	HasIPv6            bool     `json:"has_ipv6"`
	DNSUpstreams       []string `json:"dns_upstreams"`
}

type Client struct {
	cfg            Config
	mu             sync.Mutex
	conn           *http2.ClientConn
	sessions       []*http2.ClientConn
	roots          *x509.CertPool
	closed         bool
	lifetime       context.Context
	cancelLifetime context.CancelFunc
}

func newClient(cfg Config) (*Client, error) {
	if cfg.Server == "" || cfg.Hostname == "" || cfg.Username == "" || cfg.Password == "" || strings.ContainsAny(cfg.Username, ":\r\n") {
		return nil, errors.New("invalid TrustTunnel settings")
	}
	if _, _, err := net.SplitHostPort(cfg.Server); err != nil {
		return nil, errors.New("invalid server address")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	// Android exports its trusted CA store here: Go on Android may not discover
	// the APEX certificate location on every OS version by itself.
	if path := os.Getenv("RXPRO_CA_FILE"); path != "" {
		if b, e := os.ReadFile(path); e == nil {
			roots.AppendCertsFromPEM(b)
		}
	}
	if cfg.Certificate != "" {
		// Explicit trust anchors from tt:// are not discarded or combined with
		// unrelated public roots. Hostname verification remains mandatory.
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.Certificate)) {
			return nil, errors.New("invalid certificate bundle")
		}
	}
	if cfg.SNI == "" {
		cfg.SNI = cfg.Hostname
	}
	if _, err := randomBytes(cfg.ClientRandomPrefix); err != nil {
		return nil, err
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	return &Client{cfg: cfg, roots: roots, lifetime: lifetime, cancelLifetime: cancelLifetime}, nil
}

// Never include err.Error(): TLS/network errors can contain endpoint identities.
func tunnelStageError(stage string, err error) error {
	kind := "transport"
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		kind = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		kind = "timeout"
	case errors.As(err, &authority):
		kind = "certificate-untrusted"
	case errors.As(err, &hostname):
		kind = "certificate-name-mismatch"
	case errors.As(err, &certificate):
		kind = "certificate-invalid-or-expired"
	case errors.As(err, &network) && network.Timeout():
		kind = "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		kind = "peer-closed"
	case errors.Is(err, net.ErrClosed):
		kind = "connection-closed"
	}
	return fmt.Errorf("TrustTunnel %s failed [%s]", stage, kind)
}

func randomBytes(prefix string) ([]byte, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	if prefix == "" {
		return data, nil
	}
	parts := strings.Split(prefix, "/")
	if len(parts) > 2 {
		return nil, errors.New("invalid client_random_prefix")
	}
	p, err := hex.DecodeString(parts[0])
	if err != nil || len(p) == 0 || len(p) > 32 {
		return nil, errors.New("invalid client_random_prefix")
	}
	mask := make([]byte, len(p))
	for i := range mask {
		mask[i] = 255
	}
	if len(parts) == 2 {
		mask, err = hex.DecodeString(parts[1])
		if err != nil || len(mask) != len(p) {
			return nil, errors.New("invalid client_random mask")
		}
	}
	for i := range p {
		data[i] = (data[i] & ^mask[i]) | (p[i] & mask[i])
	}
	return data, nil
}
func (c *Client) session(ctx context.Context) (*http2.ClientConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("client stopped")
	}
	if c.conn != nil {
		// CanTakeNewRequest intentionally returns true for a connection closed
		// before its first stream. Without State checks this adapter reuses that
		// failed session forever instead of establishing a fresh connection.
		state := c.conn.State()
		if !state.Closed && !state.Closing && c.conn.CanTakeNewRequest() {
			return c.conn, nil
		}
	}
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 20*time.Second)
	defer handshakeCancel()
	raw, err := (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 20 * time.Second}).DialContext(handshakeCtx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, tunnelStageError("upstream TCP", err)
	}
	fail := true
	defer func() {
		if fail {
			raw.Close()
		}
	}()
	cfg := &utls.Config{ServerName: c.cfg.SNI, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	// Custom SNI is distinct from the endpoint certificate identity.
	cfg.VerifyConnection = func(state utls.ConnectionState) error {
		if c.cfg.SkipVerification {
			return nil
		}
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: intermediates, DNSName: c.cfg.Hostname})
		return err
	}
	conn := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err = conn.BuildHandshakeState(); err != nil {
		return nil, errors.New("TLS ClientHello creation failed")
	}
	for _, extension := range conn.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"h2"}
		}
	}
	random, err := randomBytes(c.cfg.ClientRandomPrefix)
	if err != nil {
		return nil, err
	}
	if err = conn.SetClientRandom(random); err != nil {
		return nil, errors.New("TLS random configuration failed")
	}
	if err = conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, tunnelStageError("TLS", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, errors.New("TrustTunnel requires ALPN h2")
	}
	// Configure through net/http to set the protocol's 128 KiB stream window.
	base := &http.Transport{HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: 131072}}
	transport, err := http2.ConfigureTransports(base)
	if err != nil {
		return nil, errors.New("HTTP/2 transport configuration failed")
	}
	transport.ReadIdleTimeout = 20 * time.Second
	transport.PingTimeout = 7 * time.Second
	transport.StrictMaxConcurrentStreams = true
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, errors.New("HTTP/2 session failed")
	}
	fail = false
	c.conn = cc
	active := c.sessions[:0]
	for _, previous := range c.sessions {
		if !previous.State().Closed {
			active = append(active, previous)
		}
	}
	c.sessions = append(active, cc)
	return cc, nil
}

// A CONNECT stream is a bidirectional pipe. Deadlines cancel this stream only,
// never the other multiplexed streams in the session.
type stream struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
	mu     sync.Mutex
	timer  *time.Timer
}

func (s *stream) Read(b []byte) (int, error)  { return s.reader.Read(b) }
func (s *stream) Write(b []byte) (int, error) { return s.writer.Write(b) }
func (s *stream) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.reader.Close()
		s.writer.Close()
		s.mu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Unlock()
	})
	return nil
}
func (s *stream) CloseWrite() error    { return s.writer.Close() }
func (s *stream) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (s *stream) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (s *stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if !t.IsZero() {
		s.timer = time.AfterFunc(time.Until(t), s.cancel)
	}
	return nil
}
func (s *stream) SetReadDeadline(t time.Time) error  { return s.SetDeadline(t) }
func (s *stream) SetWriteDeadline(t time.Time) error { return s.SetDeadline(t) }

func (c *Client) open(ctx context.Context, target, app string) (*stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	cc, err := c.session(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	reader, writer := io.Pipe()
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: make(http.Header), Body: reader, ContentLength: -1}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "android "+app)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.cfg.Username+":"+c.cfg.Password)))
	// Bound CONNECT setup but leave established streams alive until closed.
	timer := time.AfterFunc(25*time.Second, cancel)
	resp, err := cc.RoundTrip(req)
	timer.Stop()
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, tunnelStageError("HTTP2 CONNECT", err)
	}
	if resp.StatusCode != 200 {
		cancel()
		resp.Body.Close()
		reader.Close()
		writer.Close()
		if resp.StatusCode == 407 {
			cc.Close()
			return nil, errors.New("TrustTunnel authentication rejected (407)")
		}
		return nil, fmt.Errorf("TrustTunnel CONNECT rejected (%d)", resp.StatusCode)
	}
	return &stream{reader: resp.Body, writer: writer, cancel: cancel}, nil
}
func (c *Client) Close() {
	// Cancel a blocked dial/handshake before waiting on its session mutex.
	c.cancelLifetime()
	c.mu.Lock()
	c.closed = true
	sessions := append([]*http2.ClientConn(nil), c.sessions...)
	c.mu.Unlock()
	for _, cc := range sessions {
		cc.Close()
	}
}
