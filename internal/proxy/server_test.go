package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) *Config {
	t.Helper()

	c := &Config{
		ListenAddr:   "127.0.0.1",
		AuthToken:    "test-token-of-sufficient-length",
		AllowedHosts: []string{".ct.example.com", "single.example.org"},
		AllowedPorts: []int{443, 8443},
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}

	return c
}

// startProxy runs a proxy on an ephemeral port and returns its address.
func startProxy(t *testing.T, cfg *Config) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(cfg)
	go func() { _ = s.server.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	return ln.Addr().String()
}

// connect issues a raw CONNECT and returns the status line.
func connect(t *testing.T, proxyAddr, target, token string) (string, net.Conn) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if token != "" {
		req += "Proxy-Authorization: Bearer " + token + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("reading status line: %v", err)
	}

	return strings.TrimSpace(line), conn
}

func TestRejectsMissingToken(t *testing.T) {
	addr := startProxy(t, testConfig(t))

	status, conn := connect(t, addr, "a.ct.example.com:443", "")
	defer conn.Close()

	if !strings.Contains(status, "407") {
		t.Errorf("status = %q, want 407 Proxy Authentication Required", status)
	}
}

func TestRejectsWrongToken(t *testing.T) {
	addr := startProxy(t, testConfig(t))

	status, conn := connect(t, addr, "a.ct.example.com:443", "wrong-token-but-long-enough")
	defer conn.Close()

	if !strings.Contains(status, "407") {
		t.Errorf("status = %q, want 407", status)
	}
}

func TestRejectsDisallowedHost(t *testing.T) {
	cfg := testConfig(t)
	addr := startProxy(t, cfg)

	// A valid token must not be enough to reach an arbitrary host: this is what
	// stops a leaked token turning the proxy into an open relay.
	status, conn := connect(t, addr, "evil.example.net:443", cfg.AuthToken)
	defer conn.Close()

	if !strings.Contains(status, "403") {
		t.Errorf("status = %q, want 403 for a host outside the allowlist", status)
	}
}

func TestRejectsDisallowedPort(t *testing.T) {
	cfg := testConfig(t)
	addr := startProxy(t, cfg)

	status, conn := connect(t, addr, "a.ct.example.com:22", cfg.AuthToken)
	defer conn.Close()

	if !strings.Contains(status, "403") {
		t.Errorf("status = %q, want 403 for a port outside the allowlist", status)
	}
}

func TestRejectsNonConnect(t *testing.T) {
	cfg := testConfig(t)
	addr := startProxy(t, cfg)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+cfg.AuthToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 — plain HTTP relaying must be refused", resp.StatusCode)
	}
}

func TestRejectsDisallowedSourceIP(t *testing.T) {
	cfg := testConfig(t)
	// Allow only an address this test cannot be connecting from.
	cfg.AllowedIPs = []string{"203.0.113.0/24"}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	addr := startProxy(t, cfg)

	status, conn := connect(t, addr, "a.ct.example.com:443", cfg.AuthToken)
	defer conn.Close()

	if !strings.Contains(status, "403") {
		t.Errorf("status = %q, want 403 for a source outside the allowlist", status)
	}
}

// TestTunnelsToAllowedHost proves the happy path actually carries traffic, not
// just that the checks pass.
func TestTunnelsToAllowedHost(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	upstreamHost, upstreamPort, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	upstreamPortNum := 0
	if _, err := fmt.Sscanf(upstreamPort, "%d", &upstreamPortNum); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	// httptest listens on loopback, which the SSRF guard blocks by design, so
	// allow it explicitly for this test only.
	cfg.AllowedHosts = []string{upstreamHost}
	cfg.AllowedPorts = []int{upstreamPortNum}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	s := NewServer(cfg)
	s.allowLoopbackForTest = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() { _ = s.server.Serve(ln) }()

	status, conn := connect(t, ln.Addr().String(),
		net.JoinHostPort(upstreamHost, upstreamPort), cfg.AuthToken)
	defer conn.Close()

	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q, want 200 Connection Established", status)
	}

	// Speak TLS through the established tunnel and fetch from upstream.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: upstreamHost})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through tunnel failed: %v", err)
	}

	if _, err := tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + upstreamHost + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	body, _ := io.ReadAll(tlsConn)
	if !strings.Contains(string(body), "hello from upstream") {
		t.Errorf("tunnel did not carry the upstream response, got: %q", string(body))
	}

	if s.total.Load() != 1 {
		t.Errorf("tunnel count = %d, want 1", s.total.Load())
	}
}

func TestHealthIsUnauthenticatedAndQuiet(t *testing.T) {
	addr := startProxy(t, testConfig(t))

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "token") || len(body) > 32 {
		t.Errorf("health response leaks detail: %q", string(body))
	}
}

func TestStatsRequiresToken(t *testing.T) {
	cfg := testConfig(t)
	addr := startProxy(t, cfg)

	resp, err := http.Get("http://" + addr + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("unauthenticated /stats = %d, want 407", resp.StatusCode)
	}
}
