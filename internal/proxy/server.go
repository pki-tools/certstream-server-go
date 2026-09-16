package proxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Server is an authenticated CONNECT proxy.
//
// Only CONNECT is supported. Plain HTTP forwarding is deliberately refused: CT
// logs are all HTTPS, and accepting it would make this an open HTTP relay for
// anyone who obtained the token.
type Server struct {
	cfg    *Config
	server *http.Server

	active    atomic.Int64
	total     atomic.Int64
	rejected  atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	startedAt time.Time

	// allowLoopbackForTest disables the non-public address guard. Only the tests
	// set it: their upstream fixture necessarily listens on loopback, which the
	// guard blocks by design.
	allowLoopbackForTest bool
}

// NewServer builds a proxy server from config.
func NewServer(cfg *Config) *Server {
	s := &Server{cfg: cfg, startedAt: time.Now()}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
	})

	// CONNECT carries an authority ("host:port") rather than a path, so it must
	// bypass ServeMux: the mux would path-clean it and answer with a redirect.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			s.handleProxy(w, r)
			return
		}

		mux.ServeHTTP(w, r)
	})

	s.server = &http.Server{
		Addr:    net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.ListenPort)),
		Handler: handler,
		// No WriteTimeout: a CONNECT tunnel is long-lived and a write deadline
		// would sever it mid-transfer.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       cfg.IdleTimeout,
	}

	return s
}

// ListenAndServe starts the proxy, with TLS when configured.
func (s *Server) ListenAndServe() error {
	log.Printf("certstream-proxy listening on %s (hosts: %d patterns, ports: %v)\n",
		s.server.Addr, len(s.cfg.AllowedHosts), s.cfg.AllowedPorts)

	if s.cfg.TLS.CertPath != "" {
		return s.server.ListenAndServeTLS(s.cfg.TLS.CertPath, s.cfg.TLS.KeyPath)
	}

	log.Println("WARNING: TLS is not configured, so the auth token travels in plaintext. Set tls.cert_path and tls.key_path unless this hop is already private.")

	return s.server.ListenAndServe()
}

// Shutdown stops the proxy gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Addr returns the address the proxy is configured to listen on.
func (s *Server) Addr() string {
	return s.server.Addr
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Unauthenticated so load balancers can probe it, and deliberately free of
	// any detail that would help someone who found the port by scanning.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorised(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"uptimeSeconds":%d,"active":%d,"total":%d,"rejected":%d,"bytesUp":%d,"bytesDown":%d}`+"\n",
		int64(time.Since(s.startedAt).Seconds()), s.active.Load(), s.total.Load(),
		s.rejected.Load(), s.bytesUp.Load(), s.bytesDown.Load())
}

// authorised enforces the source-IP allowlist and the bearer token. It writes
// the response on failure.
func (s *Server) authorised(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if ip := net.ParseIP(host); ip == nil || !s.cfg.sourceAllowed(ip) {
		s.rejected.Add(1)
		log.Printf("proxy: rejected %s: source address not allowed\n", r.RemoteAddr)
		// 403 rather than 407: the caller cannot fix this by authenticating.
		http.Error(w, "forbidden", http.StatusForbidden)

		return false
	}

	if !s.tokenValid(r.Header.Get("Proxy-Authorization")) {
		s.rejected.Add(1)
		log.Printf("proxy: rejected %s: bad or missing token\n", r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", `Bearer realm="certstream-proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)

		return false
	}

	return true
}

// tokenValid compares in constant time so the token cannot be recovered by
// timing repeated guesses.
func (s *Server) tokenValid(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}

	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))

	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AuthToken)) == 1
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.authorised(w, r) {
		return
	}

	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "malformed target", http.StatusBadRequest)
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !s.cfg.portAllowed(port) {
		s.rejected.Add(1)
		log.Printf("proxy: rejected %s -> %s: port not allowed\n", r.RemoteAddr, r.Host)
		http.Error(w, "destination port not allowed", http.StatusForbidden)

		return
	}

	if !s.cfg.hostAllowed(host) {
		s.rejected.Add(1)
		log.Printf("proxy: rejected %s -> %s: host not allowed\n", r.RemoteAddr, r.Host)
		http.Error(w, "destination host not allowed", http.StatusForbidden)

		return
	}

	if s.active.Load() >= int64(s.cfg.MaxConnections) {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	upstream, err := s.dialUpstream(r.Context(), r.Host)
	if err != nil {
		log.Printf("proxy: dial %s failed: %v\n", r.Host, err)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)

		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Under HTTP/2 the connection cannot be hijacked. The main server speaks
		// HTTP/1.1 to proxies, so this indicates a misconfiguration.
		upstream.Close()
		http.Error(w, "proxy requires HTTP/1.1", http.StatusHTTPVersionNotSupported)

		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	s.active.Add(1)
	s.total.Add(1)
	defer s.active.Add(-1)

	s.tunnel(client, upstream)
}

// dialUpstream resolves and connects to the destination, refusing addresses
// that are not publicly routable.
func (s *Server) dialUpstream(ctx context.Context, target string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: s.cfg.DialTimeout,
		// Checked after resolution, so a permitted hostname cannot be pointed at
		// an internal address via DNS.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("unresolvable address %q", address)
			}

			if !publiclyRoutable(ip) && !s.allowLoopbackForTest {
				return fmt.Errorf("refusing to connect to non-public address %s", ip)
			}

			return nil
		},
	}

	return dialer.DialContext(ctx, "tcp", target)
}

// publiclyRoutable rejects loopback, private, link-local and similar ranges, so
// the proxy cannot be used to reach the host's own network.
func publiclyRoutable(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}

	// Carrier-grade NAT (100.64.0.0/10) is not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}

	return true
}

// countingWriter tallies bytes as they are written.
//
// Deliberately exposes only Write: that stops io.Copy taking a ReadFrom or
// splice fast path, which would move the data without the proxy ever seeing the
// byte count. Accurate live figures are the point here, and CT tunnels are
// long-lived enough that counting only on close would report zero for hours.
type countingWriter struct {
	w       io.Writer
	counter *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.counter.Add(int64(n))

	return n, err
}

// tunnel copies bytes in both directions until either side closes.
func (s *Server) tunnel(client, upstream net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(countingWriter{upstream, &s.bytesUp}, client)
		// Unblock the other direction once this one ends.
		if c, ok := upstream.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(countingWriter{client, &s.bytesDown}, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
