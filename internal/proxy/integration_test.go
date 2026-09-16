package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEndToEndThroughProxy runs the whole path the main server uses: an
// http.Transport pointed at a running proxy with a bearer token, fetching an
// HTTPS origin through a CONNECT tunnel. This is the shape applyProxy produces.
func TestEndToEndThroughProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fetched %s", r.URL.Path)
	}))
	defer origin.Close()

	originHost, originPort, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	var port int
	if _, err := fmt.Sscanf(originPort, "%d", &port); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ListenAddr:   "127.0.0.1",
		AuthToken:    "integration-token-long-enough",
		AllowedHosts: []string{originHost},
		AllowedPorts: []int{port},
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}

	s := NewServer(cfg)
	s.allowLoopbackForTest = true // the origin fixture is on loopback

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() { _ = s.server.Serve(ln) }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		ProxyConnectHeader: http.Header{
			"Proxy-Authorization": []string{"Bearer " + cfg.AuthToken},
		},
		TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	resp, err := client.Get(origin.URL + "/ct/v1/get-entries")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "fetched /ct/v1/get-entries") {
		t.Errorf("unexpected body through proxy: %q", string(body))
	}

	if s.total.Load() != 1 {
		t.Errorf("proxy handled %d tunnels, want 1", s.total.Load())
	}

	if s.bytesDown.Load() == 0 || s.bytesUp.Load() == 0 {
		t.Errorf("byte counters not updated: up=%d down=%d", s.bytesUp.Load(), s.bytesDown.Load())
	}

	// Without the token the same transport must fail, proving auth is enforced
	// on the real path and not just on hand-built requests.
	noAuth := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: transport.TLSClientConfig,
	}
	if _, err := (&http.Client{Transport: noAuth, Timeout: 5 * time.Second}).Get(origin.URL + "/"); err == nil {
		t.Error("request without a token succeeded through the proxy")
	}
}
