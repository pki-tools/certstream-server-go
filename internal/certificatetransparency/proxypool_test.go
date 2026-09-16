package certificatetransparency

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// resetProxyPool clears the memoised pool so each test can configure its own.
func resetProxyPool(t *testing.T, proxies []config.ProxyConfig) {
	t.Helper()

	config.AppConfig.General.Proxies = proxies
	proxyPool.entries = nil
	proxyPool.once = sync.Once{}

	t.Cleanup(func() {
		config.AppConfig.General.Proxies = nil
		proxyPool.entries = nil
		proxyPool.once = sync.Once{}
	})
}

func TestNoProxiesMeansDirect(t *testing.T) {
	resetProxyPool(t, nil)

	if got := proxyForLog("ct.example.com/log"); got != nil {
		t.Errorf("expected direct fetching, got proxy %q", got.name)
	}

	tr := &http.Transport{}
	applyProxy(tr, "ct.example.com/log")

	if tr.Proxy != nil {
		t.Error("transport should be left alone when no proxies are configured")
	}
}

// Assignment must be stable: a log's rate-limit bucket is per source address,
// so it should keep the same egress across restarts.
func TestAssignmentIsStableAndDistributed(t *testing.T) {
	resetProxyPool(t, []config.ProxyConfig{
		{Name: "a", URL: "https://198.51.100.1:8443", Token: "t"},
		{Name: "b", URL: "https://198.51.100.2:8443", Token: "t"},
		{Name: "c", URL: "https://198.51.100.3:8443", Token: "t"},
	})

	first := ProxyAssignment("ct.example.com/log1")
	for i := 0; i < 20; i++ {
		if got := ProxyAssignment("ct.example.com/log1"); got != first {
			t.Fatalf("assignment changed between calls: %q then %q", first, got)
		}
	}

	// The same log addressed with a scheme or trailing slash must land on the
	// same proxy, since those normalise to one log.
	for _, variant := range []string{
		"https://ct.example.com/log1", "ct.example.com/log1/", "https://ct.example.com/log1/",
	} {
		if got := ProxyAssignment(variant); got != first {
			t.Errorf("variant %q assigned to %q, want %q", variant, got, first)
		}
	}

	// Across many logs, every proxy should get used.
	seen := make(map[string]int)
	for i := 0; i < 300; i++ {
		seen[ProxyAssignment(logURLf(i))]++
	}

	if len(seen) != 3 {
		t.Errorf("used %d of 3 proxies: %v", len(seen), seen)
	}

	for name, n := range seen {
		if n == 0 {
			t.Errorf("proxy %q never used", name)
		}
	}
}

func TestApplyProxySetsTokenHeader(t *testing.T) {
	resetProxyPool(t, []config.ProxyConfig{
		{Name: "only", URL: "https://198.51.100.1:8443", Token: "secret-token"},
	})

	tr := &http.Transport{}
	applyProxy(tr, "ct.example.com/log")

	if tr.Proxy == nil {
		t.Fatal("transport was not pointed at the proxy")
	}

	u, err := tr.Proxy(&http.Request{URL: mustURL(t, "https://ct.example.com/x")})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || u.Host != "198.51.100.1:8443" {
		t.Errorf("proxy URL = %v, want 198.51.100.1:8443", u)
	}

	got := tr.ProxyConnectHeader.Get("Proxy-Authorization")
	if got != "Bearer secret-token" {
		t.Errorf("Proxy-Authorization = %q, want the bearer token", got)
	}
}

// Malformed entries must be skipped rather than taking the server down.
func TestInvalidProxiesAreSkipped(t *testing.T) {
	resetProxyPool(t, []config.ProxyConfig{
		{Name: "good", URL: "https://198.51.100.1:8443", Token: "t"},
		{Name: "no-scheme", URL: "198.51.100.2:8443", Token: "t"},
		{Name: "ftp", URL: "ftp://198.51.100.3", Token: "t"},
	})

	if names := ProxyNames(); len(names) != 1 || names[0] != "good" {
		t.Errorf("configured proxies = %v, want just [good]", names)
	}
}

func logURLf(i int) string {
	return fmt.Sprintf("ct%d.example.com/log", i)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	return u
}
