package certificatetransparency

import (
	"hash/fnv"
	"log"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// Egress fetching can be spread across certstream-proxy instances running on
// other addresses. Each log is pinned to one proxy rather than round-robining
// per request: a log's rate-limit bucket is per source address, so spraying its
// requests across several egress points would be counterproductive, and pinning
// also keeps connections reusable.

type proxyEntry struct {
	name  string
	url   *url.URL
	token string
}

var proxyPool struct {
	once    sync.Once
	entries []proxyEntry
}

// initProxyPool parses the configured proxies once. Invalid entries are skipped
// with a warning rather than stopping the server, since losing an egress point
// should degrade throughput, not halt ingestion.
func initProxyPool() {
	proxyPool.once.Do(func() {
		for _, p := range config.AppConfig.General.Proxies {
			u, err := url.Parse(p.URL)
			if err != nil || u.Host == "" {
				log.Printf("Ignoring invalid proxy URL %q: %v\n", p.URL, err)
				continue
			}

			if u.Scheme != "http" && u.Scheme != "https" {
				log.Printf("Ignoring proxy %q: scheme must be http or https\n", p.URL)
				continue
			}

			name := p.Name
			if name == "" {
				name = u.Host
			}

			proxyPool.entries = append(proxyPool.entries, proxyEntry{
				name: name, url: u, token: p.Token,
			})
		}

		// Sorted so assignment is stable across restarts regardless of map or
		// config ordering quirks.
		sort.Slice(proxyPool.entries, func(i, j int) bool {
			return proxyPool.entries[i].name < proxyPool.entries[j].name
		})

		if len(proxyPool.entries) > 0 {
			log.Printf("Egress proxies configured: %d\n", len(proxyPool.entries))
		}
	})
}

// proxyForLog returns the proxy a given log should use, or nil for direct
// fetching. Assignment is a stable hash of the log URL, so a log keeps the same
// egress address across restarts.
func proxyForLog(logURL string) *proxyEntry {
	initProxyPool()

	if len(proxyPool.entries) == 0 {
		return nil
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(normalizeCtlogURL(logURL)))

	return &proxyPool.entries[int(h.Sum32()%uint32(len(proxyPool.entries)))]
}

// ProxyAssignment names the proxy a log fetches through, empty when direct.
func ProxyAssignment(logURL string) string {
	if p := proxyForLog(logURL); p != nil {
		return p.name
	}

	return ""
}

// ProxyNames lists the configured proxies, for display.
func ProxyNames() []string {
	initProxyPool()

	out := make([]string, 0, len(proxyPool.entries))
	for _, p := range proxyPool.entries {
		out = append(out, p.name)
	}

	return out
}

// applyProxy points a transport at this log's assigned proxy, if any, and
// attaches the token the proxy requires.
func applyProxy(transport *http.Transport, logURL string) {
	p := proxyForLog(logURL)
	if p == nil {
		return
	}

	transport.Proxy = http.ProxyURL(p.url)

	if p.token != "" {
		transport.ProxyConnectHeader = http.Header{
			"Proxy-Authorization": []string{"Bearer " + p.token},
		}
	}
}
