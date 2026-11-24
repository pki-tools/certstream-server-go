package certificatetransparency

import (
	"compress/gzip"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// Rate limiting is invisible from above: certificate-transparency-go retries 429
// responses inside jsonclient (honouring Retry-After) and again inside
// scanner.fetcher's own backoff loop, which retries indefinitely and logs only at
// klog verbosity 2. A throttled log therefore just silently stalls.
//
// Instrumenting at the http.RoundTripper level sits below both retry layers, so
// every 429 is observed no matter how the library handles it afterwards.

// rateLimitNoteInterval throttles how often a rate-limited log writes to the
// shared error ring. Without it a single throttled log would evict every other
// error from the 500-entry window. Exact counts are kept separately.
const rateLimitNoteInterval = 30 * time.Second

// RateLimitStat is the per-log rate-limiting tally shown on /errors.
type RateLimitStat struct {
	LogURL     string
	LogName    string
	Count      int64
	LastAt     time.Time
	LastStatus int
	RetryAfter string
}

type rateLimitEntry struct {
	stat     RateLimitStat
	lastNote time.Time
}

var rateLimitReg = struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	total   int64
}{entries: make(map[string]*rateLimitEntry)}

// rateLimitTransport records 429/503 responses for one CT log.
type rateLimitTransport struct {
	base    http.RoundTripper
	logURL  string
	logName string
	// noCompression is set when scanner.http_compression is false. The base
	// transport then neither requests nor transparently decodes gzip.
	noCompression bool
}

// HTTPCompressionEnabled reports whether log responses are requested gzipped.
func HTTPCompressionEnabled() bool { return httpCompressionEnabled() }

// httpCompressionEnabled reports scanner.http_compression, defaulting to on.
func httpCompressionEnabled() bool {
	p := config.AppConfig.General.Scanner.HTTPCompression
	return p == nil || *p
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Captured before the call: the range asked for is what the response's entry
	// count has to be compared against. See fetchstats.go.
	requested := requestedEntries(req)

	if t.noCompression {
		// With compression disabled the transport sends no Accept-Encoding at
		// all, which RFC 9110 reads as "any coding is acceptable". Ask for
		// identity explicitly. RoundTrippers must not modify the caller's
		// request, hence the clone.
		req = req.Clone(req.Context())
		req.Header.Set("Accept-Encoding", "identity")
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	latency := time.Since(start)

	if err != nil || resp == nil {
		return resp, err
	}

	if t.noCompression && resp.Body != nil && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		// A server that gzips regardless. With compression disabled the base
		// transport passes such a body through still encoded, which would
		// break JSON and tile decoding, so decode it here instead. Done before
		// any other wrapping so the entry counter below sees plain JSON.
		if gz, gzErr := gzip.NewReader(resp.Body); gzErr == nil {
			resp.Body = &gzipBody{Reader: gz, underlying: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		recordRateLimit(t.logURL, t.logName, resp.StatusCode, resp.Header.Get("Retry-After"))
	}

	if requested > 0 && resp.StatusCode == http.StatusOK && resp.Body != nil {
		logURL, logName := t.logURL, t.logName
		resp.Body = newEntryCountingBody(resp.Body, func(returned int64) {
			recordFetch(logURL, logName, requested, returned, latency)
		})
	}

	return resp, err
}

// newRateLimitTransport builds the shared base transport for CT fetches.
//
// http.DefaultTransport caps idle connections at 2 per host, so with
// parallel_fetch above 2 the surplus connections are torn down and re-handshaked
// on every batch. Raising the per-host idle pool lets parallel fetches actually
// reuse connections.
func newRateLimitTransport(logURL, logName string) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.MaxIdleConns = 200
	base.MaxIdleConnsPerHost = 20
	base.IdleConnTimeout = 90 * time.Second

	// scanner.http_compression: false trades bandwidth for the CPU spent
	// decompressing responses. See rateLimitTransport.RoundTrip.
	noCompression := !httpCompressionEnabled()
	base.DisableCompression = noCompression

	// Route this log's fetches through its assigned egress proxy, when any are
	// configured. Done on the base transport so rate-limit accounting above still
	// sees every response.
	applyProxy(base, logURL)

	return &rateLimitTransport{base: base, logURL: logURL, logName: logName, noCompression: noCompression}
}

// gzipBody decodes a gzip response body and closes both layers on Close.
type gzipBody struct {
	*gzip.Reader
	underlying io.ReadCloser
}

func (g *gzipBody) Close() error {
	_ = g.Reader.Close()
	return g.underlying.Close()
}

// NewRateLimitedClient returns an HTTP client that reports rate-limit responses
// for the given log to the error log and the per-log tally.
func NewRateLimitedClient(logURL, logName string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: newRateLimitTransport(logURL, logName),
	}
}

// recordRateLimit tallies a rate-limit response and, at most once per
// rateLimitNoteInterval per log, writes a note into the error ring.
func recordRateLimit(logURL, logName string, status int, retryAfter string) {
	now := time.Now()

	rateLimitReg.mu.Lock()
	e, ok := rateLimitReg.entries[logURL]
	if !ok {
		e = &rateLimitEntry{stat: RateLimitStat{LogURL: logURL, LogName: logName}}
		rateLimitReg.entries[logURL] = e
	}

	e.stat.Count++
	e.stat.LastAt = now
	e.stat.LastStatus = status
	e.stat.RetryAfter = retryAfter
	rateLimitReg.total++

	count := e.stat.Count
	shouldNote := now.Sub(e.lastNote) >= rateLimitNoteInterval
	if shouldNote {
		e.lastNote = now
	}
	rateLimitReg.mu.Unlock()

	if !shouldNote {
		return
	}

	msg := http.StatusText(status) + " from log"
	if retryAfter != "" {
		msg += " (Retry-After: " + retryAfter + ")"
	}
	msg += " — " + itoa64(count) + " rate-limited responses so far; the client is backing off and falling behind"

	RecordError(logURL, logName, ErrCatRateLimit, msg)
}

// GetRateLimitStats returns per-log rate-limit tallies, worst first.
func GetRateLimitStats() []RateLimitStat {
	rateLimitReg.mu.Lock()
	out := make([]RateLimitStat, 0, len(rateLimitReg.entries))
	for _, e := range rateLimitReg.entries {
		out = append(out, e.stat)
	}
	rateLimitReg.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })

	return out
}

// TotalRateLimitHits returns the total number of rate-limit responses seen.
func TotalRateLimitHits() int64 {
	rateLimitReg.mu.Lock()
	defer rateLimitReg.mu.Unlock()
	return rateLimitReg.total
}

// Pipeline saturation. If the entry channel sits near capacity the bottleneck is
// downstream processing (CPU, broadcast, slow clients) rather than fetching —
// which distinguishes "needs more resources" from "is being rate-limited".
var (
	certChanDepth atomic.Int64
	certChanCap   atomic.Int64
)

// recordStartPosition publishes a worker's starting index so the rest of the
// system sees it before the first certificate is processed. metrics.Inc is
// otherwise the only writer, and it does not run until an entry completes the
// pipeline, leaving the log recorded at index 0 until then.
func recordStartPosition(normURL string, index uint64) {
	metrics.SetCTIndex(normURL, index)
	// The index jump is a reposition, not throughput; don't let it register as one.
	resetRateBaseline(normURL, index)
}

// GetPipelineDepth returns the current and maximum depth of the entry channel.
func GetPipelineDepth() (depth, capacity int64) {
	return certChanDepth.Load(), certChanCap.Load()
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}

	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	return string(buf[i:])
}
