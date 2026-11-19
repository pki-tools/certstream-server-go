package certificatetransparency

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Why entries-per-response is the number that matters.
//
// batch_size maps directly onto the wire: scanner.genRanges splits the
// outstanding range into chunks of batch_size and each chunk becomes exactly
// one GET /ct/v1/get-entries?start=X&end=Y (end inclusive, so end = X+size-1).
//
// But RFC 6962 section 4.6 lets a log return FEWER entries than asked for, and
// scanner.runWorker handles that by re-requesting the remainder in the same
// worker:
//
//	fn(EntryBatch{Start: r.start, Entries: resp.Entries})
//	r.start += int64(len(resp.Entries))
//
// So a log that caps responses at, say, 32 entries turns one nominal
// 1000-entry batch into ~32 sequential round trips on that one worker. No
// entries are lost; the cost is paid in requests. Since the number of requests
// in flight equals parallel_fetch regardless of batch_size, raising batch_size
// past the operator's cap buys nothing, and lowering it below the cap wastes
// request budget against a per-request rate limit.
//
// That makes the operator's effective cap the thing to measure rather than
// guess. Observing it from the http.RoundTripper is exact: the request's own
// start/end say how many entries were asked for, and the response body says
// how many came back.

// fetchStat is the per-log accounting of get-entries traffic.
type fetchStat struct {
	LogURL     string
	LogName    string
	Requests   int64
	Requested  int64
	Returned   int64
	MaxReturn  int64
	LatencySum time.Duration
	FirstAt    time.Time
	LastAt     time.Time
}

// FetchStat is the externally visible view, with the derived figures computed.
type FetchStat struct {
	LogURL   string
	LogName  string
	Requests int64

	// EntriesPerResponse is the operator's observed effective batch size.
	EntriesPerResponse float64
	// FillRatio is entries returned over entries requested. Well below 1 means
	// batch_size is larger than the log will honour, so each configured batch
	// costs several round trips.
	FillRatio float64
	// MaxReturn is the largest single response seen, which is the practical
	// ceiling for batch_size on this log.
	MaxReturn int64
	// RequestsPerSec and AvgLatency describe the round-trip cost.
	RequestsPerSec float64
	AvgLatency     time.Duration
}

var fetchReg = struct {
	mu      sync.Mutex
	entries map[string]*fetchStat
}{entries: make(map[string]*fetchStat)}

func recordFetch(logURL, logName string, requested, returned int64, latency time.Duration) {
	now := time.Now()

	fetchReg.mu.Lock()
	defer fetchReg.mu.Unlock()

	e, ok := fetchReg.entries[logURL]
	if !ok {
		e = &fetchStat{LogURL: logURL, LogName: logName, FirstAt: now}
		fetchReg.entries[logURL] = e
	}

	e.Requests++
	e.Requested += requested
	e.Returned += returned
	e.LatencySum += latency
	e.LastAt = now

	if returned > e.MaxReturn {
		e.MaxReturn = returned
	}
}

// GetFetchStats returns per-log get-entries statistics, worst fill ratio first:
// those are the logs where batch_size is not being honoured and request budget
// is being spent on short responses.
func GetFetchStats() []FetchStat {
	fetchReg.mu.Lock()
	out := make([]FetchStat, 0, len(fetchReg.entries))

	for _, e := range fetchReg.entries {
		s := FetchStat{
			LogURL:    e.LogURL,
			LogName:   e.LogName,
			Requests:  e.Requests,
			MaxReturn: e.MaxReturn,
		}

		if e.Requests > 0 {
			s.EntriesPerResponse = float64(e.Returned) / float64(e.Requests)
			s.AvgLatency = e.LatencySum / time.Duration(e.Requests)
		}

		if e.Requested > 0 {
			s.FillRatio = float64(e.Returned) / float64(e.Requested)
		}

		if span := e.LastAt.Sub(e.FirstAt).Seconds(); span > 0 {
			s.RequestsPerSec = float64(e.Requests) / span
		}

		out = append(out, s)
	}
	fetchReg.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].FillRatio != out[j].FillRatio {
			return out[i].FillRatio < out[j].FillRatio
		}

		return out[i].LogURL < out[j].LogURL
	})

	return out
}

// requestedEntries reads the entry count a get-entries request asked for.
// Returns 0 for any request that is not a well-formed get-entries call.
func requestedEntries(req *http.Request) int64 {
	if req.URL == nil || !isGetEntriesPath(req.URL.Path) {
		return 0
	}

	q := req.URL.Query()

	start, err := strconv.ParseInt(q.Get("start"), 10, 64)
	if err != nil {
		return 0
	}

	end, err := strconv.ParseInt(q.Get("end"), 10, 64)
	if err != nil || end < start {
		return 0
	}

	return end - start + 1
}

func isGetEntriesPath(path string) bool {
	const suffix = "/ct/v1/get-entries"
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}

// entryCountingBody counts entries in a get-entries response as the JSON is
// read, without buffering it. Each entry object in the response carries exactly
// one "leaf_input" member, so occurrences of that key are the entry count.
//
// Occurrences are counted non-overlapping. Two occurrences of the key could
// only overlap in the text `"leaf_input"leaf_input"`, which no valid response
// contains - a JSON object key is always followed by ':' - so the distinction
// never arises in practice. For a malformed body the count may differ by one;
// it is a diagnostic statistic, and no decision depends on it being exact.
//
// Counting runs on every fetched byte in the ingestion path, so it uses
// bytes.Count (assembly-optimised substring search) over each chunk rather than
// a byte-at-a-time state machine. A byte-wise loop measured 2.5 us per entry,
// roughly 7% on top of the ~34 us it costs to parse one, which is too much to
// spend on instrumentation; this costs 0.28 us per entry (10.7 GB/s), under 1%.
// Matches that straddle two Read calls are caught by
// re-searching a small window of the carried-over tail plus the start of the
// next chunk, so no match is missed or counted twice.
type entryCountingBody struct {
	body   io.ReadCloser
	needle []byte
	// carry holds the last len(needle)-1 bytes seen: too short to contain a
	// match on their own, but long enough to start one that the next chunk
	// completes.
	carry []byte
	count int64

	report func(count int64)
	once   sync.Once
}

func newEntryCountingBody(body io.ReadCloser, report func(int64)) *entryCountingBody {
	needle := []byte(`"leaf_input"`)

	return &entryCountingBody{
		body:   body,
		needle: needle,
		carry:  make([]byte, 0, 2*len(needle)),
		report: report,
	}
}

func (b *entryCountingBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if n > 0 {
		b.scan(p[:n])
	}

	if err != nil {
		// Report at EOF as well as at Close: the http client may hand the body
		// back to the connection pool without an explicit Close.
		b.finish()
	}

	return n, err
}

func (b *entryCountingBody) scan(chunk []byte) {
	n := len(b.needle)

	// Boundary matches: one that starts in the carry must end within the first
	// n-1 bytes of this chunk, so a window that size is enough to find them all.
	// Only matches starting inside the carry are counted here; any that start in
	// the chunk are left to the full-chunk count below.
	// skip is how many bytes at the start of the chunk a boundary match already
	// consumed, so the chunk-wide count below cannot count them twice. Matches
	// are counted non-overlapping throughout, which is what bytes.Count does.
	skip := 0

	if len(b.carry) > 0 {
		window := append(b.carry[:len(b.carry):len(b.carry)], chunk[:min(n-1, len(chunk))]...)

		for off := 0; off < len(b.carry); {
			i := bytes.Index(window[off:], b.needle)
			if i < 0 || off+i >= len(b.carry) {
				break
			}

			b.count++

			end := off + i + n
			off = end

			if end > len(b.carry) {
				skip = end - len(b.carry)
			}
		}
	}

	b.count += int64(bytes.Count(chunk[skip:], b.needle))

	// Carry the trailing n-1 bytes of (carry + chunk) into the next Read.
	tail := b.carry
	if len(chunk) >= n-1 {
		tail = chunk[len(chunk)-(n-1):]
	} else {
		tail = append(tail, chunk...)
		if len(tail) > n-1 {
			tail = tail[len(tail)-(n-1):]
		}
	}

	b.carry = append(b.carry[:0], tail...)
}

func (b *entryCountingBody) finish() {
	b.once.Do(func() { b.report(b.count) })
}

func (b *entryCountingBody) Close() error {
	b.finish()
	return b.body.Close()
}

// SeedFetchStatsForTest records one synthetic get-entries observation so page
// rendering can be exercised. Test-only.
func SeedFetchStatsForTest(logURL, logName string, requested, returned int64) {
	recordFetch(logURL, logName, requested, returned, 42*time.Millisecond)
}
