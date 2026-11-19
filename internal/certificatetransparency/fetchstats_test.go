package certificatetransparency

import (
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestedEntries(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"full batch", "https://ct.example.com/log/ct/v1/get-entries?start=0&end=999", 1000},
		{"single entry", "https://ct.example.com/log/ct/v1/get-entries?start=5&end=5", 1},
		{"not get-entries", "https://ct.example.com/log/ct/v1/get-sth", 0},
		{"get-entries substring only", "https://ct.example.com/log/ct/v1/get-entries-extra?start=0&end=9", 0},
		{"missing params", "https://ct.example.com/log/ct/v1/get-entries", 0},
		{"reversed range", "https://ct.example.com/log/ct/v1/get-entries?start=9&end=0", 0},
		{"garbage start", "https://ct.example.com/log/ct/v1/get-entries?start=x&end=9", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}

			if got := requestedEntries(&http.Request{URL: u}); got != tc.want {
				t.Errorf("requestedEntries(%s) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

// TestEntryCountingBodySplitReads is the important one: the counter must find
// the key even when it straddles Read boundaries, which is the normal case for
// a megabyte-sized response arriving over TLS.
func TestEntryCountingBodySplitReads(t *testing.T) {
	body := `{"entries":[{"leaf_input":"AAA","extra_data":"BBB"},` +
		`{"leaf_input":"CCC","extra_data":"DDD"},` +
		`{"leaf_input":"EEE","extra_data":"FFF"}]}`

	// One byte at a time is the worst case for a rolling match.
	for _, chunk := range []int{1, 2, 3, 7, 11, 12, 13, 64, len(body)} {
		var got int64

		b := newEntryCountingBody(io.NopCloser(strings.NewReader(body)), func(n int64) { got = n })

		buf := make([]byte, chunk)
		for {
			_, err := b.Read(buf)
			if err != nil {
				break
			}
		}

		if err := b.Close(); err != nil {
			t.Fatal(err)
		}

		if got != 3 {
			t.Errorf("chunk size %d: counted %d entries, want 3", chunk, got)
		}
	}
}

// TestEntryCountingBodyReportsOnce guards against double counting: the http
// client may both read to EOF and Close the body.
func TestEntryCountingBodyReportsOnce(t *testing.T) {
	var reports int

	b := newEntryCountingBody(io.NopCloser(strings.NewReader(`{"leaf_input":"A"}`)), func(int64) { reports++ })

	if _, err := io.ReadAll(b); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	if reports != 1 {
		t.Errorf("report called %d times, want 1", reports)
	}
}

// TestEntryCountingBodyFalsePositives pins what the matcher does and does not
// treat as an entry.
//
// It matches the quoted token `"leaf_input"` wherever it appears, so in
// principle a *value* spelling that exact string would also count. That cannot
// happen in a get-entries response: the only string values are leaf_input and
// extra_data, both standard base64 (RFC 6962 section 4.6), and '_' is not in
// the standard base64 alphabet - it belongs to base64url. The last case below
// records that behaviour deliberately rather than pretending it is impossible.
func TestEntryCountingBodyFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int64
	}{
		{"empty entry list", `{"entries":[]}`, 0},
		{"key without quotes", `{"entries":[{leaf_input:1}]}`, 0},
		{"partial key", `{"leaf_inpu":"x"}`, 0},
		{"doubled quote before key", `{""leaf_input":"x"}`, 1},
		// Counts, by design; unreachable with real base64 values (see above).
		{"key name as a value", `{"extra_data":"leaf_input"}`, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got int64

			b := newEntryCountingBody(io.NopCloser(strings.NewReader(tc.body)), func(n int64) { got = n })
			if _, err := io.ReadAll(b); err != nil {
				t.Fatal(err)
			}

			if got != tc.want {
				t.Errorf("counted %d, want %d for %s", got, tc.want, tc.body)
			}
		})
	}
}

// TestFetchStatsShortResponse exercises the whole path against a real server
// that behaves like a rate-limited operator: it is asked for 1000 entries and
// returns 32. That is the case the statistics exist to expose.
func TestFetchStatsShortResponse(t *testing.T) {
	resetFetchStats()

	const cap32 = 32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sb strings.Builder
		sb.WriteString(`{"entries":[`)

		for i := 0; i < cap32; i++ {
			if i > 0 {
				sb.WriteString(",")
			}

			sb.WriteString(`{"leaf_input":"AAAA","extra_data":"BBBB"}`)
		}

		sb.WriteString(`]}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer srv.Close()

	client := NewRateLimitedClient(srv.URL, "short-log", 0)

	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + "/ct/v1/get-entries?start=0&end=999")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}

		resp.Body.Close()
	}

	stats := GetFetchStats()
	if len(stats) != 1 {
		t.Fatalf("got %d log stats, want 1", len(stats))
	}

	s := stats[0]
	if s.Requests != 3 {
		t.Errorf("Requests = %d, want 3", s.Requests)
	}

	if s.EntriesPerResponse != cap32 {
		t.Errorf("EntriesPerResponse = %v, want %d", s.EntriesPerResponse, cap32)
	}

	if s.MaxReturn != cap32 {
		t.Errorf("MaxReturn = %d, want %d", s.MaxReturn, cap32)
	}

	// 32 of 1000 requested: this is the signal that batch_size is not honoured.
	if want := float64(cap32) / 1000; s.FillRatio != want {
		t.Errorf("FillRatio = %v, want %v", s.FillRatio, want)
	}

	if s.AvgLatency <= 0 {
		t.Errorf("AvgLatency = %v, want a positive duration", s.AvgLatency)
	}
}

// TestFetchStatsIgnoresNonEntryCalls makes sure STH polling does not pollute
// the per-log batch figures.
func TestFetchStatsIgnoresNonEntryCalls(t *testing.T) {
	resetFetchStats()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tree_size":12345}`))
	}))
	defer srv.Close()

	client := NewRateLimitedClient(srv.URL, "sth-log", 0)

	resp, err := client.Get(srv.URL + "/ct/v1/get-sth")
	if err != nil {
		t.Fatal(err)
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if stats := GetFetchStats(); len(stats) != 0 {
		t.Errorf("get-sth recorded %d fetch stats, want 0", len(stats))
	}
}

func resetFetchStats() {
	fetchReg.mu.Lock()
	fetchReg.entries = make(map[string]*fetchStat)
	fetchReg.mu.Unlock()
}

// TestEntryCountingBodyRandomChunking cross-checks the boundary handling
// against strings.Count over randomly chunked input. The carry/window logic is
// the easiest thing here to get subtly wrong, so it is checked over many
// random chunkings rather than on hand-picked cases.
//
// The fragments deliberately split the key across boundaries, but never
// produce two overlapping keys (`"leaf_input"leaf_input"`), which valid JSON
// cannot contain and which the counter does not promise to resolve - see the
// note on entryCountingBody.
func TestEntryCountingBodyRandomChunking(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	// Fragments chosen so partial needles straddle boundaries often.
	frags := []string{`"leaf_input"`, `"leaf_inpu`, `t":`, `{`, `}`, `,`, `"x"`, `:`, `AAAA`, `"extra_data"`}

	for iter := 0; iter < 400; iter++ {
		var sb strings.Builder
		for i := 0; i < rng.Intn(40); i++ {
			sb.WriteString(frags[rng.Intn(len(frags))])
		}

		body := sb.String()
		want := int64(strings.Count(body, `"leaf_input"`))

		var got int64

		b := newEntryCountingBody(io.NopCloser(strings.NewReader(body)), func(n int64) { got = n })

		// Read in random-sized pieces.
		for {
			size := 1 + rng.Intn(13)
			buf := make([]byte, size)

			if _, err := b.Read(buf); err != nil {
				break
			}
		}

		b.Close()

		if got != want {
			t.Fatalf("iter %d: counted %d, want %d for %q", iter, got, want, body)
		}
	}
}
