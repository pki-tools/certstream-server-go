package certificatetransparency

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/scanner"
)

// fakeLog is a scanner.LogClient serving a fixed tree. Like many real logs it
// returns at most maxPerResponse entries per get-entries call however many are
// requested, which exercises the fetcher's re-request loop.
type fakeLog struct {
	entries        []ct.LeafEntry
	maxPerResponse int64

	mu       sync.Mutex
	requests int
}

func (f *fakeLog) BaseURI() string { return "https://ct.example.com/fake" }

func (f *fakeLog) GetSTH(context.Context) (*ct.SignedTreeHead, error) {
	return &ct.SignedTreeHead{TreeSize: uint64(len(f.entries))}, nil
}

func (f *fakeLog) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()

	if end-start+1 > f.maxPerResponse {
		end = start + f.maxPerResponse - 1
	}

	if last := int64(len(f.entries)) - 1; end > last {
		end = last
	}

	return &ct.GetEntriesResponse{Entries: f.entries[start : end+1]}, nil
}

// newFakeLog builds a tree alternating certificates and precertificates.
func newFakeLog(t *testing.T, n int, maxPerResponse int64) *fakeLog {
	t.Helper()

	leaf := makeDER(t, "www.example.com", []string{"www.example.com"}, false)
	inter := makeDER(t, "Example Intermediate", nil, true)

	x509Entry := referenceLeafEntry(t, false, nil, leaf, inter)
	precertEntry := referenceLeafEntry(t, true, nil, leaf, inter)

	f := &fakeLog{maxPerResponse: maxPerResponse}
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			f.entries = append(f.entries, *x509Entry)
		} else {
			f.entries = append(f.entries, *precertEntry)
		}
	}

	return f
}

// TestScanEntriesDeliversEveryEntryOnce runs the real ct-go Fetcher through
// scanEntries against a log that caps its responses, for several worker
// counts. Every index must arrive exactly once with the right entry type: no
// entry lost to short responses, none duplicated by concurrent workers.
func TestScanEntriesDeliversEveryEntryOnce(t *testing.T) {
	const n = 300

	for _, workers := range []int{1, 2, 4} {
		t.Run("workers="+itoa64(int64(workers)), func(t *testing.T) {
			fl := newFakeLog(t, n, 7)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			w := &worker{
				name:         "fake",
				operatorName: "Example",
				ctURL:        fl.BaseURI(),
				entryChan:    make(chan models.Entry, n),
				ctx:          ctx,
			}

			err := w.scanEntries(ctx, ctx, fl, scanner.FetcherOptions{
				BatchSize:     32,
				ParallelFetch: 3,
				StartIndex:    0,
				Continuous:    false,
			}, workers, 16)
			if err != nil {
				t.Fatalf("scanEntries: %v", err)
			}

			close(w.entryChan)

			seen := make(map[uint64]string, n)
			for e := range w.entryChan {
				if prev, dup := seen[e.Data.CertIndex]; dup {
					t.Fatalf("index %d delivered twice (%s, %s)", e.Data.CertIndex, prev, e.Data.UpdateType)
				}

				seen[e.Data.CertIndex] = e.Data.UpdateType
			}

			if len(seen) != n {
				t.Fatalf("delivered %d distinct entries, want %d", len(seen), n)
			}

			for i := uint64(0); i < n; i++ {
				want := "X509LogEntry"
				if i%2 == 1 {
					want = "PrecertLogEntry"
				}

				if got := seen[i]; got != want {
					t.Errorf("index %d: type %q, want %q", i, got, want)
				}
			}

			// 300 entries at 7 per response is at least 43 requests: the
			// re-request path really was exercised.
			if fl.requests < n/7 {
				t.Errorf("only %d requests made; short responses were not exercised", fl.requests)
			}
		})
	}
}

// TestScanEntriesShutdownDoesNotHang cancels the worker's lifetime while
// nothing is draining its output. The scanner's own push into its queue was not
// cancellable; this must return promptly instead of blocking forever.
func TestScanEntriesShutdownDoesNotHang(t *testing.T) {
	fl := newFakeLog(t, 500, 50)

	ctx, cancel := context.WithCancel(context.Background())

	w := &worker{
		name:         "fake",
		operatorName: "Example",
		ctURL:        fl.BaseURI(),
		entryChan:    make(chan models.Entry), // unbuffered and never read
		ctx:          ctx,
	}

	done := make(chan error, 1)

	go func() {
		done <- w.scanEntries(ctx, ctx, fl, scanner.FetcherOptions{
			BatchSize:     100,
			ParallelFetch: 2,
			Continuous:    true,
		}, 2, 0)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scanEntries did not return after its context was cancelled")
	}
}

// TestFetcherRunReturnsNilWhenCancelled pins the behaviour the restart fix
// depends on. runWorker used to recognise a planned catch-up restart only when
// the scan returned an error, but scanner.Fetcher.Run returns nil when its
// context is cancelled, so the restart was never recognised. If a future
// certificate-transparency-go returns ctx.Err() instead, this fails, and the
// restart check in runWorker should be revisited.
func TestFetcherRunReturnsNilWhenCancelled(t *testing.T) {
	fl := newFakeLog(t, 500, 50)

	ctx := context.Background()
	fetchCtx, cancelFetch := context.WithCancel(ctx)

	w := &worker{
		name:         "fake",
		operatorName: "Example",
		ctURL:        fl.BaseURI(),
		entryChan:    make(chan models.Entry, 1000),
		ctx:          ctx,
	}

	done := make(chan error, 1)

	go func() {
		done <- w.scanEntries(ctx, fetchCtx, fl, scanner.FetcherOptions{
			BatchSize:     50,
			ParallelFetch: 2,
			Continuous:    true,
		}, 2, 16)
	}()

	time.Sleep(100 * time.Millisecond)
	cancelFetch()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scanEntries returned %v on cancellation; runWorker's restart check assumes nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scanEntries did not return after the fetch context was cancelled")
	}

	if fetchCtx.Err() == nil {
		t.Fatal("precondition: fetch context should be cancelled")
	}
}

// TestResumePosition covers the decision that stops a restarting worker from
// re-fetching everything since it first started.
func TestResumePosition(t *testing.T) {
	cases := []struct {
		name                    string
		current, recorded, want uint64
		recovery                bool
	}{
		{"restart after progress resumes from progress", 1_000, 250_000, 250_000, true},
		{"first start with nothing recorded stays put", 0, 0, 0, true},
		{"saved index ahead of recorded is kept", 500_000, 400_000, 500_000, true},
		{"recovery off leaves position for the head jump", 1_000, 250_000, 1_000, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resumePosition(tc.current, tc.recorded, tc.recovery); got != tc.want {
				t.Errorf("resumePosition(%d, %d, %v) = %d, want %d",
					tc.current, tc.recorded, tc.recovery, got, tc.want)
			}
		})
	}
}
