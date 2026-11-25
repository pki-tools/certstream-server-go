package certificatetransparency

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/scanner"
)

func TestWaitWhileHeld(t *testing.T) {
	ResetLogControlsForTest()
	defer ResetLogControlsForTest()

	const url = "ct.example.com/held"

	if !waitWhileHeld(context.Background(), url) {
		t.Fatal("a running log must not wait")
	}

	if err := SetLogState(url, LogPaused); err != nil {
		t.Fatal(err)
	}

	released := make(chan bool, 1)
	go func() { released <- waitWhileHeld(context.Background(), url) }()

	select {
	case <-released:
		t.Fatal("waitWhileHeld returned while the log was paused")
	case <-time.After(50 * time.Millisecond):
	}

	// Paused -> stopped is still held.
	_ = SetLogState(url, LogStopped)

	select {
	case <-released:
		t.Fatal("waitWhileHeld returned while the log was stopped")
	case <-time.After(50 * time.Millisecond):
	}

	_ = SetLogState(url, LogRunning)

	select {
	case ok := <-released:
		if !ok {
			t.Fatal("waitWhileHeld reported cancellation on resume")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitWhileHeld did not return on resume")
	}

	// Cancellation releases a held waiter with false.
	_ = SetLogState(url, LogPaused)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { released <- waitWhileHeld(ctx, url) }()

	cancel()

	select {
	case ok := <-released:
		if ok {
			t.Fatal("waitWhileHeld should report false when its context ends")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitWhileHeld did not return on cancellation")
	}
}

func TestHeldContextCancelsOnPause(t *testing.T) {
	ResetLogControlsForTest()
	defer ResetLogControlsForTest()

	const url = "ct.example.com/heldctx"

	hctx, cancel := heldContext(context.Background(), url)
	defer cancel()

	select {
	case <-hctx.Done():
		t.Fatal("held context ended while the log was running")
	case <-time.After(50 * time.Millisecond):
	}

	_ = SetLogState(url, LogPaused)

	select {
	case <-hctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("held context was not cancelled by a pause")
	}
}

// TestStoppedLogsPersist covers the difference between stop and pause: a
// stopped log is still stopped after a restart, a paused one is not.
func TestStoppedLogsPersist(t *testing.T) {
	ResetLogControlsForTest()
	defer ResetLogControlsForTest()

	file := filepath.Join(t.TempDir(), "log_controls.json")

	if err := LoadLogControls(file); err != nil {
		t.Fatalf("a missing state file must not be an error: %v", err)
	}

	_ = SetLogState("ct.example.com/stopped", LogStopped)
	_ = SetLogState("ct.example.com/paused", LogPaused)

	// Simulate a restart.
	ResetLogControlsForTest()

	if err := LoadLogControls(file); err != nil {
		t.Fatal(err)
	}

	if got := GetLogState("ct.example.com/stopped"); got != LogStopped {
		t.Errorf("stopped log after restart: %s, want stopped", got)
	}

	if got := GetLogState("ct.example.com/paused"); got != LogRunning {
		t.Errorf("paused log after restart: %s, want running", got)
	}

	// Resuming removes it from the file.
	_ = SetLogState("ct.example.com/stopped", LogRunning)

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var f stoppedLogsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}

	if len(f.Stopped) != 0 {
		t.Errorf("state file still lists %v after resume", f.Stopped)
	}
}

// TestTiledPauseLosesNothing pauses a tiled log part-way through draining a
// backlog, resumes it, and checks every entry is delivered exactly once.
//
// This is the case pausing could easily get wrong. ctIndex advances as entries
// are handed to the parsing pool, so if a pause also cancelled the pool's
// sends, the entries in flight would count as processed without ever being
// delivered - lost for good. The pool finishes on the worker's lifetime
// instead; only fetching stops on the pause.
func TestTiledPauseLosesNothing(t *testing.T) {
	ResetLogControlsForTest()
	defer ResetLogControlsForTest()

	const n = 60 * tileWidth

	prev := config.AppConfig.General.Scanner.NumWorkers
	config.AppConfig.General.Scanner.NumWorkers = 4
	defer func() { config.AppConfig.General.Scanner.NumWorkers = prev }()

	tl := newTestTiledLog(t, n)

	srv := httptest.NewServer(tl)
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: srv.URL + "/",
		PublicKey:        &key.PublicKey,
		HTTPClient:       srv.Client(),
		UserAgent:        "certstream-server-go test (+https://example.com)",
	})
	if err != nil {
		t.Fatal(err)
	}

	life, cancelLife := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelLife()

	normURL := normalizeCtlogURL(srv.URL)

	tw := &tiledWorker{
		name: "paused-tiled", operatorName: "Example", monitoringURL: srv.URL,
		entryChan: make(chan models.Entry, 64),
		tree:      tl.tree, treeSize: tl.tree.N, treeGrewAt: time.Now(),
	}

	const pauseAfter = 2000

	var got []uint64

	collected := make(chan struct{})

	go func() {
		for e := range tw.entryChan {
			got = append(got, e.Data.CertIndex)
			if len(got) == pauseAfter {
				_ = SetLogState(normURL, LogPaused)
			}
		}

		close(collected)
	}()

	fetchCtx, cancelFetch := heldContext(life, normURL)
	if _, err := tw.drainBatch(fetchCtx, life, client); err != nil {
		t.Fatalf("drainBatch: %v", err)
	}

	cancelFetch()

	if tw.ctIndex >= n {
		t.Fatalf("the pause did not stop the drain (ctIndex %d of %d)", tw.ctIndex, n)
	}

	t.Logf("paused at ctIndex %d of %d", tw.ctIndex, n)

	_ = SetLogState(normURL, LogRunning)

	for calls := 0; tw.ctIndex < n; calls++ {
		if calls > 1000 {
			t.Fatalf("no progress after resume: ctIndex %d", tw.ctIndex)
		}

		fetchCtx, cancelFetch := heldContext(life, normURL)
		if _, err := tw.drainBatch(fetchCtx, life, client); err != nil {
			t.Fatalf("drainBatch after resume: %v", err)
		}

		cancelFetch()
	}

	close(tw.entryChan)
	<-collected

	assertExactlyOnce(t, got, n)
}

// TestRFC6962PauseLeavesNoGap pauses an RFC 6962 scan part-way, then resumes
// from just after the last entry delivered. If the pause had discarded entries
// already fetched, there would be a gap below that point.
func TestRFC6962PauseLeavesNoGap(t *testing.T) {
	ResetLogControlsForTest()
	defer ResetLogControlsForTest()

	const n = 600

	const marker = ^uint64(0)

	fl := newFakeLog(t, n, 50)
	normURL := normalizeCtlogURL(fl.BaseURI())

	life, cancelLife := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelLife()

	w := &worker{name: "paused", operatorName: "Example", ctURL: fl.BaseURI(), entryChan: make(chan models.Entry, 32), ctx: life}

	var (
		mu  sync.Mutex
		got []uint64
	)

	collected := make(chan struct{})
	drained := make(chan struct{})

	go func() {
		for e := range w.entryChan {
			if e.Data.CertIndex == marker {
				drained <- struct{}{}
				continue
			}

			mu.Lock()
			got = append(got, e.Data.CertIndex)
			paused := len(got) == 150
			mu.Unlock()

			if paused {
				_ = SetLogState(normURL, LogPaused)
			}
		}

		close(collected)
	}()

	fetchCtx, cancelFetch := heldContext(life, normURL)

	// Continuous: without the pause this would never return.
	if err := w.scanEntries(life, fetchCtx, fl, scanner.FetcherOptions{
		BatchSize: 50, ParallelFetch: 1, Continuous: true,
	}, 2, 16); err != nil {
		t.Fatalf("scanEntries: %v", err)
	}

	cancelFetch()

	// Channels are FIFO: once the collector has seen this marker, it has
	// recorded every entry the first scan delivered. Checking the channel's
	// length instead races with an entry received but not yet recorded.
	w.entryChan <- models.Entry{Data: models.Data{CertIndex: marker}}
	<-drained

	mu.Lock()
	resumeAt := uint64(0)
	for _, idx := range got {
		if idx+1 > resumeAt {
			resumeAt = idx + 1
		}
	}
	delivered := len(got)
	mu.Unlock()

	if resumeAt >= n {
		t.Fatalf("the pause did not stop the scan (%d of %d delivered)", delivered, n)
	}

	t.Logf("paused after %d entries; resuming at %d", delivered, resumeAt)

	_ = SetLogState(normURL, LogRunning)

	if err := w.scanEntries(life, life, fl, scanner.FetcherOptions{
		BatchSize: 50, ParallelFetch: 1, StartIndex: int64(resumeAt), Continuous: false,
	}, 2, 16); err != nil {
		t.Fatalf("scanEntries after resume: %v", err)
	}

	close(w.entryChan)
	<-collected

	assertExactlyOnce(t, got, n)
}

func assertExactlyOnce(t *testing.T, got []uint64, n int) {
	t.Helper()

	seen := make([]bool, n)

	for _, idx := range got {
		if idx >= uint64(n) {
			t.Fatalf("out-of-range index %d", idx)
		}

		if seen[idx] {
			t.Fatalf("index %d delivered twice", idx)
		}

		seen[idx] = true
	}

	for i, ok := range seen {
		if !ok {
			t.Fatalf("index %d never delivered (%d of %d delivered) - lost across the pause", i, len(got), n)
		}
	}
}
