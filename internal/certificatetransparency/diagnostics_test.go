package certificatetransparency

import (
	"testing"
	"time"
)

// TestStartPositionIsRecordedImmediately is the regression test for logs being
// persisted at index 0 despite start_at_head placing them at the tree head.
//
// metrics.Inc is the only other writer of the recorded index and it does not run
// until a certificate completes the pipeline. Before the fix, everything that
// reads the index — ct_index.json, /log-status, the dashboard — saw 0 until then,
// so a correctly-started log reported its entire tree as backlog, and a restart
// in that window could trigger a real full backfill.
func TestStartPositionIsRecordedImmediately(t *testing.T) {
	const (
		url      = "ct.example.com/regular-startathead"
		treeSize = uint64(500_000_000)
	)

	metrics.Init("Example", url)
	registerLogForStatus(url, "Example Log", "Example", LogTypeRegular, nil)

	if got := metrics.GetCTIndex(url); got != 0 {
		t.Fatalf("precondition: index = %d, want 0", got)
	}

	// What a worker does when it starts at the tree head.
	recordStartPosition(url, treeSize)

	if got := metrics.GetCTIndex(url); got != treeSize {
		t.Errorf("recorded index = %d, want %d — this is what lands in ct_index.json", got, treeSize)
	}

	// /log-status must show the log as caught up, not the whole tree as backlog.
	logStatusReg.mu.RLock()
	entry := logStatusReg.entries[url]
	logStatusReg.mu.RUnlock()

	if entry == nil {
		t.Fatal("log not registered for status")
	}

	entry.mu.Lock()
	entry.treeSize = treeSize
	entry.treeSizeAt = time.Now()
	entry.mu.Unlock()

	var snap *LogStatusSnapshot
	for _, s := range GetLogStatuses() {
		if s.URL == url {
			snap = &s
			break
		}
	}
	if snap == nil {
		t.Fatal("log missing from status snapshot")
	}

	if snap.Behind != 0 {
		t.Errorf("Behind = %d, want 0 (a start-at-head log is live, not backlogged)", snap.Behind)
	}
}

// TestStartPositionDoesNotFakeARateSpike guards the other half of the fix: moving
// the index from 0 to the tree size is a reposition, not throughput, and must not
// be counted as hundreds of millions of entries per second on the next poll.
func TestStartPositionDoesNotFakeARateSpike(t *testing.T) {
	const (
		url      = "ct.example.com/rate-baseline"
		treeSize = uint64(500_000_000)
	)

	metrics.Init("Example", url)
	registerLogForStatus(url, "Example Log 2", "Example", LogTypeRegular, nil)

	recordStartPosition(url, treeSize)

	logStatusReg.mu.RLock()
	entry := logStatusReg.entries[url]
	logStatusReg.mu.RUnlock()

	entry.mu.Lock()
	prevIndex, rate := entry.prevIndex, entry.ratePerSec
	entry.mu.Unlock()

	if prevIndex != treeSize {
		t.Errorf("rate baseline prevIndex = %d, want %d; the next poll would bill the jump as throughput", prevIndex, treeSize)
	}
	if rate != 0 {
		t.Errorf("ratePerSec = %v, want 0", rate)
	}
}

// TestTiledThroughputCeiling records the ceiling the drain fix removed: the old
// loop waited for the poll ticker between batches, so a tiled log could never
// exceed tiled_batch_size per interval no matter how far behind it was.
func TestTiledThroughputCeiling(t *testing.T) {
	const batch = 500

	oldCeiling := float64(batch) / tiledPollInterval.Seconds()
	t.Logf("old ceiling: %d entries per %s = %.1f entries/sec per tiled log",
		batch, tiledPollInterval, oldCeiling)
	t.Logf("a log growing at 1000 entries/sec outpaced that by %.0fx", 1000/oldCeiling)

	if oldCeiling > 20 {
		t.Fatalf("sanity check failed: expected a tiny ceiling, got %.1f/s", oldCeiling)
	}
}

// TestBackfillMarking verifies cold-start detection is deduplicated per log and
// survives the error ring overflowing, since it drives the /errors verdict.
func TestBackfillMarking(t *testing.T) {
	start := BackfillingLogs()

	RecordError("ct.example.com/newshard", "New Shard", ErrCatBackfill, "backfilling from 0")
	RecordError("ct.example.com/newshard", "New Shard", ErrCatBackfill, "backfilling from 0")
	RecordError("ct.example.com/other", "Other Shard", ErrCatBackfill, "backfilling from 0")

	if got := BackfillingLogs() - start; got != 2 {
		t.Fatalf("BackfillingLogs delta = %d, want 2 (deduped by URL)", got)
	}

	// Flood the ring past capacity; the tally must not be evicted with the records.
	for i := 0; i < errorRingSize+50; i++ {
		RecordError("ct.example.com/noise", "Noise", ErrCatParse, "noise")
	}

	if got := BackfillingLogs() - start; got != 2 {
		t.Errorf("after ring overflow BackfillingLogs delta = %d, want 2", got)
	}

	for _, r := range GetRecentErrors(0) {
		if r.Category == ErrCatBackfill {
			t.Error("expected backfill records to be evicted by the flood; tally must be what survives")
		}
	}
}

// TestErrorRingOrdering guards the ring's newest-first contract, which the
// /errors page depends on for its "most recent" figure.
func TestErrorRingOrdering(t *testing.T) {
	RecordError("a", "A", ErrCatOther, "first")
	RecordError("b", "B", ErrCatOther, "second")
	RecordError("c", "C", ErrCatOther, "third")

	got := GetRecentErrors(3)
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}

	want := []string{"third", "second", "first"}
	for i, w := range want {
		if got[i].Message != w {
			t.Errorf("record %d = %q, want %q", i, got[i].Message, w)
		}
	}
}
