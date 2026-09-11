package certificatetransparency

import "testing"

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
