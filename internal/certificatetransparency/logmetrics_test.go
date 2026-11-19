package certificatetransparency

import (
	"sync"
	"testing"
)

// TestIncKeepsHighWaterMark covers the out-of-order completion that num_workers
// and parallel_fetch both produce. A backwards-moving index would persist a
// stale resume position in ct_index.json and suppress rate reporting.
func TestIncKeepsHighWaterMark(t *testing.T) {
	m := newTestMetrics()

	const url = "ct.example.com/log"

	// Arrive deliberately out of order, as concurrent matcher goroutines do.
	for _, idx := range []uint64{100, 250, 180, 249, 400, 399} {
		m.Inc("Example", url, idx)
	}

	if got := m.GetCTIndex(url); got != 400 {
		t.Errorf("GetCTIndex = %d, want 400 (the high-water mark)", got)
	}

	if got := m.Get("Example", url); got != 6 {
		t.Errorf("cert count = %d, want 6 - every entry must still be counted", got)
	}
}

// TestIncHighWaterMarkUnderConcurrency runs the real race the fix exists for.
// Run with -race to be meaningful.
func TestIncHighWaterMarkUnderConcurrency(t *testing.T) {
	m := newTestMetrics()

	const (
		url      = "ct.example.com/log"
		workers  = 8
		perBatch = 500
	)

	var wg sync.WaitGroup

	// Each worker writes a disjoint, descending run, so any last-write-wins
	// behaviour leaves the mark below the true maximum.
	for w := 0; w < workers; w++ {
		wg.Add(1)

		go func(w int) {
			defer wg.Done()

			base := uint64(w * perBatch)
			for i := perBatch - 1; i >= 0; i-- {
				m.Inc("Example", url, base+uint64(i))
			}
		}(w)
	}

	wg.Wait()

	want := uint64(workers*perBatch - 1)
	if got := m.GetCTIndex(url); got != want {
		t.Errorf("GetCTIndex = %d, want %d", got, want)
	}
}

// TestSetCTIndexRepositionsUnconditionally guards the other direction:
// recordStartPosition uses SetCTIndex to place a worker deliberately, including
// moving it backwards, and that must not be clamped by the high-water mark.
func TestSetCTIndexRepositionsUnconditionally(t *testing.T) {
	m := newTestMetrics()

	const url = "ct.example.com/log"

	m.Inc("Example", url, 5000)
	m.SetCTIndex(url, 42)

	if got := m.GetCTIndex(url); got != 42 {
		t.Errorf("GetCTIndex = %d, want 42 - a deliberate reposition must apply", got)
	}
}

// newTestMetrics builds an empty LogMetrics with its maps initialised, matching
// how the package-level instance is constructed.
func newTestMetrics() *LogMetrics {
	return &LogMetrics{
		metrics: make(CTMetrics),
		index:   make(CTCertIndex),
	}
}
