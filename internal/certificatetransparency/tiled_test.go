package certificatetransparency

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestIsTileNotYetPublished pins the classification that keeps a transient tile
// 404 from tearing down a worker, without swallowing genuine failures.
func TestIsTileNotYetPublished(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "data tile 404 as torchwood reports it",
			err:  errors.New("tile/data/x456/118: unexpected status code 404"),
			want: true,
		},
		{
			name: "hash tile 404",
			err:  errors.New("tile/8/x001/234: unexpected status code 404"),
			want: true,
		},
		{
			name: "wrapped tile 404",
			err:  fmt.Errorf("reading tiles: %w", errors.New("tile/data/x456/118: unexpected status code 404")),
			want: true,
		},
		{
			// 403 is a real problem — blocked, not merely unpublished.
			name: "tile 403 is not transient",
			err:  errors.New("tile/data/x456/118: unexpected status code 403"),
			want: false,
		},
		{
			// A 404 elsewhere means a misconfigured monitoring prefix.
			name: "checkpoint 404 is not a tile",
			err:  errors.New("checkpoint: unexpected status code 404"),
			want: false,
		},
		{
			name: "unrelated error",
			err:  errors.New("unexpected end of tile data for tile 42"),
			want: false,
		},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTileNotYetPublished(tc.err); got != tc.want {
				t.Errorf("isTileNotYetPublished(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// countRecorded returns how many ring entries carry the given message. The ring
// size itself cannot be used to count writes: it saturates at errorRingSize, so
// once the window is full it stops growing no matter how much is recorded.
func countRecorded(msg string) int {
	var n int
	for _, r := range GetRecentErrors(0) {
		if r.Message == msg {
			n++
		}
	}

	return n
}

// TestRecordErrorThrottled checks a recurring condition writes once per interval
// rather than flooding the ring and evicting everything else.
func TestRecordErrorThrottled(t *testing.T) {
	stamp := time.Now().UnixNano()
	key := fmt.Sprintf("test-throttle-%d", stamp)
	msg := fmt.Sprintf("tile missing %d", stamp)

	for i := 0; i < 50; i++ {
		RecordErrorThrottled(key, time.Hour, "ct.example.com/t", "Tiled", ErrCatTile, msg)
	}

	if got := countRecorded(msg); got != 1 {
		t.Errorf("recorded %d times, want 1 — throttling is not holding", got)
	}

	// A zero interval always records, so a misconfigured interval cannot
	// silently swallow everything.
	msg2 := msg + "-always"
	for i := 0; i < 3; i++ {
		RecordErrorThrottled(key+"-b", 0, "ct.example.com/t", "Tiled", ErrCatTile, msg2)
	}

	if got := countRecorded(msg2); got != 3 {
		t.Errorf("recorded %d times with a zero interval, want 3", got)
	}
}

// Separate keys must not throttle each other.
func TestRecordErrorThrottledIsPerKey(t *testing.T) {
	stamp := time.Now().UnixNano()
	msg := fmt.Sprintf("per-key tile missing %d", stamp)

	for i := 0; i < 4; i++ {
		RecordErrorThrottled(fmt.Sprintf("per-key-%d-%d", stamp, i), time.Hour,
			"ct.example.com/t", "Tiled", ErrCatTile, msg)
	}

	if got := countRecorded(msg); got != 4 {
		t.Errorf("recorded %d times, want 4 — keys are sharing a throttle", got)
	}
}
