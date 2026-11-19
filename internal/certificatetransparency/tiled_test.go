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

func TestIsPartialTile(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "partial hash tile",
			err:  errors.New("tile/0/x287/768.p/124: unexpected status code 404"),
			want: true,
		},
		{
			name: "partial data tile",
			err:  errors.New("tile/data/x287/768.p/124: unexpected status code 404"),
			want: true,
		},
		{
			name: "full data tile",
			err:  errors.New("tile/data/x456/118: unexpected status code 404"),
			want: false,
		},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPartialTile(tc.err); got != tc.want {
				t.Errorf("isPartialTile(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestTrailingPartialTileIsSkipped covers the decision that stops the endless
// partial-tile 404s: while only the trailing partial tile remains and the tree
// is still growing, the fetch is skipped; once the tree goes static the entries
// must not be stranded, so it is attempted.
func TestTrailingPartialTileIsSkipped(t *testing.T) {
	cases := []struct {
		name        string
		ctIndex     int64
		treeSize    int64
		treeGrewAgo time.Duration
		wantSkip    bool
	}{
		{
			name:        "only trailing partial remains, tree active",
			ctIndex:     287768 * tileWidth,
			treeSize:    287768*tileWidth + 124,
			treeGrewAgo: time.Second,
			wantSkip:    true,
		},
		{
			name:        "mid-tile progress, same tile as tree head",
			ctIndex:     287768*tileWidth + 10,
			treeSize:    287768*tileWidth + 124,
			treeGrewAgo: time.Second,
			wantSkip:    true,
		},
		{
			name:        "a full tile is available",
			ctIndex:     287768 * tileWidth,
			treeSize:    287770*tileWidth + 124,
			treeGrewAgo: time.Second,
			wantSkip:    false,
		},
		{
			name:        "exactly one full tile available",
			ctIndex:     287768 * tileWidth,
			treeSize:    287769 * tileWidth,
			treeGrewAgo: time.Second,
			wantSkip:    false,
		},
		{
			name:        "tree static past the grace period",
			ctIndex:     287768 * tileWidth,
			treeSize:    287768*tileWidth + 124,
			treeGrewAgo: partialTileGrace + time.Minute,
			wantSkip:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			skip := skipTrailingPartialTile(tc.ctIndex, tc.treeSize, now.Add(-tc.treeGrewAgo), now)

			if skip != tc.wantSkip {
				t.Errorf("skip = %v, want %v (ctIndex=%d treeSize=%d)",
					skip, tc.wantSkip, tc.ctIndex, tc.treeSize)
			}
		})
	}
}

// TestHasFullTileToRead pins the predicate that decides both whether the
// checkpoint is refreshed and whether the trailing partial tile is requested.
//
// The checkpoint-refresh case is the important one: the worker stops short of
// the trailing partial tile, so refreshing only once treeSize is fully consumed
// would leave a log whose last tile is partial never fetching a checkpoint
// again - frozen at that index, with the tree apparently static.
func TestHasFullTileToRead(t *testing.T) {
	const base = 287768 * tileWidth

	cases := []struct {
		name     string
		ctIndex  int64
		treeSize int64
		want     bool
	}{
		{"fully consumed", base, base, false},
		{"only trailing partial", base, base + 124, false},
		{"mid-tile, head in same tile", base + 10, base + 124, false},
		{"one full tile", base, base + tileWidth, true},
		{"one full tile plus partial", base, base + tileWidth + 124, true},
		{"many tiles behind", base, base + 50*tileWidth, true},
		{"mid-tile with a later full tile", base + 10, base + 2*tileWidth, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasFullTileToRead(tc.ctIndex, tc.treeSize); got != tc.want {
				t.Errorf("hasFullTileToRead(%d, %d) = %v, want %v",
					tc.ctIndex, tc.treeSize, got, tc.want)
			}
		})
	}
}

// TestPartialTileWaitEventuallyRefreshes is the regression guard for the stall:
// a log sitting on a trailing partial tile must keep refreshing its checkpoint,
// otherwise it can never learn that the tree has grown.
func TestPartialTileWaitEventuallyRefreshes(t *testing.T) {
	const base = 287768 * tileWidth

	ctIndex, treeSize := int64(base), int64(base+124)

	// drainBatch refreshes the checkpoint when this is false, so in the
	// partial-tile-only state it must be false or the log stops asking.
	if hasFullTileToRead(ctIndex, treeSize) {
		t.Fatal("waiting on a trailing partial tile must still trigger a checkpoint refresh")
	}

	// Once the tree grows past the tile boundary, normal reading resumes and
	// the previously stranded entries are picked up in a full tile.
	grown := int64(base + tileWidth + 8)
	if !hasFullTileToRead(ctIndex, grown) {
		t.Errorf("after growth to %d, expected a full tile to be readable", grown)
	}

	now := time.Now()
	if skipTrailingPartialTile(ctIndex, grown, now, now) {
		t.Error("should not skip once a full tile is available")
	}
}
