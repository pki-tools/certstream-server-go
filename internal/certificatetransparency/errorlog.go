package certificatetransparency

import (
	"sync"
	"time"
)

// ErrorCategory classifies the kind of error recorded.
type ErrorCategory string

const (
	ErrCatConnection ErrorCategory = "connection"
	ErrCatSTH        ErrorCategory = "sth"
	ErrCatCheckpoint ErrorCategory = "checkpoint"
	ErrCatParse      ErrorCategory = "parse"
	ErrCatScan       ErrorCategory = "scan"
	ErrCatTreeSize   ErrorCategory = "tree-size"
	ErrCatCCADB      ErrorCategory = "ccadb"
	ErrCatRateLimit  ErrorCategory = "rate-limit"
	ErrCatBackfill   ErrorCategory = "backfill"
	ErrCatTile       ErrorCategory = "tile"
	ErrCatOther      ErrorCategory = "other"
)

const errorRingSize = 500

// ErrorRecord is a single captured error event.
type ErrorRecord struct {
	Time     time.Time
	LogURL   string
	LogName  string
	Category ErrorCategory
	Message  string
}

type errorRingBuf struct {
	mu   sync.RWMutex
	buf  [errorRingSize]ErrorRecord
	head int // index where the next write goes
	size int // number of valid entries (≤ errorRingSize)
}

var errRing = &errorRingBuf{}

// backfillingLogs tracks which logs started this run from index 0. Kept outside
// the ring buffer so the count survives the window filling up with other errors.
var backfillingLogs = struct {
	mu   sync.Mutex
	urls map[string]struct{}
}{urls: make(map[string]struct{})}

// BackfillingLogs returns how many distinct logs began this run from index 0.
func BackfillingLogs() int {
	backfillingLogs.mu.Lock()
	defer backfillingLogs.mu.Unlock()

	return len(backfillingLogs.urls)
}

// RecordError appends an error to the sliding-window ring buffer.
// It is safe to call from multiple goroutines.
func RecordError(logURL, logName string, cat ErrorCategory, msg string) {
	if cat == ErrCatBackfill {
		backfillingLogs.mu.Lock()
		backfillingLogs.urls[logURL] = struct{}{}
		backfillingLogs.mu.Unlock()
	}

	errRing.mu.Lock()
	errRing.buf[errRing.head] = ErrorRecord{
		Time:     time.Now(),
		LogURL:   logURL,
		LogName:  logName,
		Category: cat,
		Message:  msg,
	}
	errRing.head = (errRing.head + 1) % errorRingSize
	if errRing.size < errorRingSize {
		errRing.size++
	}
	errRing.mu.Unlock()
}

// noteThrottle tracks when each key last wrote to the ring.
var noteThrottle = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// RecordErrorThrottled records an error at most once per interval for the given
// key. A condition that recurs every poll would otherwise evict every other
// error from the window, hiding the problems worth seeing.
func RecordErrorThrottled(key string, interval time.Duration, logURL, logName string, cat ErrorCategory, msg string) {
	now := time.Now()

	noteThrottle.mu.Lock()
	last, seen := noteThrottle.last[key]
	due := !seen || now.Sub(last) >= interval
	if due {
		noteThrottle.last[key] = now
	}
	noteThrottle.mu.Unlock()

	if due {
		RecordError(logURL, logName, cat, msg)
	}
}

// GetRecentErrors returns up to n most-recent error records, newest first.
// If n <= 0 all stored records are returned.
func GetRecentErrors(n int) []ErrorRecord {
	errRing.mu.RLock()
	size := errRing.size
	head := errRing.head
	errRing.mu.RUnlock()

	if size == 0 {
		return nil
	}

	if n <= 0 || n > size {
		n = size
	}

	out := make([]ErrorRecord, n)
	// head points to the oldest slot when the buffer is full, or to the
	// next-write slot when it isn't yet full. Walk backwards from the
	// most-recently written slot.
	for i := 0; i < n; i++ {
		// slot of the i-th most recent entry
		idx := ((head - 1 - i) + errorRingSize) % errorRingSize
		errRing.mu.RLock()
		out[i] = errRing.buf[idx]
		errRing.mu.RUnlock()
	}

	return out
}

// ErrorRingSize returns the current number of stored error records.
func ErrorRingSize() int {
	errRing.mu.RLock()
	defer errRing.mu.RUnlock()
	return errRing.size
}
