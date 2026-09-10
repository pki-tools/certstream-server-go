package certificatetransparency

import (
	"sync"
	"time"
)

// ErrorCategory classifies the kind of error recorded.
type ErrorCategory string

const (
	ErrCatConnection  ErrorCategory = "connection"
	ErrCatSTH         ErrorCategory = "sth"
	ErrCatCheckpoint  ErrorCategory = "checkpoint"
	ErrCatParse       ErrorCategory = "parse"
	ErrCatScan        ErrorCategory = "scan"
	ErrCatTreeSize    ErrorCategory = "tree-size"
	ErrCatCCADB       ErrorCategory = "ccadb"
	ErrCatOther       ErrorCategory = "other"
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

// RecordError appends an error to the sliding-window ring buffer.
// It is safe to call from multiple goroutines.
func RecordError(logURL, logName string, cat ErrorCategory, msg string) {
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
