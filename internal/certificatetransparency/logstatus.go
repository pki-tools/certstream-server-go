package certificatetransparency

import (
	"context"
	"crypto"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
)

// LogType distinguishes regular CT logs from tiled (Static CT API) logs.
type LogType int

const (
	LogTypeRegular LogType = iota
	LogTypeTiled
)

func (t LogType) String() string {
	if t == LogTypeTiled {
		return "Tiled"
	}
	return "Regular"
}

// LogStatusSnapshot is a point-in-time view of a single CT log's status.
type LogStatusSnapshot struct {
	URL          string
	Name         string
	Operator     string
	Type         string
	CurrentIndex uint64
	TreeSize     uint64
	Behind       uint64
	RatePerSec   float64
	ETA          time.Duration // 0 = live, -1 = unknown
	TreeSizeAge  time.Duration // -1 = never fetched
	CatchupUntil time.Time     // zero if catch-up not active
}

type logStatusEntry struct {
	normURL   string
	rawURL    string
	name      string
	operator  string
	lType     LogType
	publicKey crypto.PublicKey // nil for regular logs

	mu            sync.Mutex
	treeSize      uint64
	treeSizeAt    time.Time
	prevIndex     uint64
	prevIndexAt   time.Time
	ratePerSec    float64
	catchupUntil  time.Time
	scanRestartCh chan struct{} // buffered(1); signal to restart scanner with catch-up settings
}

type logStatusRegistryT struct {
	mu      sync.RWMutex
	entries map[string]*logStatusEntry // keyed by normalised URL
}

var logStatusReg = &logStatusRegistryT{
	entries: make(map[string]*logStatusEntry),
}

// registerLogForStatus registers a log for status tracking. Safe to call multiple times with the same URL.
func registerLogForStatus(rawURL, name, operator string, lType LogType, publicKey crypto.PublicKey) {
	normURL := normalizeCtlogURL(rawURL)

	logStatusReg.mu.Lock()
	defer logStatusReg.mu.Unlock()

	if _, ok := logStatusReg.entries[normURL]; ok {
		return
	}

	// Seed prevIndex with whatever the metrics already know so the very first
	// tree-size poll (3 minutes after startup) can compute a rate rather than
	// waiting for a second poll 3 minutes after that.
	seedIndex := metrics.GetCTIndex(normURL)
	logStatusReg.entries[normURL] = &logStatusEntry{
		normURL:       normURL,
		rawURL:        rawURL,
		name:          name,
		operator:      operator,
		lType:         lType,
		publicKey:     publicKey,
		prevIndex:     seedIndex,
		prevIndexAt:   time.Now(),
		scanRestartCh: make(chan struct{}, 1),
	}
}

// resetRateBaseline re-seeds a log's rate calculation after its index jumps for a
// reason other than progress — a start-at-head reposition moves the index from 0
// to the tree size, which would otherwise be counted as millions of entries per
// second on the next poll.
func resetRateBaseline(normURL string, index uint64) {
	logStatusReg.mu.RLock()
	entry, ok := logStatusReg.entries[normURL]
	logStatusReg.mu.RUnlock()

	if !ok {
		return
	}

	entry.mu.Lock()
	entry.prevIndex = index
	entry.prevIndexAt = time.Now()
	entry.ratePerSec = 0
	entry.mu.Unlock()
}

// GetLogStatuses returns a sorted snapshot of all registered logs' current statuses.
func GetLogStatuses() []LogStatusSnapshot {
	indexes := metrics.GetAllCTIndexes()

	logStatusReg.mu.RLock()
	entries := make([]*logStatusEntry, 0, len(logStatusReg.entries))
	for _, e := range logStatusReg.entries {
		entries = append(entries, e)
	}
	logStatusReg.mu.RUnlock()

	snapshots := make([]LogStatusSnapshot, 0, len(entries))
	for _, entry := range entries {
		currentIndex := indexes[entry.normURL]

		entry.mu.Lock()
		treeSize := entry.treeSize
		treeSizeAt := entry.treeSizeAt
		rate := entry.ratePerSec
		catchupUntil := entry.catchupUntil
		entry.mu.Unlock()

		var behind uint64
		if treeSize > currentIndex {
			behind = treeSize - currentIndex
		}

		eta := time.Duration(-1)
		if behind == 0 && treeSize > 0 {
			eta = 0 // live
		} else if rate > 0 && behind > 0 {
			eta = time.Duration(float64(behind)/rate) * time.Second
		}

		treeSizeAge := time.Duration(-1)
		if !treeSizeAt.IsZero() {
			treeSizeAge = time.Since(treeSizeAt).Round(time.Second)
		}

		snapshots = append(snapshots, LogStatusSnapshot{
			URL:          entry.rawURL,
			Name:         entry.name,
			Operator:     entry.operator,
			Type:         entry.lType.String(),
			CurrentIndex: currentIndex,
			TreeSize:     treeSize,
			Behind:       behind,
			RatePerSec:   rate,
			ETA:          eta,
			TreeSizeAge:  treeSizeAge,
			CatchupUntil: catchupUntil,
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Operator != snapshots[j].Operator {
			return snapshots[i].Operator < snapshots[j].Operator
		}
		return snapshots[i].Name < snapshots[j].Name
	})

	return snapshots
}

// StartTreeSizePoller starts a goroutine that periodically refreshes tree sizes for all registered logs.
// It performs an initial poll immediately after being called.
func StartTreeSizePoller(ctx context.Context, interval time.Duration) {
	go func() {
		pollAllTreeSizes(ctx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pollAllTreeSizes(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// pollAllTreeSizes fetches the current tree size for every registered log concurrently.
func pollAllTreeSizes(ctx context.Context) {
	logStatusReg.mu.RLock()
	entries := make([]*logStatusEntry, 0, len(logStatusReg.entries))
	for _, e := range logStatusReg.entries {
		entries = append(entries, e)
	}
	logStatusReg.mu.RUnlock()

	if len(entries) == 0 {
		return
	}

	// Snapshot indexes once; avoids holding the metrics lock during HTTP calls.
	indexes := metrics.GetAllCTIndexes()

	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, e := range entries {
		wg.Add(1)
		sem <- struct{}{}

		go func(entry *logStatusEntry) {
			defer wg.Done()
			defer func() { <-sem }()

			currentIndex := indexes[entry.normURL]
			now := time.Now()

			// Always update the rate estimate from the index delta, regardless of
			// whether the tree-size fetch below succeeds. This decouples rate/ETA
			// from tree-size availability so logs still show processing stats even
			// when the checkpoint/STH endpoint is unreachable.
			entry.mu.Lock()
			if !entry.prevIndexAt.IsZero() {
				elapsed := now.Sub(entry.prevIndexAt).Seconds()
				if elapsed > 0 && currentIndex >= entry.prevIndex {
					entry.ratePerSec = float64(currentIndex-entry.prevIndex) / elapsed
				}
			}
			entry.prevIndex = currentIndex
			entry.prevIndexAt = now
			entry.mu.Unlock()

			pollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			var treeSize uint64
			var err error

			if entry.lType == LogTypeTiled {
				treeSize, err = fetchTiledTreeSize(pollCtx, entry)
			} else {
				treeSize, err = fetchRegularTreeSize(pollCtx, entry.rawURL, entry.name)
			}

			if err != nil {
				// Keep the previous tree size on failure.
				if ctx.Err() == nil {
					log.Printf("Tree size poll failed for '%s': %v\n", entry.normURL, err)
					RecordError(entry.rawURL, entry.name, ErrCatTreeSize, err.Error())
				}
				return
			}

			entry.mu.Lock()
			entry.treeSize = treeSize
			entry.treeSizeAt = time.Now()
			entry.mu.Unlock()
		}(e)
	}

	wg.Wait()
}

func fetchRegularTreeSize(ctx context.Context, rawURL, name string) (uint64, error) {
	u := strings.TrimRight(rawURL, "/") + "/ct/v1/get-sth"
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)

	hc := NewRateLimitedClient(rawURL, name, 15*time.Second)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sth); err != nil {
		return 0, err
	}

	return sth.TreeSize, nil
}

func fetchTiledTreeSize(ctx context.Context, entry *logStatusEntry) (uint64, error) {
	hc := NewRateLimitedClient(entry.rawURL, entry.name, 15*time.Second)
	c, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: entry.rawURL,
		PublicKey:        entry.publicKey,
		HTTPClient:       hc,
		UserAgent:        userAgent,
		Timeout:          15 * time.Second,
	})
	if err != nil {
		return 0, err
	}

	checkpoint, _, err := c.Checkpoint(ctx)
	if err != nil {
		return 0, err
	}

	return uint64(checkpoint.N), nil
}

// TriggerCatchup activates catch-up mode for the given log for dur. It also sends a
// non-blocking signal on the log's scanRestartCh so regular-log workers restart their
// scanner immediately with higher batch/parallel settings rather than waiting for the
// next natural restart.
func TriggerCatchup(normURL string, dur time.Duration) {
	logStatusReg.mu.RLock()
	entry, ok := logStatusReg.entries[normURL]
	logStatusReg.mu.RUnlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.catchupUntil = time.Now().Add(dur)
	entry.mu.Unlock()
	// Non-blocking: if a signal is already pending, the new one is redundant.
	select {
	case entry.scanRestartCh <- struct{}{}:
	default:
	}
}

// IsCatchupActive returns true if catch-up mode is currently active for the given log.
func IsCatchupActive(normURL string) bool {
	logStatusReg.mu.RLock()
	entry, ok := logStatusReg.entries[normURL]
	logStatusReg.mu.RUnlock()
	if !ok {
		return false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return !entry.catchupUntil.IsZero() && time.Now().Before(entry.catchupUntil)
}

// GetScanRestartCh returns the restart-signal channel for the given log. Workers should
// select on it to detect when they should restart their scanner with catch-up settings.
func GetScanRestartCh(normURL string) <-chan struct{} {
	logStatusReg.mu.RLock()
	defer logStatusReg.mu.RUnlock()
	if entry, ok := logStatusReg.entries[normURL]; ok {
		return entry.scanRestartCh
	}
	return nil
}

// NormalizeCtlogURL is the exported form of normalizeCtlogURL.
func NormalizeCtlogURL(rawURL string) string {
	return normalizeCtlogURL(rawURL)
}

// IsKnownLog reports whether the given normalised URL is registered in the status registry.
func IsKnownLog(normURL string) bool {
	logStatusReg.mu.RLock()
	_, ok := logStatusReg.entries[normURL]
	logStatusReg.mu.RUnlock()
	return ok
}
