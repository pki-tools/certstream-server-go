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
}

type logStatusEntry struct {
	normURL   string
	rawURL    string
	name      string
	operator  string
	lType     LogType
	publicKey crypto.PublicKey // nil for regular logs

	mu          sync.Mutex
	treeSize    uint64
	treeSizeAt  time.Time
	prevIndex   uint64
	prevIndexAt time.Time
	ratePerSec  float64
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

	logStatusReg.entries[normURL] = &logStatusEntry{
		normURL:   normURL,
		rawURL:    rawURL,
		name:      name,
		operator:  operator,
		lType:     lType,
		publicKey: publicKey,
	}
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

			pollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			var treeSize uint64
			var err error

			if entry.lType == LogTypeTiled {
				treeSize, err = fetchTiledTreeSize(pollCtx, entry)
			} else {
				treeSize, err = fetchRegularTreeSize(pollCtx, entry.rawURL)
			}

			if err != nil {
				// Keep the previous tree size; log only at debug level to avoid noise.
				if ctx.Err() == nil {
					log.Printf("Tree size poll failed for '%s': %v\n", entry.normURL, err)
				}
				return
			}

			currentIndex := indexes[entry.normURL]

			entry.mu.Lock()
			defer entry.mu.Unlock()

			entry.treeSize = treeSize
			entry.treeSizeAt = time.Now()

			// Update rate estimate from index delta since the last poll.
			if !entry.prevIndexAt.IsZero() {
				elapsed := time.Since(entry.prevIndexAt).Seconds()
				if elapsed > 0 && currentIndex >= entry.prevIndex {
					entry.ratePerSec = float64(currentIndex-entry.prevIndex) / elapsed
				}
			}
			entry.prevIndex = currentIndex
			entry.prevIndexAt = time.Now()
		}(e)
	}

	wg.Wait()
}

func fetchRegularTreeSize(ctx context.Context, rawURL string) (uint64, error) {
	u := strings.TrimRight(rawURL, "/") + "/ct/v1/get-sth"
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)

	hc := &http.Client{}
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
	hc := &http.Client{}
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
