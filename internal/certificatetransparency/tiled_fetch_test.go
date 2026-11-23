package certificatetransparency

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	"golang.org/x/mod/sumdb/tlog"
)

// testTiledLog serves a complete, verifiable static-CT log over HTTP - data
// tiles, hash tiles, and the tree they hash to - and counts every request, so
// tests can see how much the tiled worker really downloads.
type testTiledLog struct {
	tiles map[string][]byte
	tree  tlog.Tree

	mu   sync.Mutex
	hits map[string]int
}

func newTestTiledLog(t testing.TB, n int64) *testTiledLog {
	t.Helper()

	der := makeDER(t, "www.example.com", []string{"www.example.com"}, false)

	var stored []tlog.Hash

	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, x := range indexes {
			out[i] = stored[x]
		}

		return out, nil
	})

	var dataTiles [][]byte

	var cur []byte

	for i := int64(0); i < n; i++ {
		e := &sunlight.LogEntry{Certificate: der, LeafIndex: i}

		hashes, err := tlog.StoredHashes(i, e.MerkleTreeLeaf(), hr)
		if err != nil {
			t.Fatal(err)
		}

		stored = append(stored, hashes...)
		cur = sunlight.AppendTileLeaf(cur, e)

		if (i+1)%tileWidth == 0 {
			dataTiles = append(dataTiles, cur)
			cur = nil
		}
	}

	if len(cur) > 0 {
		dataTiles = append(dataTiles, cur)
	}

	root, err := tlog.TreeHash(n, hr)
	if err != nil {
		t.Fatal(err)
	}

	l := &testTiledLog{
		tiles: make(map[string][]byte),
		tree:  tlog.Tree{N: n, Hash: root},
		hits:  make(map[string]int),
	}

	for _, tile := range tlog.NewTiles(8, 0, n) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatal(err)
		}

		l.tiles[sunlight.TilePath(tile)] = data

		if tile.L == 0 {
			dt := tile
			dt.L = -1
			l.tiles[sunlight.TilePath(dt)] = dataTiles[tile.N]
		}
	}

	return l
}

func (l *testTiledLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")

	l.mu.Lock()
	l.hits[path]++
	l.mu.Unlock()

	data, ok := l.tiles[path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	_, _ = w.Write(data)
}

// dataTileFetches returns total data-tile requests and how many distinct tiles
// they covered.
func (l *testTiledLog) dataTileFetches() (total, distinct int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for path, n := range l.hits {
		if strings.HasPrefix(path, "tile/data/") {
			total += n
			distinct++
		}
	}

	return total, distinct
}

// drainTestLog drains a test tiled log from index 0 with the given number of
// parsing workers and returns the index of every entry delivered.
func drainTestLog(tb testing.TB, tl *testTiledLog, srvURL string, hc *http.Client, workers int) []uint64 {
	tb.Helper()

	prevBatch := config.AppConfig.General.Scanner.TiledBatchSize
	prevWorkers := config.AppConfig.General.Scanner.NumWorkers
	config.AppConfig.General.Scanner.TiledBatchSize = 500 // the old default; now ignored
	config.AppConfig.General.Scanner.NumWorkers = workers

	defer func() {
		config.AppConfig.General.Scanner.TiledBatchSize = prevBatch
		config.AppConfig.General.Scanner.NumWorkers = prevWorkers
	}()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: srvURL + "/",
		PublicKey:        &key.PublicKey,
		HTTPClient:       hc,
		UserAgent:        "certstream-server-go test (+https://example.com)",
	})
	if err != nil {
		tb.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tw := &tiledWorker{
		name:          "test-tiled",
		operatorName:  "Example",
		monitoringURL: srvURL,
		entryChan:     make(chan models.Entry, 1024),
		tree:          tl.tree,
		treeSize:      tl.tree.N,
		treeGrewAt:    time.Now(),
	}

	// Collect the output as the certHandler would consume it.
	var got []uint64

	collected := make(chan struct{})

	go func() {
		for e := range tw.entryChan {
			got = append(got, e.Data.CertIndex)
		}

		close(collected)
	}()

	for calls := 0; tw.ctIndex < tl.tree.N; calls++ {
		if calls > 10_000 {
			tb.Fatalf("no progress: ctIndex=%d of %d", tw.ctIndex, tl.tree.N)
		}

		if _, err := tw.drainBatch(ctx, client); err != nil {
			tb.Fatalf("drainBatch: %v", err)
		}
	}

	close(tw.entryChan)
	<-collected

	return got
}

// TestTiledDrainFetchesEachTileOnce drains a tiled log that is far behind and
// checks both the download count and the delivered entries.
//
// torchwood's Entries iterator fetches up to 50 data tiles per window and
// caches them only for the life of that iterator. Breaking out of it after
// tiled_batch_size entries threw the rest of the window away, and the next
// call fetched it again - about 20 downloads of each tile at the default 500,
// with the decompression, TLS and hashing that come with them.
//
// It runs with several parsing workers too: entries are parsed concurrently
// now, and every index must still arrive exactly once.
func TestTiledDrainFetchesEachTileOnce(t *testing.T) {
	const tiles = 120 // more than two of torchwood's 50-tile windows
	const n = tiles * tileWidth

	for _, workers := range []int{1, 4} {
		t.Run("workers="+itoa64(int64(workers)), func(t *testing.T) {
			tl := newTestTiledLog(t, n)

			srv := httptest.NewServer(tl)
			defer srv.Close()

			got := drainTestLog(t, tl, srv.URL, srv.Client(), workers)

			total, distinct := tl.dataTileFetches()
			t.Logf("drained %d entries: %d data-tile downloads covering %d distinct tiles", n, total, distinct)

			if distinct != tiles {
				t.Fatalf("fetched %d distinct data tiles, want %d", distinct, tiles)
			}

			if total != tiles {
				t.Errorf("data tiles downloaded %d times for %d tiles (%.1fx); each should be fetched once",
					total, tiles, float64(total)/tiles)
			}

			seen := make([]bool, n)
			for _, idx := range got {
				if idx >= n {
					t.Fatalf("delivered out-of-range index %d", idx)
				}

				if seen[idx] {
					t.Fatalf("index %d delivered twice", idx)
				}

				seen[idx] = true
			}

			if len(got) != n {
				t.Fatalf("delivered %d entries, want %d", len(got), n)
			}
		})
	}
}

// BenchmarkTiledDrainWorkers measures how a backlogged tiled log's drain rate
// scales with parsing workers. Before the worker pool it could not: parsing
// ran inline on the one goroutine iterating the log.
func BenchmarkTiledDrainWorkers(b *testing.B) {
	const n = 40 * tileWidth

	for _, workers := range []int{1, 2, 4} {
		b.Run("workers="+itoa64(int64(workers)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()

				tl := newTestTiledLog(b, n)
				srv := httptest.NewServer(tl)

				b.StartTimer()
				drainTestLog(b, tl, srv.URL, srv.Client(), workers)
				b.StopTimer()

				srv.Close()
			}

			b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "entries/s")
		})
	}
}
