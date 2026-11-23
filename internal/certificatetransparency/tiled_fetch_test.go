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

func newTestTiledLog(t *testing.T, n int64) *testTiledLog {
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

// TestTiledDrainFetchesEachTileOnce drains a tiled log that is far behind and
// counts data-tile downloads.
//
// torchwood's Entries iterator fetches up to 50 data tiles per window and
// caches them only for the life of that iterator. Breaking out of it after
// tiled_batch_size entries threw the rest of the window away, and the next
// call fetched it again - about 25 downloads of each tile at the default 500,
// and the decompression, TLS and hashing that come with them. That was the
// dominant CPU cost on a backlogged tiled log, far above certificate parsing.
func TestTiledDrainFetchesEachTileOnce(t *testing.T) {
	const tiles = 120 // more than two of torchwood's 50-tile windows
	const n = tiles * tileWidth

	prev := config.AppConfig.General.Scanner.TiledBatchSize
	config.AppConfig.General.Scanner.TiledBatchSize = 500 // the shipped default
	defer func() { config.AppConfig.General.Scanner.TiledBatchSize = prev }()

	tl := newTestTiledLog(t, n)

	srv := httptest.NewServer(tl)
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: srv.URL + "/",
		PublicKey:        &key.PublicKey,
		HTTPClient:       srv.Client(),
		UserAgent:        "certstream-server-go test (+https://example.com)",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tw := &tiledWorker{
		name:          "test-tiled",
		operatorName:  "Example",
		monitoringURL: srv.URL,
		entryChan:     make(chan models.Entry, 1024),
		tree:          tl.tree,
		treeSize:      tl.tree.N,
		treeGrewAt:    time.Now(),
	}

	// Drain the output as the certHandler would.
	go func() {
		for range tw.entryChan {
		}
	}()

	for calls := 0; tw.ctIndex < n; calls++ {
		if calls > 10_000 {
			t.Fatalf("no progress: ctIndex=%d of %d", tw.ctIndex, n)
		}

		if _, err := tw.drainBatch(ctx, client); err != nil {
			t.Fatalf("drainBatch: %v", err)
		}
	}

	close(tw.entryChan)

	total, distinct := tl.dataTileFetches()
	t.Logf("drained %d entries: %d data-tile downloads covering %d distinct tiles", n, total, distinct)

	if distinct != tiles {
		t.Fatalf("fetched %d distinct data tiles, want %d", distinct, tiles)
	}

	if total != tiles {
		t.Errorf("data tiles downloaded %d times for %d tiles (%.1fx); each should be fetched once",
			total, tiles, float64(total)/tiles)
	}
}
