package certificatetransparency

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/mod/sumdb/tlog"
)

// tiledPollInterval is how long a caught-up tiled log waits before re-checking
// its checkpoint. It does not bound throughput: a log that is behind fetches
// batches back-to-back without waiting.
const tiledPollInterval = 30 * time.Second

// tileWidth is the number of entries in a full tile: 2^TileHeight with the
// TileHeight of 8 fixed by c2sp.org/tlog-tiles. Defined here rather than
// imported so this package does not take a direct dependency on torchwood for
// one constant the spec pins.
const tileWidth = 256

// partialTileGrace is how long the tree must have been static before the
// trailing partial tile is requested anyway. Long enough that an active log
// never asks for one, short enough that a stalled log's last entries are not
// held back for long.
const partialTileGrace = 15 * time.Minute

// tiledWorker processes a single tiled (Static CT API) log.
type tiledWorker struct {
	name          string
	operatorName  string
	monitoringURL string
	publicKey     crypto.PublicKey
	entryChan     chan models.Entry
	ctIndex       int64
	// tree and treeSize cache the last verified checkpoint so consecutive
	// batches can be drained without re-fetching it each time.
	tree     tlog.Tree
	treeSize int64
	// treeGrewAt is when treeSize last increased, used to decide whether the
	// trailing partial tile is worth requesting. See drainBatch.
	treeGrewAt time.Time
	mu         sync.Mutex
	running    bool
	cancel     context.CancelFunc
}

// startDownloadingCerts starts downloading certificates from the tiled CT log. This method is blocking.
func (tw *tiledWorker) startDownloadingCerts(ctx context.Context) {
	ctx, tw.cancel = context.WithCancel(ctx)

	log.Printf("Initializing tiled worker for CT log: %s\n", tw.monitoringURL)
	defer log.Printf("Stopping tiled worker for CT log: %s\n", tw.monitoringURL)

	tw.mu.Lock()
	if tw.running {
		log.Printf("Tiled worker for '%s' already running\n", tw.monitoringURL)
		tw.mu.Unlock()
		return
	}

	tw.running = true
	defer func() { tw.running = false }()
	tw.mu.Unlock()

	normURL := normalizeCtlogURL(tw.monitoringURL)

	for {
		// A paused or stopped log waits here, making no requests, until it is
		// resumed. See logcontrol.go.
		if !waitWhileHeld(ctx, normURL) {
			return
		}

		workerErr := tw.runWorker(ctx)
		if workerErr != nil {
			if strings.Contains(workerErr.Error(), "no such host") {
				log.Printf("Tiled worker for '%s' failed to resolve host: %s\n", tw.monitoringURL, workerErr)
				RecordError(tw.monitoringURL, tw.name, ErrCatConnection, workerErr.Error())
				return
			}
			log.Printf("Tiled worker for '%s' failed with error: %s\n", tw.monitoringURL, workerErr)
			RecordError(tw.monitoringURL, tw.name, ErrCatOther, workerErr.Error())
		}

		// Check if the context was cancelled
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(5 * time.Second)
			continue
		}
	}
}

func (tw *tiledWorker) stop() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.cancel()
}

// runWorker runs a single worker for a tiled CT log. This method is blocking.
func (tw *tiledWorker) runWorker(ctx context.Context) error {
	hc := NewRateLimitedClient(tw.monitoringURL, tw.name, 30*time.Second)

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: tw.monitoringURL,
		PublicKey:        tw.publicKey,
		HTTPClient:       hc,
		UserAgent:        userAgent,
		Timeout:          5 * time.Minute,
	})
	if err != nil {
		log.Printf("Error creating sunlight client: %s\n", err)
		RecordError(tw.monitoringURL, tw.name, ErrCatConnection, err.Error())
		return fmt.Errorf("failed to create sunlight client: %w", err)
	}

	// Get the current checkpoint to know the tree size
	checkpoint, _, err := client.Checkpoint(ctx)
	if err != nil {
		log.Printf("Could not get checkpoint for '%s': %s\n", tw.monitoringURL, err)
		RecordError(tw.monitoringURL, tw.name, ErrCatCheckpoint, err.Error())
		return fmt.Errorf("failed to get checkpoint: %w", err)
	}

	treeSize := checkpoint.N

	// Seed the cache from the checkpoint just fetched, so the first batch can be
	// drained without asking for it again.
	tw.tree = checkpoint.Tree
	tw.treeSize = treeSize
	tw.treeGrewAt = time.Now()

	// If recovery is not enabled, start from the current tree size
	recoveryEnabled := config.AppConfig.General.Recovery.Enabled
	startAtHead := config.AppConfig.General.Recovery.StartAtHead
	if !recoveryEnabled {
		tw.ctIndex = treeSize
		log.Printf("Starting tiled log '%s' from tree size %d (skipping past entries)\n", tw.monitoringURL, tw.ctIndex)
		// See worker.runWorker: publish the position now, or the log stays
		// recorded at index 0 until its first certificate is processed.
		recordStartPosition(normalizeCtlogURL(tw.monitoringURL), uint64(tw.ctIndex))
	} else if startAtHead && tw.ctIndex == 0 {
		tw.ctIndex = treeSize
		log.Printf("No saved index for tiled log '%s', starting from current tree size %d (start_at_head)\n", tw.monitoringURL, tw.ctIndex)
		recordStartPosition(normalizeCtlogURL(tw.monitoringURL), uint64(tw.ctIndex))
	} else {
		log.Printf("Starting tiled log '%s' from saved index %d (tree size: %d)\n", tw.monitoringURL, tw.ctIndex, treeSize)

		if tw.ctIndex == 0 {
			// See the equivalent branch in worker.runWorker: this is a cold start
			// backfilling the whole log, not an inability to keep up.
			RecordError(tw.monitoringURL, tw.name, ErrCatBackfill,
				"no saved index for this log, so it is backfilling from index 0 - this is a cold start, not a throughput problem. Set recovery.start_at_head: true to begin at the current checkpoint instead")
		}
	}

	// A log that is behind drains batches back-to-back; only a caught-up log
	// waits for the poll interval.
	ticker := time.NewTicker(tiledPollInterval)
	defer ticker.Stop()

	normURL := normalizeCtlogURL(tw.monitoringURL)

	for {
		// Held here, keeping the client and its checkpoint, while paused or
		// stopped; see logcontrol.go.
		if !waitWhileHeld(ctx, normURL) {
			return nil
		}

		fetchCtx, cancelFetch := heldContext(ctx, normURL)
		caughtUp, drainErr := tw.drainBatch(fetchCtx, ctx, client)
		cancelFetch()

		if drainErr != nil {
			return drainErr
		}

		if ctx.Err() != nil {
			return nil
		}

		if !caughtUp {
			// More entries are already available — fetch the next batch immediately
			// instead of sleeping, otherwise throughput would be capped at
			// tiled_batch_size per poll interval no matter how far behind we are.
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// drainBatch fetches at most one batch of entries, reporting whether the log has
// caught up with the latest checkpoint. Batching bounds the work done per call so
// the checkpoint is refreshed periodically on a fast-moving log; it deliberately
// does not bound throughput.
//
// fetchCtx bounds fetching: cancelling it - when the log is paused or stopped -
// stops the iterator and dispatch. ctx is the worker's lifetime: entries
// already handed to the parsing pool are finished on it, because ctIndex has
// already moved past them and abandoning them would lose them for good.
func (tw *tiledWorker) drainBatch(fetchCtx, ctx context.Context, client *sunlight.Client) (caughtUp bool, err error) {
	// Reuse the last checkpoint while it still has entries we have not consumed.
	// Re-fetching one per batch would multiply checkpoint traffic on a log that
	// is far behind, and would pull every tile request up against the moment a
	// checkpoint is published, when its tiles may not have propagated yet.
	//
	// The condition is "no full tile left to read", not "nothing left to read".
	// Since this worker deliberately stops short of the trailing partial tile
	// (see below), waiting for treeSize to be fully consumed would mean never
	// refreshing the checkpoint again on a log whose last tile is partial: the
	// tree would appear frozen, treeGrewAt would never advance, and the log
	// would stall at that index.
	if !hasFullTileToRead(tw.ctIndex, tw.treeSize) {
		checkpoint, _, cpErr := client.Checkpoint(fetchCtx)
		if cpErr != nil {
			if fetchCtx.Err() != nil {
				// Cut short by a pause or shutdown, not a fault.
				return false, nil
			}

			log.Printf("Could not get checkpoint for '%s': %s\n", tw.monitoringURL, cpErr)
			RecordError(tw.monitoringURL, tw.name, ErrCatCheckpoint, cpErr.Error())
			// Report caught-up so the caller backs off to the ticker rather than
			// spinning on a failing checkpoint endpoint.
			return true, nil
		}

		tw.tree = checkpoint.Tree

		if checkpoint.N > tw.treeSize {
			tw.treeGrewAt = time.Now()
		}

		tw.treeSize = checkpoint.N
	}

	if tw.treeSize <= tw.ctIndex {
		return true, nil
	}

	// Steady state on a tiled log: every full data tile has been drained and
	// only the trailing partial tile is left.
	//
	// torchwood deliberately skips the trailing partial tile while there is a
	// full tile to read, but once the consumed index and the tree size fall in
	// the same tile it does request it (tlogclient.go: "if top-base == 0 { top
	// = tree.N }"). Logs that do not serve partial tiles answer 404, every
	// poll, indefinitely - which is what produced a continuous stream of
	// "tile not published yet" notes.
	//
	// Those entries are not lost by waiting: they arrive as soon as the tile
	// fills and becomes a full tile. So skip the request and wait for the tree
	// to grow, which also removes one pointless HTTP request per log per poll.
	if skipTrailingPartialTile(tw.ctIndex, tw.treeSize, tw.treeGrewAt, time.Now()) {
		return true, nil
	}

	// The iterator is consumed to the end rather than cut off after a fixed
	// number of entries.
	//
	// torchwood's Entries downloads up to 50 data tiles per window and keeps
	// them only for the life of the iterator. This loop used to break after
	// tiled_batch_size entries (default 500, about two tiles), discarding the
	// rest of the window, and the next call downloaded the same window again:
	// every data tile was fetched roughly 20 times over, each time decompressed,
	// decrypted and hash-verified. On a tiled log that was behind, that
	// redundant work cost far more CPU than parsing the certificates.
	//
	// The cap dated from when a tiled log handled one batch per poll interval.
	// Since batches are drained back-to-back it bounded nothing, and the window
	// is already bounded by torchwood, so running the iterator out is both
	// cheaper and no less responsive to cancellation: every send below selects
	// on ctx, and the iterator checks it between entries.
	batchCount := 0

	// Certificates are parsed by a pool of num_workers goroutines, as on the
	// RFC 6962 path. They used to be parsed inline on this goroutine, so a
	// backlogged tiled log could never use more than one core however many
	// the machine had - num_workers did not apply to tiled logs at all.
	//
	// The iterator itself stays here: it is not safe to share, and the work
	// it does per entry (splitting the tile and hash-checking the leaf) is a
	// fraction of parsing the certificate. Each yielded entry is freshly
	// allocated over tile data that is never reused, so workers may hold it
	// after the iterator moves on.
	//
	// ctIndex advances as entries are handed off. All handed-off entries are
	// finished before drainBatch returns, so at every return ctIndex again
	// means "processed up to here" - unless ctx was cancelled, when the worker
	// is stopping anyway.
	workers := config.AppConfig.General.Scanner.NumWorkers
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan tiledJob, workers*32)

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				tw.processTiledEntry(ctx, job.index, job.entry)
			}
		}()
	}

	cancelled := false

dispatch:
	for index, entry := range client.Entries(fetchCtx, tw.tree, tw.ctIndex) {
		if entry == nil {
			continue
		}

		select {
		case jobs <- tiledJob{index: index, entry: entry}:
		case <-fetchCtx.Done():
			cancelled = true
			break dispatch
		}

		tw.ctIndex = index + 1
		batchCount++
	}

	close(jobs)
	wg.Wait()

	if cancelled || fetchCtx.Err() != nil {
		return false, nil
	}

	if iterErr := client.Err(); iterErr != nil {
		if isTileNotYetPublished(iterErr) {
			// The signed checkpoint is ahead of the tiles actually being served.
			// Tearing the worker down would drop the client's tile cache and
			// re-fetch the checkpoint over a condition that clears on its own,
			// so keep any progress made and retry on the next tick instead.
			note := "tile not published yet for the current checkpoint, retrying: " + iterErr.Error()
			if isPartialTile(iterErr) {
				// Permitted and permanent, not a fault: the log serves only full
				// tiles. Say so, so this is not read as the log falling behind.
				note = "log does not serve partial tiles; the trailing " +
					"entries will arrive once the tile fills: " + iterErr.Error()
			}

			RecordErrorThrottled("tile404:"+tw.monitoringURL, tileNoteInterval,
				tw.monitoringURL, tw.name, ErrCatTile, note)

			// Force a fresh checkpoint next time; the current one outran its data.
			tw.treeSize = tw.ctIndex

			return true, nil
		}

		log.Printf("Error during tiled log iteration for '%s': %s\n", tw.monitoringURL, iterErr)
		RecordError(tw.monitoringURL, tw.name, ErrCatScan, iterErr.Error())

		return false, iterErr
	}

	if batchCount == 0 {
		// The checkpoint claims there is more, but the iterator produced nothing.
		// Reporting "behind" here would hot-loop on the checkpoint endpoint, so
		// back off to the ticker and retry on the next tick.
		return true, nil
	}

	return tw.ctIndex >= tw.treeSize, nil
}

// tileNoteInterval throttles tile-unavailable notes per log, so a log whose
// tiles lag its checkpoint cannot evict everything else from the error window.
const tileNoteInterval = 5 * time.Minute

// isTileNotYetPublished reports whether err is a 404 from fetching a tile.
//
// Static CT logs sign and publish a checkpoint before every data tile behind it
// is necessarily served by their CDN, so a tile covered by the advertised tree
// size can briefly return 404. torchwood retries 429 and 5xx internally but
// treats any other non-200 as fatal, so this has to be recognised here. Its
// error is unstructured, hence matching on the documented format
// ("<path>: unexpected status code <code>").
func isTileNotYetPublished(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()

	return strings.Contains(msg, "unexpected status code 404") && strings.Contains(msg, "tile/")
}

// hasFullTileToRead reports whether at least one complete tile of unconsumed
// entries is available. When it is false the only thing left is the trailing
// partial tile, which both drives the checkpoint refresh above and the decision
// in skipTrailingPartialTile below.
func hasFullTileToRead(ctIndex, treeSize int64) bool {
	return ctIndex/tileWidth != treeSize/tileWidth && treeSize > ctIndex
}

// skipTrailingPartialTile reports whether the only thing left to read is the
// trailing partial tile, and the tree is still growing fast enough that waiting
// for it to fill is better than requesting a tile the log may not serve.
//
// Returning false once the tree has been static for partialTileGrace is what
// keeps a slow or retired log's final entries from being stranded forever.
func skipTrailingPartialTile(ctIndex, treeSize int64, treeGrewAt, now time.Time) bool {
	if hasFullTileToRead(ctIndex, treeSize) {
		// torchwood will read the full tile and stop at the boundary without
		// touching a partial tile.
		return false
	}

	return now.Sub(treeGrewAt) < partialTileGrace
}

// isPartialTile reports whether a tile path refers to a partial tile, which
// c2sp.org/tlog-tiles spells "<N>.p/<width>".
//
// This separates two conditions that produce an identical-looking 404. A full
// tile 404 means the log's checkpoint has outrun its own CDN - transient, but
// worth seeing. A partial tile 404 means the log simply does not serve partial
// tiles, which is permitted and permanent, and says nothing is wrong.
func isPartialTile(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), ".p/")
}

// tiledJob is one verified tile entry awaiting parsing.
type tiledJob struct {
	index int64
	entry *sunlight.LogEntry
}

// processTiledEntry parses one entry and hands it to the pipeline. It runs on
// drainBatch's worker pool, so it may only read the worker's configuration.
func (tw *tiledWorker) processTiledEntry(ctx context.Context, index int64, entry *sunlight.LogEntry) {
	certstreamEntry, parseErr := tw.parseTiledEntry(entry, index)
	if parseErr != nil {
		log.Printf("Error parsing tiled entry at index %d: %s\n", index, parseErr)
		RecordError(tw.monitoringURL, tw.name, ErrCatParse, fmt.Sprintf("index %d: %s", index, parseErr))

		return
	}

	// Context-aware send so a full channel can't freeze this goroutine and
	// prevent context cancellation from propagating.
	select {
	case tw.entryChan <- certstreamEntry:
	case <-ctx.Done():
		return
	}

	if entry.IsPrecert {
		atomic.AddInt64(&processedPrecerts, 1)
	} else {
		atomic.AddInt64(&processedCerts, 1)
	}
}

// parseTiledEntry converts a sunlight.LogEntry to a models.Entry.
func (tw *tiledWorker) parseTiledEntry(entry *sunlight.LogEntry, index int64) (models.Entry, error) {
	if entry == nil {
		return models.Entry{}, errors.New("tiled entry is nil")
	}

	// Parse the certificate
	var cert *x509.Certificate
	var rawData []byte
	var isPrecert bool
	var err error

	// parseLeafCertificate handles both parsers, and non-fatal errors; see it.
	if entry.IsPrecert {
		// For precerts, entry.Certificate holds the raw TBS certificate bytes,
		// not a full DER certificate.
		cert, err = parseLeafCertificate(entry.Certificate, true)
		if err != nil {
			return models.Entry{}, fmt.Errorf("failed to parse precert TBS certificate: %w", err)
		}

		rawData = entry.PreCertificate
		isPrecert = true
	} else {
		cert, err = parseLeafCertificate(entry.Certificate, false)
		if err != nil {
			return models.Entry{}, fmt.Errorf("failed to parse certificate: %w", err)
		}

		rawData = entry.Certificate
		isPrecert = false
	}

	data, err := tw.buildDataFromCert(cert, index, isPrecert, rawData)
	if err != nil {
		return models.Entry{}, err
	}

	certstreamEntry := models.Entry{
		Data:        data,
		MessageType: "certificate_update",
	}
	if isPrecert {
		certstreamEntry.Data.UpdateType = "PrecertLogEntry"
	} else {
		certstreamEntry.Data.UpdateType = "X509LogEntry"
	}

	return certstreamEntry, nil
}

// buildDataFromCert creates a models.Data structure from an x509 certificate.
func (tw *tiledWorker) buildDataFromCert(cert *x509.Certificate, index int64, isPrecert bool, rawData []byte) (models.Data, error) {
	// Build cert link (note: tiled logs don't have the same get-entries endpoint, so we just use the monitoring URL)
	certLink := fmt.Sprintf("%s (index: %d)", tw.monitoringURL, index)

	// Create main data structure
	data := models.Data{
		CertIndex: uint64(index),
		CertLink:  certLink,
		Seen:      float64(time.Now().UnixMilli()) / 1_000,
		Source: models.Source{
			Name:          tw.name,
			URL:           tw.monitoringURL,
			Operator:      tw.operatorName,
			NormalizedURL: normalizeCtlogURL(tw.monitoringURL),
		},
	}

	// Identified by the published DER - for a precertificate the submitted
	// precertificate, not the TBSCertificate that was parsed. See
	// leafCertWithIdentity.
	data.LeafCert = leafCertWithIdentity(*cert, rawData)

	if isPrecert {
		data.LeafCert.Extensions.CTLPoisonByte = true
	}

	// Note: Chain parsing is not available for tiled logs in the same way
	// The ChainFingerprints field exists but we'd need to fetch the actual certs
	data.Chain = []models.LeafCert{}

	return data, nil
}
