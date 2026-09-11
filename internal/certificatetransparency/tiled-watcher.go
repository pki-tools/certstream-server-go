package certificatetransparency

import (
	"context"
	"crypto"
	"encoding/base64"
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
)

// tiledPollInterval is how long a caught-up tiled log waits before re-checking
// its checkpoint. It does not bound throughput: a log that is behind fetches
// batches back-to-back without waiting.
const tiledPollInterval = 30 * time.Second

// tiledWorker processes a single tiled (Static CT API) log.
type tiledWorker struct {
	name          string
	operatorName  string
	monitoringURL string
	publicKey     crypto.PublicKey
	entryChan     chan models.Entry
	ctIndex       int64
	mu            sync.Mutex
	running       bool
	cancel        context.CancelFunc
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

	for {
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

	// If recovery is not enabled, start from the current tree size
	recoveryEnabled := config.AppConfig.General.Recovery.Enabled
	startAtHead := config.AppConfig.General.Recovery.StartAtHead
	if !recoveryEnabled {
		tw.ctIndex = treeSize
		log.Printf("Starting tiled log '%s' from tree size %d (skipping past entries)\n", tw.monitoringURL, tw.ctIndex)
	} else if startAtHead && tw.ctIndex == 0 {
		tw.ctIndex = treeSize
		log.Printf("No saved index for tiled log '%s', starting from current tree size %d (start_at_head)\n", tw.monitoringURL, tw.ctIndex)
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

	for {
		caughtUp, drainErr := tw.drainBatch(ctx, client)
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
func (tw *tiledWorker) drainBatch(ctx context.Context, client *sunlight.Client) (caughtUp bool, err error) {
	checkpoint, _, err := client.Checkpoint(ctx)
	if err != nil {
		log.Printf("Could not get checkpoint for '%s': %s\n", tw.monitoringURL, err)
		RecordError(tw.monitoringURL, tw.name, ErrCatCheckpoint, err.Error())
		// Report caught-up so the caller backs off to the ticker rather than
		// spinning on a failing checkpoint endpoint.
		return true, nil
	}

	if checkpoint.N <= tw.ctIndex {
		return true, nil
	}

	batchLimit := config.AppConfig.General.Scanner.TiledBatchSize
	if batchLimit <= 0 {
		batchLimit = 500
	}

	batchCount := 0

	for index, entry := range client.Entries(ctx, checkpoint.Tree, tw.ctIndex) {
		if entry == nil {
			continue
		}

		certstreamEntry, parseErr := tw.parseTiledEntry(entry, index)
		if parseErr != nil {
			log.Printf("Error parsing tiled entry at index %d: %s\n", index, parseErr)
			RecordError(tw.monitoringURL, tw.name, ErrCatParse, fmt.Sprintf("index %d: %s", index, parseErr))
			continue
		}

		// Context-aware send so a full channel can't freeze this goroutine and
		// prevent context cancellation from propagating.
		select {
		case tw.entryChan <- certstreamEntry:
		case <-ctx.Done():
			return false, nil
		}

		tw.ctIndex = index + 1

		if entry.IsPrecert {
			atomic.AddInt64(&processedPrecerts, 1)
		} else {
			atomic.AddInt64(&processedCerts, 1)
		}

		batchCount++
		if batchCount >= batchLimit {
			break
		}
	}

	if iterErr := client.Err(); iterErr != nil {
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

	return tw.ctIndex >= checkpoint.N, nil
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

	if entry.IsPrecert {
		// For precerts, entry.Certificate holds the raw TBS certificate bytes,
		// not a full DER certificate, so ParseTBSCertificate must be used.
		cert, err = x509.ParseTBSCertificate(entry.Certificate)
		if err != nil {
			return models.Entry{}, fmt.Errorf("failed to parse precert TBS certificate: %w", err)
		}
		rawData = entry.PreCertificate
		isPrecert = true
	} else {
		cert, err = x509.ParseCertificate(entry.Certificate)
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

	// Convert certificate to LeafCert
	data.LeafCert = leafCertFromX509cert(*cert)

	// If it's a precert, recalculate hashes and set poison byte
	if isPrecert {
		calculatedHash := calculateSHA1(rawData)
		data.LeafCert.Fingerprint = calculatedHash
		data.LeafCert.SHA1 = calculatedHash
		data.LeafCert.SHA256 = calculateSHA256(rawData)
		data.LeafCert.Extensions.CTLPoisonByte = true
	}

	// Set AsDER
	certAsDER := base64.StdEncoding.EncodeToString(rawData)
	data.LeafCert.AsDER = certAsDER

	// Note: Chain parsing is not available for tiled logs in the same way
	// The ChainFingerprints field exists but we'd need to fetch the actual certs
	data.Chain = []models.LeafCert{}

	return data, nil
}
