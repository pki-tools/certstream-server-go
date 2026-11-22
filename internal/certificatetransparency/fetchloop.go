package certificatetransparency

import (
	"context"
	"fmt"
	"log"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/scanner"
)

// leafJob is one undecoded entry and its index in the log.
type leafJob struct {
	index int64
	entry ct.LeafEntry
}

// scanEntries fetches entries from an RFC 6962 log and hands each one, decoded,
// to the worker's callbacks. It replaces scanner.Scanner.Scan, which it mirrors
// - a scanner.Fetcher feeding numWorkers goroutines through a buffered channel
// - with two differences that are the reason it exists:
//
//   - Entries are decoded with decodeLeafEntry rather than
//     ct.RawLogEntryFromLeaf. The scanner calls the latter internally before
//     any callback runs, so its reflection-based TLS decoding could not be
//     avoided while using it. See leafdecode.go.
//   - No certificate is parsed here at all. The scanner parses every entry to
//     evaluate a scanner.Matcher, even scanner.MatchAll, then passes on the raw
//     entry so the callback parses it again. Here parseData parses it once.
//
// Measured as CPU time per entry, including garbage collection on other cores:
// 88 us with the scanner and MatchAll, 42 us with this loop.
//
// fetchCtx stops fetching; ctx is the worker's lifetime. Every batch the
// fetcher has already returned is handed to the workers in full even after
// fetchCtx is cancelled, as the scanner did, so a planned restart does not
// discard entries that were fetched but not yet queued. Only cancelling ctx
// abandons them, so shutdown cannot block on a full queue.
func (w *worker) scanEntries(ctx, fetchCtx context.Context, client scanner.LogClient, opts scanner.FetcherOptions, numWorkers, bufferSize int) error {
	if numWorkers < 1 {
		numWorkers = 1
	}

	if bufferSize < 0 {
		bufferSize = 0
	}

	jobs := make(chan leafJob, bufferSize)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				w.handleLeaf(job.index, &job.entry)
			}
		}()
	}

	fetcher := scanner.NewFetcher(client, &opts)

	err := fetcher.Run(fetchCtx, func(batch scanner.EntryBatch) {
		for i := range batch.Entries {
			select {
			case jobs <- leafJob{index: batch.Start + int64(i), entry: batch.Entries[i]}:
			case <-ctx.Done():
				return
			}
		}
	})

	close(jobs)
	wg.Wait()

	return err
}

// handleLeaf decodes one entry and dispatches it by type.
func (w *worker) handleLeaf(index int64, entry *ct.LeafEntry) {
	rawEntry, err := decodeLeafEntry(index, entry)
	if err != nil {
		// The scanner dropped these too, but logged them only at klog
		// verbosity; record them where they can be seen.
		msg := fmt.Sprintf("index %d: %s", index, err)
		log.Printf("Error decoding entry for '%s': %s\n", w.ctURL, msg)
		RecordError(w.ctURL, w.name, ErrCatParse, msg)

		return
	}

	switch rawEntry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		w.foundCertCallback(rawEntry)
	case ct.PrecertLogEntryType:
		w.foundPrecertCallback(rawEntry)
	}
}
