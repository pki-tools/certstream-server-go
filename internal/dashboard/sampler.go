package dashboard

import (
	"context"
	"log"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// pruneInterval is how often expired samples are swept. Retention itself is
// configurable; the sweep cadence does not need to be.
const pruneInterval = time.Hour

// StartSampler begins periodically snapshotting server and log state into the store.
// It samples once immediately so a freshly started dashboard is not empty, then
// every `interval` until ctx is cancelled.
func StartSampler(ctx context.Context, store *Store, interval, retention time.Duration) {
	go func() {
		if err := store.Prune(retention); err != nil {
			log.Printf("dashboard: initial prune failed: %v\n", err)
		}

		collect(store)

		sampleTicker := time.NewTicker(interval)
		defer sampleTicker.Stop()

		pruneTicker := time.NewTicker(pruneInterval)
		defer pruneTicker.Stop()

		for {
			select {
			case <-sampleTicker.C:
				collect(store)
			case <-pruneTicker.C:
				if err := store.Prune(retention); err != nil {
					log.Printf("dashboard: prune failed: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// collect builds a Sample from current server state and writes it to the store.
func collect(store *Store) {
	statuses := certificatetransparency.GetLogStatuses()

	sample := Sample{
		Certs:         certificatetransparency.GetProcessedCerts(),
		Precerts:      certificatetransparency.GetProcessedPrecerts(),
		ClientsFull:   web.ClientHandler.ClientFullCount(),
		ClientsLite:   web.ClientHandler.ClientLiteCount(),
		ClientsDomain: web.ClientHandler.ClientDomainsCount(),
		LogsTotal:     len(statuses),
		Logs:          make([]LogSample, 0, len(statuses)),
	}

	for _, st := range statuses {
		// A log with no tree size yet has never been successfully polled, so it
		// counts as neither live nor behind.
		if st.TreeSize > 0 {
			if st.Behind == 0 {
				sample.LogsLive++
			} else {
				sample.LogsBehind++
			}
		}

		sample.TotalBehind += st.Behind

		sample.Logs = append(sample.Logs, LogSample{
			URL:          st.URL,
			CurrentIndex: st.CurrentIndex,
			TreeSize:     st.TreeSize,
			Behind:       st.Behind,
			Rate:         st.RatePerSec,
		})
	}

	if err := store.Insert(time.Now(), sample); err != nil {
		log.Printf("dashboard: could not write sample: %v\n", err)
	}
}
