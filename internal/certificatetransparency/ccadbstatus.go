package certificatetransparency

import (
	"sort"
	"sync"
	"time"
)

// CCADBOwnerSnapshot is an exported snapshot of one CA owner's entries from CCADB.
type CCADBOwnerSnapshot struct {
	Owner     string
	CACount   int
	FirstSeen time.Time
}

// CCADBStatusSnapshot is the top-level snapshot returned to the page handler.
type CCADBStatusSnapshot struct {
	LastRefreshed time.Time
	TotalCAs      int
	TotalOwners   int
	Owners        []CCADBOwnerSnapshot
}

// ccadbEntryMeta tracks metadata per SKI key for change-detection.
type ccadbEntryMeta struct {
	owner     string
	firstSeen time.Time
}

type ccadbRegistryT struct {
	mu            sync.RWMutex
	entries       map[string]ccadbEntryMeta // key: SKI hex
	lastRefreshed time.Time
}

var ccadbReg = &ccadbRegistryT{
	entries: make(map[string]ccadbEntryMeta),
}

// UpdateCAOwners merges a fresh CCADB download into the registry, preserving
// firstSeen for entries that already exist, and records the refresh timestamp.
func UpdateCAOwners(newOwners map[string]string) {
	now := time.Now()

	ccadbReg.mu.Lock()
	defer ccadbReg.mu.Unlock()

	for ski, owner := range newOwners {
		if existing, ok := ccadbReg.entries[ski]; ok {
			// Keep firstSeen; update owner if it changed.
			if existing.owner != owner {
				ccadbReg.entries[ski] = ccadbEntryMeta{owner: owner, firstSeen: existing.firstSeen}
			}
		} else {
			ccadbReg.entries[ski] = ccadbEntryMeta{owner: owner, firstSeen: now}
		}
	}

	ccadbReg.lastRefreshed = now
}

// GetCCADBStatus returns an aggregated snapshot grouped by CA Owner, sorted
// alphabetically by owner name.
func GetCCADBStatus() CCADBStatusSnapshot {
	ccadbReg.mu.RLock()
	defer ccadbReg.mu.RUnlock()

	// Aggregate by owner: track count and earliest firstSeen.
	type ownerAgg struct {
		count     int
		firstSeen time.Time
	}
	agg := make(map[string]*ownerAgg, 64)

	for _, meta := range ccadbReg.entries {
		a, ok := agg[meta.owner]
		if !ok {
			agg[meta.owner] = &ownerAgg{count: 1, firstSeen: meta.firstSeen}
		} else {
			a.count++
			if meta.firstSeen.Before(a.firstSeen) {
				a.firstSeen = meta.firstSeen
			}
		}
	}

	owners := make([]CCADBOwnerSnapshot, 0, len(agg))
	for owner, a := range agg {
		owners = append(owners, CCADBOwnerSnapshot{
			Owner:     owner,
			CACount:   a.count,
			FirstSeen: a.firstSeen,
		})
	}

	sort.Slice(owners, func(i, j int) bool {
		return owners[i].Owner < owners[j].Owner
	})

	return CCADBStatusSnapshot{
		LastRefreshed: ccadbReg.lastRefreshed,
		TotalCAs:      len(ccadbReg.entries),
		TotalOwners:   len(owners),
		Owners:        owners,
	}
}
