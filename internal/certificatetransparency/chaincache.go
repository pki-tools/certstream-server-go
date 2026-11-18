package certificatetransparency

import (
	"sync"
	"sync/atomic"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

// Every log entry carries its issuer chain, and those issuer certificates are
// byte-identical across millions of entries: there are only a few hundred
// intermediates in use worldwide. Parsing them again for every entry dominates
// the per-entry CPU cost, because certificate-transparency-go's x509 package
// uses a reflection-based ASN.1 decoder.
//
// BenchmarkParseData measures 92.6 us/entry with a two-certificate chain and
// 40.0 us/entry for the leaf alone, so 57% of the parsing cost is re-parsing
// certificates we have already seen. Caching the converted result removes
// almost all of it.
//
// The cached models.LeafCert values are shared by reference (they contain
// pointers and slices) with every entry that carries the same issuer, so they
// must be treated as immutable once stored. Nothing downstream writes to chain
// entries - parseData only fills in the leaf's own fields, and JSON encoding
// only reads - but anything added later that mutates a chain element has to
// copy it first.
const chainCacheMaxEntries = 4096

var chainCache = struct {
	mu      sync.RWMutex
	entries map[string]models.LeafCert
}{entries: make(map[string]models.LeafCert, 512)}

var (
	chainCacheHits   atomic.Int64
	chainCacheMisses atomic.Int64
)

// lookupChainCert returns the converted form of a previously seen issuer
// certificate. The map is keyed by the raw DER bytes; Go compiles the
// map[string(byteSlice)] lookup without allocating the key.
func lookupChainCert(der []byte) (models.LeafCert, bool) {
	chainCache.mu.RLock()
	cert, ok := chainCache.entries[string(der)]
	chainCache.mu.RUnlock()

	if ok {
		chainCacheHits.Add(1)
	} else {
		chainCacheMisses.Add(1)
	}

	return cert, ok
}

// storeChainCert records a converted issuer certificate.
//
// The map is bounded. Legitimate traffic settles well below the cap, so hitting
// it means the keys are not the handful of real intermediates: dropping
// everything is better than growing without limit, and the cache refills from
// live traffic within seconds.
func storeChainCert(der []byte, cert models.LeafCert) {
	chainCache.mu.Lock()
	if len(chainCache.entries) >= chainCacheMaxEntries {
		chainCache.entries = make(map[string]models.LeafCert, 512)
	}

	chainCache.entries[string(der)] = cert
	chainCache.mu.Unlock()
}

// ChainCacheStats reports the issuer-chain cache's effectiveness. A hit ratio
// well below ~100% once the server is warm means entries are arriving with
// unusually varied chains, and the parsing cost per entry is correspondingly
// higher.
func ChainCacheStats() (hits, misses int64, size int) {
	chainCache.mu.RLock()
	size = len(chainCache.entries)
	chainCache.mu.RUnlock()

	return chainCacheHits.Load(), chainCacheMisses.Load(), size
}

// SeedChainCacheForTest primes the cache counters so page rendering can be
// exercised with a known hit ratio. Test-only.
func SeedChainCacheForTest(der []byte, hits, misses int64) {
	storeChainCert(der, models.LeafCert{})
	chainCacheHits.Store(hits)
	chainCacheMisses.Store(misses)
}
