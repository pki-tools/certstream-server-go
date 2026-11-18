package certificatetransparency

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	ct "github.com/google/certificate-transparency-go"
)

func makeDER(tb testing.TB, cn string, sans []string, isCA bool) []byte {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		DNSNames:              sans,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}

	return der
}

// BenchmarkParseData measures the per-entry cost of the parsing step that runs
// in each log's matcher goroutines: leaf parse, chain parse, hashes, base64.
func BenchmarkParseData(b *testing.B) {
	leaf := makeDER(b, "www.example.com", []string{"www.example.com", "example.com", "cdn.example.com"}, false)
	inter := makeDER(b, "Example Intermediate CA", nil, true)
	root := makeDER(b, "Example Root CA", nil, true)

	entry := &ct.RawLogEntry{
		Index: 123456,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: uint64(time.Now().UnixMilli()),
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: leaf},
			},
		},
		Cert:  ct.ASN1Cert{Data: leaf},
		Chain: []ct.ASN1Cert{{Data: inter}, {Data: root}},
	}

	// sanity: must actually parse
	if _, err := parseData(entry, "Example", "example-log", "https://ct.example.com/log"); err != nil {
		b.Fatalf("parseData failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := parseData(entry, "Example", "example-log", "https://ct.example.com/log"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseDataNoChain isolates the leaf-only cost, so the share spent
// re-parsing the (always identical) issuer chain is visible.
func BenchmarkParseDataNoChain(b *testing.B) {
	leaf := makeDER(b, "www.example.com", []string{"www.example.com", "example.com", "cdn.example.com"}, false)

	entry := &ct.RawLogEntry{
		Index: 123456,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: uint64(time.Now().UnixMilli()),
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: leaf},
			},
		},
		Cert: ct.ASN1Cert{Data: leaf},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := parseData(entry, "Example", "example-log", "https://ct.example.com/log"); err != nil {
			b.Fatal(err)
		}
	}
}

// makeEntry builds a RawLogEntry for the given leaf and chain DER.
func makeEntry(leaf []byte, chain ...[]byte) *ct.RawLogEntry {
	asn1Chain := make([]ct.ASN1Cert, len(chain))
	for i, der := range chain {
		asn1Chain[i] = ct.ASN1Cert{Data: der}
	}

	return &ct.RawLogEntry{
		Index: 7,
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: 1700000000000,
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: leaf},
			},
		},
		Cert:  ct.ASN1Cert{Data: leaf},
		Chain: asn1Chain,
	}
}

// TestChainCacheMatchesFreshParse is the safety net for the issuer-chain cache:
// a cached chain entry must be indistinguishable from one parsed from scratch,
// and two different issuers must not be confused with each other.
func TestChainCacheMatchesFreshParse(t *testing.T) {
	resetChainCache()

	leaf := makeDER(t, "www.example.com", []string{"www.example.com"}, false)
	interA := makeDER(t, "Issuer A", nil, true)
	interB := makeDER(t, "Issuer B", nil, true)

	// First pass populates the cache, second pass must hit it.
	first, err := parseData(makeEntry(leaf, interA, interB), "Op", "log", "https://ct.example.com/log")
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}

	hitsBefore, _, _ := ChainCacheStats()

	second, err := parseData(makeEntry(leaf, interA, interB), "Op", "log", "https://ct.example.com/log")
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}

	hitsAfter, _, size := ChainCacheStats()
	if hitsAfter-hitsBefore != 2 {
		t.Errorf("cache hits on second parse = %d, want 2", hitsAfter-hitsBefore)
	}

	if size != 2 {
		t.Errorf("cache size = %d, want 2 (one per distinct issuer)", size)
	}

	firstJSON, _ := json.Marshal(first.Chain)
	secondJSON, _ := json.Marshal(second.Chain)

	if !bytes.Equal(firstJSON, secondJSON) {
		t.Errorf("cached chain differs from freshly parsed chain:\n fresh:  %s\n cached: %s", firstJSON, secondJSON)
	}

	// The two issuers must not have collapsed into one cache entry.
	if *second.Chain[0].Subject.CN == *second.Chain[1].Subject.CN {
		t.Errorf("distinct issuers returned the same subject: %q", *second.Chain[0].Subject.CN)
	}

	if cn := *second.Chain[0].Subject.CN; cn != "Issuer A" {
		t.Errorf("chain[0] CN = %q, want \"Issuer A\"", cn)
	}
}

// TestChainCacheEvictsAtCap checks the bound actually holds, so a flood of
// unique chains cannot grow the map without limit.
func TestChainCacheEvictsAtCap(t *testing.T) {
	resetChainCache()

	for i := 0; i < chainCacheMaxEntries+10; i++ {
		storeChainCert([]byte("issuer-"+strconv.Itoa(i)), models.LeafCert{})
	}

	_, _, size := ChainCacheStats()
	if size > chainCacheMaxEntries {
		t.Errorf("cache size = %d, want at most %d", size, chainCacheMaxEntries)
	}
}

// TestParseKeyTypeUsesDecodedKey pins the key-type strings after the switch to
// the already-decoded public key, for both of the common algorithms.
func TestParseKeyTypeUsesDecodedKey(t *testing.T) {
	t.Run("ECDSA", func(t *testing.T) {
		der := makeDER(t, "ecdsa.example.com", []string{"ecdsa.example.com"}, false)

		data, err := parseData(makeEntry(der), "Op", "log", "https://ct.example.com/log")
		if err != nil {
			t.Fatal(err)
		}

		if data.LeafCert.KeyType != "ECDSA256" {
			t.Errorf("KeyType = %q, want \"ECDSA256\"", data.LeafCert.KeyType)
		}
	})

	t.Run("RSA", func(t *testing.T) {
		der := makeRSADER(t, "rsa.example.com")

		data, err := parseData(makeEntry(der), "Op", "log", "https://ct.example.com/log")
		if err != nil {
			t.Fatal(err)
		}

		if data.LeafCert.KeyType != "RSA2048" {
			t.Errorf("KeyType = %q, want \"RSA2048\"", data.LeafCert.KeyType)
		}
	})
}

func resetChainCache() {
	chainCache.mu.Lock()
	chainCache.entries = make(map[string]models.LeafCert)
	chainCache.mu.Unlock()
}

func makeRSADER(tb testing.TB, cn string) []byte {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}

	return der
}
