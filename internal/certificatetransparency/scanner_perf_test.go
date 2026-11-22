package certificatetransparency

import (
	"testing"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
)

func makeLeafEntry(tb testing.TB, leafDER []byte, chain ...[]byte) *ct.LeafEntry {
	tb.Helper()

	mtl := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: 1700000000000,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: leafDER},
		},
	}

	leafInput, err := cttls.Marshal(mtl)
	if err != nil {
		tb.Fatal(err)
	}

	cc := ct.CertificateChain{}
	for _, c := range chain {
		cc.Entries = append(cc.Entries, ct.ASN1Cert{Data: c})
	}

	extra, err := cttls.Marshal(cc)
	if err != nil {
		tb.Fatal(err)
	}

	return &ct.LeafEntry{LeafInput: leafInput, ExtraData: extra}
}

// BenchmarkScannerPath measures what one RFC 6962 entry really costs, from the
// leaf bytes the fetcher returns to a finished models.Data.
//
// Benchmarking parseData alone understates it, because the scanner does work of
// its own before calling us. The two cases mirror the scanner's two branches:
//
//   - matcher_double_parse is scanner.processMatcherEntry, taken for a
//     scanner.Matcher such as MatchAll. It runs ToLogEntry (a full x509 parse)
//     to evaluate the matcher, then hands the callback the raw entry, which
//     parseData parses again.
//   - leaf_matcher is scanner.processMatcherLeafEntry, taken for a
//     scanner.LeafMatcher, which parses nothing itself.
//
// Production now uses neither: scanEntries drives the fetcher directly and
// decodes with decodeLeafEntry. BenchmarkLeafDecode measures that path.
func BenchmarkScannerPath(b *testing.B) {
	leaf := makeDER(b, "www.example.com", []string{"www.example.com", "example.com", "cdn.example.com"}, false)
	inter := makeDER(b, "Example Intermediate CA", nil, true)
	le := makeLeafEntry(b, leaf, inter)

	b.Run("matcher_double_parse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rle, err := ct.RawLogEntryFromLeaf(int64(i), le)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := rle.ToLogEntry(); err != nil { // scanner's discarded parse
				b.Fatal(err)
			}
			if _, err := parseData(rle, "Op", "log", "https://ct.example.com/log"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("leaf_matcher", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rle, err := ct.RawLogEntryFromLeaf(int64(i), le)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := parseData(rle, "Op", "log", "https://ct.example.com/log"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLeafDecode compares the reflection-based reference decoder with the
// cryptobyte one on the same entry, and shows the end-to-end effect.
func BenchmarkLeafDecode(b *testing.B) {
	leaf := makeDER(b, "www.example.com", []string{"www.example.com", "example.com", "cdn.example.com"}, false)
	inter := makeDER(b, "Example Intermediate CA", nil, true)
	le := makeLeafEntry(b, leaf, inter)

	b.Run("decode_reference", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ct.RawLogEntryFromLeaf(int64(i), le); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("decode_cryptobyte", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := decodeLeafEntry(int64(i), le); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("end_to_end_cryptobyte", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rle, err := decodeLeafEntry(int64(i), le)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := parseData(rle, "Op", "log", "https://ct.example.com/log"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
