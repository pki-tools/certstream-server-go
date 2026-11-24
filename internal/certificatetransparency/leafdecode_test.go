package certificatetransparency

import (
	"fmt"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// referenceLeafEntry encodes an entry with certificate-transparency-go's own
// tls encoder, so the inputs to the differential tests are exactly what a log
// would serve rather than something hand-assembled to suit the new decoder.
func referenceLeafEntry(tb testing.TB, precert bool, ext []byte, leafDER []byte, chain ...[]byte) *ct.LeafEntry {
	tb.Helper()

	te := &ct.TimestampedEntry{Timestamp: 1700000000123, Extensions: ct.CTExtensions(ext)}

	certs := make([]ct.ASN1Cert, 0, len(chain))
	for _, c := range chain {
		certs = append(certs, ct.ASN1Cert{Data: c})
	}

	var extra []byte
	var err error

	if precert {
		// A precert leaf carries the TBSCertificate, not the whole certificate.
		// Using the whole certificate here would still decode, but would fail
		// as soon as anything parsed it.
		// ct-go's parser, the more permissive of the two, so fixtures the
		// standard library refuses can still be turned into precert entries.
		parsed, perr := ctx509.ParseCertificate(leafDER)
		if ctx509.IsFatal(perr) || parsed == nil {
			tb.Fatal(perr)
		}

		te.EntryType = ct.PrecertLogEntryType
		te.PrecertEntry = &ct.PreCert{TBSCertificate: parsed.RawTBSCertificate}
		copy(te.PrecertEntry.IssuerKeyHash[:], "0123456789abcdef0123456789abcdef")

		extra, err = cttls.Marshal(ct.PrecertChainEntry{
			PreCertificate:   ct.ASN1Cert{Data: append([]byte("precert:"), leafDER...)},
			CertificateChain: certs,
		})
	} else {
		te.EntryType = ct.X509LogEntryType
		te.X509Entry = &ct.ASN1Cert{Data: leafDER}

		extra, err = cttls.Marshal(ct.CertificateChain{Entries: certs})
	}

	if err != nil {
		tb.Fatal(err)
	}

	leafInput, err := cttls.Marshal(ct.MerkleTreeLeaf{
		Version:          ct.V1,
		LeafType:         ct.TimestampedEntryLeafType,
		TimestampedEntry: te,
	})
	if err != nil {
		tb.Fatal(err)
	}

	return &ct.LeafEntry{LeafInput: leafInput, ExtraData: extra}
}

// TestDecodeLeafEntryMatchesReference checks the decoder against
// ct.RawLogEntryFromLeaf on well-formed entries of every shape it handles:
// both entry types, chains of zero to three certificates, and with and without
// extensions. The results must be deeply equal, nil-versus-empty included.
func TestDecodeLeafEntryMatchesReference(t *testing.T) {
	leaf := makeDER(t, "www.example.com", []string{"www.example.com", "example.com"}, false)
	inter := makeDER(t, "Example Intermediate", nil, true)
	root := makeDER(t, "Example Root", nil, true)

	chains := [][][]byte{
		nil,
		{inter},
		{inter, root},
		{inter, root, inter},
	}

	extensions := [][]byte{nil, {0x00, 0x01, 0x02, 0x03}}

	for _, precert := range []bool{false, true} {
		for ci, chain := range chains {
			for ei, ext := range extensions {
				name := fmt.Sprintf("precert=%v/chain=%d/ext=%d", precert, ci, ei)

				t.Run(name, func(t *testing.T) {
					le := referenceLeafEntry(t, precert, ext, leaf, chain...)

					want, wantErr := ct.RawLogEntryFromLeaf(42, le)
					got, gotErr := decodeLeafEntry(42, le)

					if (wantErr == nil) != (gotErr == nil) {
						t.Fatalf("error mismatch: reference=%v decoder=%v", wantErr, gotErr)
					}

					if !reflect.DeepEqual(want, got) {
						t.Fatalf("decoded entry differs from reference\nreference: %#v\ndecoder:   %#v", want, got)
					}
				})
			}
		}
	}
}

// TestDecodeLeafEntryRejectsWhatReferenceRejects covers the malformed inputs
// most likely to diverge: truncation at every byte, trailing data, and types
// the decoder does not handle.
func TestDecodeLeafEntryRejectsWhatReferenceRejects(t *testing.T) {
	leaf := makeDER(t, "www.example.com", []string{"www.example.com"}, false)
	inter := makeDER(t, "Example Intermediate", nil, true)

	for _, precert := range []bool{false, true} {
		good := referenceLeafEntry(t, precert, nil, leaf, inter)

		// Every truncation of leaf_input and of extra_data.
		for n := 0; n < len(good.LeafInput); n++ {
			assertSameVerdict(t, fmt.Sprintf("precert=%v leaf_input[:%d]", precert, n),
				&ct.LeafEntry{LeafInput: good.LeafInput[:n], ExtraData: good.ExtraData})
		}

		for n := 0; n < len(good.ExtraData); n++ {
			assertSameVerdict(t, fmt.Sprintf("precert=%v extra_data[:%d]", precert, n),
				&ct.LeafEntry{LeafInput: good.LeafInput, ExtraData: good.ExtraData[:n]})
		}

		assertSameVerdict(t, fmt.Sprintf("precert=%v trailing leaf_input", precert),
			&ct.LeafEntry{LeafInput: append(append([]byte{}, good.LeafInput...), 0), ExtraData: good.ExtraData})

		assertSameVerdict(t, fmt.Sprintf("precert=%v trailing extra_data", precert),
			&ct.LeafEntry{LeafInput: good.LeafInput, ExtraData: append(append([]byte{}, good.ExtraData...), 0)})
	}

	// Zero-length certificates. Every ASN.1Cert is <1..2^24-1>, so a length of
	// zero must be rejected wherever one appears. Truncation never produces
	// this - the framing stays valid - so it needs constructing explicitly.
	zeroLenChain := []byte{0x00, 0x00, 0x03, 0x00, 0x00, 0x00} // list of one empty cert
	x509Entry := referenceLeafEntry(t, false, nil, leaf)
	assertSameVerdict(t, "x509 chain holding an empty cert",
		&ct.LeafEntry{LeafInput: x509Entry.LeafInput, ExtraData: zeroLenChain})

	emptyPrecert := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // empty pre_certificate, empty chain
	pcEntry := referenceLeafEntry(t, true, nil, leaf)
	assertSameVerdict(t, "precert with an empty pre_certificate",
		&ct.LeafEntry{LeafInput: pcEntry.LeafInput, ExtraData: emptyPrecert})

	// An x509 leaf whose certificate itself is zero-length: header (12 bytes),
	// a zero uint24 length, then empty extensions.
	emptyLeafCert := append(append([]byte{}, x509Entry.LeafInput[:12]...), 0x00, 0x00, 0x00, 0x00, 0x00)
	assertSameVerdict(t, "x509 leaf with an empty certificate",
		&ct.LeafEntry{LeafInput: emptyLeafCert, ExtraData: x509Entry.ExtraData})

	// The same for a precert's TBSCertificate: header, 32-byte issuer key hash,
	// a zero uint24 length, then empty extensions.
	emptyTBS := append(append([]byte{}, pcEntry.LeafInput[:12+32]...), 0x00, 0x00, 0x00, 0x00, 0x00)
	assertSameVerdict(t, "precert with an empty TBSCertificate",
		&ct.LeafEntry{LeafInput: emptyTBS, ExtraData: pcEntry.ExtraData})

	// Unknown and unsupported type values in the header.
	base := referenceLeafEntry(t, false, nil, leaf, inter)

	for _, patch := range []struct {
		name string
		off  int
		val  byte
	}{
		{"leaf_type=1", 1, 1},
		{"leaf_type=255", 1, 255},
		{"entry_type=2", 11, 2},
		{"entry_type=0x8000 (json)", 10, 0x80},
	} {
		in := append([]byte{}, base.LeafInput...)
		in[patch.off] = patch.val
		assertSameVerdict(t, patch.name, &ct.LeafEntry{LeafInput: in, ExtraData: base.ExtraData})
	}
}

func assertSameVerdict(t *testing.T, name string, le *ct.LeafEntry) {
	t.Helper()

	want, wantErr := ct.RawLogEntryFromLeaf(1, le)
	got, gotErr := decodeLeafEntry(1, le)

	if (wantErr == nil) != (gotErr == nil) {
		t.Errorf("%s: reference err=%v, decoder err=%v", name, wantErr, gotErr)
		return
	}

	if wantErr == nil && !reflect.DeepEqual(want, got) {
		t.Errorf("%s: both accepted but results differ", name)
	}
}

// FuzzDecodeLeafEntry is the strongest guarantee available that the decoder
// is a faithful replacement: for arbitrary bytes it must agree with
// ct.RawLogEntryFromLeaf on whether the input is valid, and when it is, produce
// an identical entry.
//
//	go test ./internal/certificatetransparency/ -run XXX -fuzz FuzzDecodeLeafEntry -fuzztime 60s
func FuzzDecodeLeafEntry(f *testing.F) {
	leaf := makeDER(f, "www.example.com", []string{"www.example.com"}, false)
	inter := makeDER(f, "Example Intermediate", nil, true)

	for _, precert := range []bool{false, true} {
		for _, ext := range [][]byte{nil, {1, 2}} {
			le := referenceLeafEntry(f, precert, ext, leaf, inter)
			f.Add(le.LeafInput, le.ExtraData)
		}
	}

	f.Fuzz(func(t *testing.T, leafInput, extraData []byte) {
		le := &ct.LeafEntry{LeafInput: leafInput, ExtraData: extraData}

		want, wantErr := ct.RawLogEntryFromLeaf(7, le)
		got, gotErr := decodeLeafEntry(7, le)

		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("verdict differs: reference err=%v, decoder err=%v", wantErr, gotErr)
		}

		if wantErr == nil && !reflect.DeepEqual(want, got) {
			t.Fatalf("both accepted but results differ\nreference: %#v\ndecoder:   %#v", want, got)
		}
	})
}
