package certificatetransparency

import (
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
)

// decodeLeafEntry is a drop-in replacement for ct.RawLogEntryFromLeaf.
//
// ct.RawLogEntryFromLeaf decodes the TLS-encoded leaf_input and extra_data of a
// get-entries response with certificate-transparency-go's tls package, which,
// like its asn1 package, works by reflection over struct tags. Profiling put it
// at about a quarter of the per-entry CPU cost once the duplicate certificate
// parse was removed - second only to the certificate parse itself - for a
// format that is a handful of fixed-width integers and length-prefixed byte
// strings (RFC 6962 sections 3.4 and 4.6):
//
//	MerkleTreeLeaf:
//	  uint8  version
//	  uint8  leaf_type            (0 = timestamped_entry)
//	  uint64 timestamp
//	  uint16 entry_type           (0 = x509_entry, 1 = precert_entry)
//	  x509_entry:    opaque ASN.1Cert<1..2^24-1>
//	  precert_entry: opaque issuer_key_hash[32]; opaque TBSCertificate<1..2^24-1>
//	  opaque CtExtensions<0..2^16-1>
//
//	extra_data, x509_entry:    ASN.1Cert certificate_chain<0..2^24-1>
//	extra_data, precert_entry: ASN.1Cert pre_certificate; ASN.1Cert certificate_chain<0..2^24-1>
//
// It decodes with cryptobyte, without reflection, and the byte slices it
// returns alias the input rather than copying it. The result is identical to
// ct.RawLogEntryFromLeaf's - field for field, including nil versus empty - and
// it accepts and rejects exactly the same inputs. Both properties are enforced
// by TestDecodeLeafEntryMatchesReference and FuzzDecodeLeafEntry, which compare
// it with the reference implementation; any change here must keep them passing.
func decodeLeafEntry(index int64, entry *ct.LeafEntry) (*ct.RawLogEntry, error) {
	if entry == nil {
		return nil, errors.New("nil leaf entry")
	}

	leaf, err := decodeMerkleTreeLeaf(entry.LeafInput)
	if err != nil {
		return nil, err
	}

	ret := ct.RawLogEntry{Index: index, Leaf: *leaf}
	extra := cryptobyte.String(entry.ExtraData)

	switch leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		chain, ok := readCertList(&extra)
		if !ok {
			return nil, errors.New("failed to unmarshal CertificateChain")
		}

		ret.Cert = *leaf.TimestampedEntry.X509Entry
		ret.Chain = chain

	case ct.PrecertLogEntryType:
		pre, ok := readASN1Cert(&extra)
		if !ok {
			return nil, errors.New("failed to unmarshal PrecertChainEntry: pre_certificate")
		}

		chain, ok := readCertList(&extra)
		if !ok {
			return nil, errors.New("failed to unmarshal PrecertChainEntry: certificate_chain")
		}

		ret.Cert = pre
		ret.Chain = chain

	default:
		return nil, fmt.Errorf("unknown entry type: %v", leaf.TimestampedEntry.EntryType)
	}

	if !extra.Empty() {
		return nil, fmt.Errorf("extra_data: trailing data %d bytes", len(extra))
	}

	return &ret, nil
}

func decodeMerkleTreeLeaf(data []byte) (*ct.MerkleTreeLeaf, error) {
	s := cryptobyte.String(data)

	var version, leafType uint8
	if !s.ReadUint8(&version) || !s.ReadUint8(&leafType) {
		return nil, errors.New("failed to unmarshal MerkleTreeLeaf: truncated header")
	}

	if ct.MerkleLeafType(leafType) != ct.TimestampedEntryLeafType {
		return nil, fmt.Errorf("failed to unmarshal MerkleTreeLeaf: unsupported leaf type %d", leafType)
	}

	te := &ct.TimestampedEntry{}

	var entryType uint16
	if !s.ReadUint64(&te.Timestamp) || !s.ReadUint16(&entryType) {
		return nil, errors.New("failed to unmarshal MerkleTreeLeaf: truncated timestamped entry")
	}

	te.EntryType = ct.LogEntryType(entryType)

	switch te.EntryType {
	case ct.X509LogEntryType:
		cert, ok := readASN1Cert(&s)
		if !ok {
			return nil, errors.New("failed to unmarshal MerkleTreeLeaf: x509_entry")
		}

		te.X509Entry = &cert

	case ct.PrecertLogEntryType:
		var issuerKeyHash []byte
		if !s.ReadBytes(&issuerKeyHash, len(ct.PreCert{}.IssuerKeyHash)) {
			return nil, errors.New("failed to unmarshal MerkleTreeLeaf: issuer_key_hash")
		}

		var tbs cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&tbs) || len(tbs) == 0 {
			return nil, errors.New("failed to unmarshal MerkleTreeLeaf: TBSCertificate")
		}

		pc := &ct.PreCert{TBSCertificate: []byte(tbs)}
		copy(pc.IssuerKeyHash[:], issuerKeyHash)
		te.PrecertEntry = pc

	default:
		// The reference decoder also fails here: it has no variant to select
		// for any other entry type, and RawLogEntryFromLeaf rejects the JSON
		// entry type that the tls package does know about.
		return nil, fmt.Errorf("unknown entry type: %v", te.EntryType)
	}

	var ext cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ext) {
		return nil, errors.New("failed to unmarshal MerkleTreeLeaf: extensions")
	}

	// Aliases the input like every other field. For zero-length extensions
	// cryptobyte yields an empty, non-nil slice, which is also what the
	// reference decoder produces.
	te.Extensions = ct.CTExtensions(ext)

	if !s.Empty() {
		return nil, fmt.Errorf("MerkleTreeLeaf: trailing data %d bytes", len(s))
	}

	return &ct.MerkleTreeLeaf{
		Version:          ct.Version(version),
		LeafType:         ct.MerkleLeafType(leafType),
		TimestampedEntry: te,
	}, nil
}

// readASN1Cert reads one non-empty uint24-length-prefixed certificate.
func readASN1Cert(s *cryptobyte.String) (ct.ASN1Cert, bool) {
	var der cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&der) || len(der) == 0 {
		return ct.ASN1Cert{}, false
	}

	return ct.ASN1Cert{Data: []byte(der)}, true
}

// readCertList reads a uint24-length-prefixed list of certificates.
func readCertList(s *cryptobyte.String) ([]ct.ASN1Cert, bool) {
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return nil, false
	}

	// Most chains hold one to three certificates.
	out := make([]ct.ASN1Cert, 0, 3)

	for !list.Empty() {
		cert, ok := readASN1Cert(&list)
		if !ok {
			return nil, false
		}

		out = append(out, cert)
	}

	return out, true
}
