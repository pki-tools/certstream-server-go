package certificatetransparency

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/x509"
)

// expectedLeafCert spells out what an entry's LeafCert must be: the converted
// certificate, identified by the DER the log published - the certificate
// itself, or for a precertificate the submitted precertificate rather than the
// TBSCertificate that was parsed - with the poison flag set on precertificates.
//
// This is the result the entry paths have always produced. They used to get
// there by hashing and encoding the parsed bytes and then overwriting all of
// it; this states it directly, so removing that redundant work can be shown to
// change nothing.
func expectedLeafCert(cert *x509.Certificate, identity []byte, precert bool) models.LeafCert {
	lc := leafCertFromX509cert(*cert)

	lc.AsDER = base64.StdEncoding.EncodeToString(identity)
	lc.Fingerprint = calculateSHA1(identity)
	lc.SHA1 = lc.Fingerprint
	lc.SHA256 = calculateSHA256(identity)

	if precert {
		lc.Extensions.CTLPoisonByte = true
	}

	return lc
}

// TestEntryIdentityFields checks AsDER, Fingerprint, SHA1 and SHA256 - and
// everything else in LeafCert - on both entry paths, for certificates and
// precertificates across the certificate corpus.
func TestEntryIdentityFields(t *testing.T) {
	inter := makeDER(t, "Example Intermediate", nil, true)
	tw := &tiledWorker{name: "tiled", operatorName: "Op", monitoringURL: "https://ct.example.com/tiled"}

	checked := 0

	for _, c := range certCorpus(t) {
		ref, err := x509.ParseCertificate(c.der)
		if x509.IsFatal(err) || ref == nil {
			continue
		}

		for _, precert := range []bool{false, true} {
			// RFC 6962 path.
			rle, err := decodeLeafEntry(3, referenceLeafEntry(t, precert, nil, c.der, inter))
			if err != nil {
				t.Fatal(err)
			}

			parsed := ref
			if precert {
				parsed, err = x509.ParseTBSCertificate(ref.RawTBSCertificate)
				if x509.IsFatal(err) || parsed == nil {
					continue
				}
			}

			data, err := parseData(rle, "Op", "log", "https://ct.example.com/log")
			if err != nil {
				t.Fatalf("%s precert=%v: parseData: %v", c.name, precert, err)
			}

			if want := expectedLeafCert(parsed, rle.Cert.Data, precert); !reflect.DeepEqual(want, data.LeafCert) {
				t.Errorf("%s precert=%v: RFC 6962 LeafCert differs in %v", c.name, precert,
					differingLeafCertFields(want, data.LeafCert))
			}

			// Tiled path.
			te := &sunlight.LogEntry{Certificate: c.der, LeafIndex: 3}
			identity := c.der

			if precert {
				te = &sunlight.LogEntry{Certificate: ref.RawTBSCertificate, IsPrecert: true, PreCertificate: c.der, LeafIndex: 3}
			}

			entry, err := tw.parseTiledEntry(te, 3)
			if err != nil {
				t.Fatalf("%s precert=%v: parseTiledEntry: %v", c.name, precert, err)
			}

			if want := expectedLeafCert(parsed, identity, precert); !reflect.DeepEqual(want, entry.Data.LeafCert) {
				t.Errorf("%s precert=%v: tiled LeafCert differs in %v", c.name, precert,
					differingLeafCertFields(want, entry.Data.LeafCert))
			}

			checked++
		}
	}

	t.Logf("checked %d entries on both paths", checked)

	if checked < 300 {
		t.Errorf("only %d entries checked", checked)
	}
}
