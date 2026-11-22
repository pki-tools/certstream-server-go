package certificatetransparency

import (
	"bytes"
	"testing"

	"filippo.io/sunlight"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// lenientDER returns a certificate that ct-go accepts only in lax mode: its
// Organization is a PrintableString containing '_', a character PrintableString
// forbids. Certificates like this really are in CT logs.
func lenientDER(t *testing.T) []byte {
	t.Helper()

	der := makeDER(t, "www.example.com", []string{"www.example.com"}, false)

	bad := bytes.Replace(der, []byte("Example Org"), []byte("Example_Org"), 1)
	if bytes.Equal(der, bad) {
		t.Fatal("could not patch the Organization into an invalid PrintableString")
	}

	// Precondition: this must be the non-fatal case, or the test proves nothing.
	cert, err := ctx509.ParseCertificate(bad)
	if cert == nil || err == nil || ctx509.IsFatal(err) {
		t.Fatalf("precondition: want a non-fatal lax parse, got cert=%v err=%v", cert != nil, err)
	}

	return bad
}

// TestParseDataAcceptsLenientCertificate is the regression guard for entries
// being silently dropped: parseData used to reject any error from ToLogEntry,
// including the non-fatal ones ct-go returns alongside a usable certificate.
func TestParseDataAcceptsLenientCertificate(t *testing.T) {
	der := lenientDER(t)
	before := LenientParses()

	data, err := parseData(makeEntry(der), "Op", "log", "https://ct.example.com/log")
	if err != nil {
		t.Fatalf("parseData rejected a leniently parsed certificate: %v", err)
	}

	if cn := *data.LeafCert.Subject.CN; cn != "www.example.com" {
		t.Errorf("CN = %q, want www.example.com - the certificate must actually be decoded", cn)
	}

	if got := LenientParses() - before; got != 1 {
		t.Errorf("lenient parse counter advanced by %d, want 1", got)
	}
}

// TestParseTiledEntryAcceptsLenientCertificate covers the same bug in the
// static-CT path, which called the parsers directly with the same mistake.
func TestParseTiledEntryAcceptsLenientCertificate(t *testing.T) {
	der := lenientDER(t)
	before := LenientParses()

	tw := &tiledWorker{name: "log", operatorName: "Op", monitoringURL: "https://ct.example.com/tiled"}

	if _, err := tw.parseTiledEntry(&sunlight.LogEntry{Certificate: der, LeafIndex: 7}, 7); err != nil {
		t.Fatalf("parseTiledEntry rejected a leniently parsed certificate: %v", err)
	}

	if got := LenientParses() - before; got != 1 {
		t.Errorf("lenient parse counter advanced by %d, want 1", got)
	}
}

// TestParseDataRejectsFatalErrors makes sure the fix did not swing too far:
// garbage must still be refused.
func TestParseDataRejectsFatalErrors(t *testing.T) {
	if _, err := parseData(makeEntry([]byte{0x30, 0x03, 0x02, 0x01}), "Op", "log", "https://ct.example.com/log"); err == nil {
		t.Error("parseData accepted a truncated, unparseable certificate")
	}
}
