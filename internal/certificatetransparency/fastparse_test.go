package certificatetransparency

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	ctdata "github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/x509"
)

type corpusCert struct {
	name string
	der  []byte
}

// pemCerts returns every CERTIFICATE block in a PEM blob.
func pemCerts(name string, data []byte) []corpusCert {
	var out []corpusCert

	for i := 0; ; i++ {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			return out
		}

		if block.Type == "CERTIFICATE" {
			out = append(out, corpusCert{name: name + "#" + itoa64(int64(i)), der: block.Bytes})
		}
	}
}

func pemFiles(t *testing.T, glob string) []corpusCert {
	t.Helper()

	paths, _ := filepath.Glob(glob)

	var out []corpusCert

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}

		out = append(out, pemCerts(filepath.Base(p), data)...)
	}

	return out
}

// certCorpus gathers real-world certificates available locally, plus
// synthetic ones covering the extensions leafCertFromX509cert renders.
func certCorpus(t *testing.T) []corpusCert {
	t.Helper()

	var corpus []corpusCert

	// System trust roots: real certificates from many CAs over decades.
	corpus = append(corpus, pemFiles(t, "/etc/ssl/certs/ca-certificates.crt")...)

	// Go's own x509 test certificates.
	corpus = append(corpus, pemFiles(t, filepath.Join(runtime.GOROOT(), "src", "crypto", "x509", "testdata", "*.pem"))...)

	// ct-go's x509 test certificates, including deliberately malformed ones.
	ctgo := ctgoModuleDir(t)
	if ctgo != "" {
		corpus = append(corpus, pemFiles(t, filepath.Join(ctgo, "x509", "testdata", "*.pem"))...)
		corpus = append(corpus, pemFiles(t, filepath.Join(ctgo, "x509", "testdata", "invalid", "*.pem"))...)
	}

	// Real CT fixtures, including a precertificate and a certificate carrying
	// embedded SCTs.
	for name, p := range map[string]string{
		"ctdata.CACert":               ctdata.CACertPEM,
		"ctdata.TestCert":             ctdata.TestCertPEM,
		"ctdata.TestPreCert":          ctdata.TestPreCertPEM,
		"ctdata.TestEmbeddedCert":     ctdata.TestEmbeddedCertPEM,
		"ctdata.TestInvalidEmbedCert": ctdata.TestInvalidEmbeddedCertPEM,
	} {
		corpus = append(corpus, pemCerts(name, []byte(p))...)
	}

	corpus = append(corpus, syntheticCorpus(t)...)

	return corpus
}

// ctgoModuleDir locates the ct-go module source for its test certificates.
func ctgoModuleDir(t *testing.T) string {
	t.Helper()

	gomodcache := os.Getenv("GOMODCACHE")
	if gomodcache == "" {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			home, _ := os.UserHomeDir()
			gopath = filepath.Join(home, "go")
		}

		gomodcache = filepath.Join(gopath, "pkg", "mod")
	}

	matches, _ := filepath.Glob(filepath.Join(gomodcache, "github.com", "google", "certificate-transparency-go@*"))
	if len(matches) == 0 {
		return ""
	}

	return matches[len(matches)-1]
}

// syntheticCorpus covers every branch of leafCertFromX509cert: each key type,
// each SAN kind, key usages, policies including the CA/B Forum validation-type
// OIDs, AIA, subject attributes including the EV jurisdiction OID, and CAs.
func syntheticCorpus(t *testing.T) []corpusCert {
	t.Helper()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	keys := map[string]any{"rsa2048": rsaKey, "p256": p256, "p384": p384, "p521": p521, "ed25519": edKey}

	uri, _ := url.Parse("https://example.com/path")
	jurisdiction := stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}

	templates := map[string]*stdx509.Certificate{
		"dv-leaf": {
			Subject:  stdpkix.Name{CommonName: "www.example.com"},
			DNSNames: []string{"www.example.com", "example.com"},
			KeyUsage: stdx509.KeyUsageDigitalSignature,
			PolicyIdentifiers: []stdasn1.ObjectIdentifier{
				{2, 23, 140, 1, 2, 1},
			},
			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://ca.example.com/ca.crt"},
		},
		"ov-leaf-wildcard": {
			Subject: stdpkix.Name{
				CommonName: "*.example.org", Organization: []string{"Example Org"},
				Country: []string{"GB"}, Locality: []string{"London"}, Province: []string{"Greater London"},
				StreetAddress: []string{"1 Example Street"}, PostalCode: []string{"EC1A 1AA"},
				OrganizationalUnit: []string{"Ops", "Security"}, SerialNumber: "12345",
			},
			DNSNames:          []string{"*.example.org", "example.org", "a.example.org", "b.example.org"},
			KeyUsage:          stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageKeyEncipherment,
			PolicyIdentifiers: []stdasn1.ObjectIdentifier{{2, 23, 140, 1, 2, 2}, {1, 3, 6, 1, 4, 1, 44947, 1, 1, 1}},
		},
		"ev-leaf": {
			Subject: stdpkix.Name{
				CommonName: "bank.example", Organization: []string{"Bank Ltd"},
				ExtraNames: []stdpkix.AttributeTypeAndValue{{Type: jurisdiction, Value: "US"}},
			},
			DNSNames:          []string{"bank.example"},
			PolicyIdentifiers: []stdasn1.ObjectIdentifier{{2, 23, 140, 1, 1}},
		},
		"mixed-sans": {
			Subject:        stdpkix.Name{CommonName: "cn-not-in-sans.example"},
			DNSNames:       []string{"one.example", "two.example.co.uk"},
			EmailAddresses: []string{"admin@example.com"},
			IPAddresses:    []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
			URIs:           []*url.URL{uri},
		},
		"unicode-subject": {
			Subject:  stdpkix.Name{CommonName: "münchen.example", Organization: []string{"Bücher & Söhne GmbH"}},
			DNSNames: []string{"xn--mnchen-3ya.example"},
		},
		"ca": {
			Subject:               stdpkix.Name{CommonName: "Example CA", Organization: []string{"Example"}},
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
			KeyUsage:              stdx509.KeyUsageCertSign | stdx509.KeyUsageCRLSign,
		},
		"all-key-usages": {
			Subject: stdpkix.Name{CommonName: "ku.example"},
			KeyUsage: stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageContentCommitment |
				stdx509.KeyUsageKeyEncipherment | stdx509.KeyUsageDataEncipherment |
				stdx509.KeyUsageKeyAgreement | stdx509.KeyUsageEncipherOnly | stdx509.KeyUsageDecipherOnly,
		},
		"no-extensions": {
			Subject: stdpkix.Name{CommonName: "bare.example"},
		},
		"ip-only": {
			Subject:     stdpkix.Name{},
			IPAddresses: []net.IP{net.ParseIP("198.51.100.7")},
		},
	}

	var out []corpusCert

	serial := int64(1000)

	for tname, tmpl := range templates {
		// Since Go 1.24 (x509usepolicies=1) CreateCertificate encodes Policies
		// and ignores PolicyIdentifiers, so set both or the certificate carries
		// no policies at all - which these templates silently did at first.
		for _, oid := range tmpl.PolicyIdentifiers {
			ints := make([]uint64, len(oid))
			for i, v := range oid {
				ints[i] = uint64(v)
			}

			if o, err := stdx509.OIDFromInts(ints); err == nil {
				tmpl.Policies = append(tmpl.Policies, o)
			}
		}

		for kname, key := range keys {
			serial++

			tmpl.SerialNumber = big.NewInt(serial)
			tmpl.NotBefore = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
			tmpl.NotAfter = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

			var pub any

			switch k := key.(type) {
			case *rsa.PrivateKey:
				pub = &k.PublicKey
			case *ecdsa.PrivateKey:
				pub = &k.PublicKey
			case ed25519.PrivateKey:
				pub = k.Public()
			}

			der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
			if err != nil {
				t.Fatalf("synthetic %s/%s: %v", tname, kname, err)
			}

			if len(tmpl.PolicyIdentifiers) > 0 {
				parsed, err := stdx509.ParseCertificate(der)
				if err != nil || len(parsed.Policies) != len(tmpl.PolicyIdentifiers) {
					t.Fatalf("synthetic %s/%s: policies were not encoded", tname, kname)
				}
			}

			out = append(out, corpusCert{name: "synthetic:" + tname + "/" + kname, der: der})
		}
	}

	return out
}

// TestFastParserMatchesCTGo is the guarantee behind the fast parser: for every
// certificate in the corpus, through both the full-certificate path and the
// precertificate (bare TBSCertificate) path, the standard library route either
// declines - and ct-go parses it as before - or produces exactly the
// models.LeafCert ct-go would. Not just the same JSON: deeply equal values.
//
// It also fails if the standard library accepts a certificate ct-go rejects,
// since there would be no reference to say what the output should be.
func TestFastParserMatchesCTGo(t *testing.T) {
	corpus := certCorpus(t)
	if len(corpus) < 100 {
		t.Fatalf("corpus has only %d certificates; expected the system roots to be available", len(corpus))
	}

	var fast, declined, bothRefused int

	for _, c := range corpus {
		for _, tbsOnly := range []bool{false, true} {
			input := c.der
			label := c.name

			if tbsOnly {
				label += " [tbs]"

				ref, err := x509.ParseCertificate(c.der)
				if x509.IsFatal(err) || ref == nil {
					// Without a certificate ct-go can read there is no TBS to test.
					continue
				}

				input = ref.RawTBSCertificate
			}

			ref, refErr := parseWithCTGo(input, tbsOnly)
			refOK := !x509.IsFatal(refErr) && ref != nil

			got := parseWithStdlib(input, tbsOnly)

			switch {
			case got == nil && !refOK:
				bothRefused++
			case got == nil:
				declined++
			case !refOK:
				t.Errorf("%s: standard library accepted a certificate ct-go rejects (%v)", label, refErr)
			default:
				fast++

				want, have := leafCertFromX509cert(*ref), leafCertFromX509cert(*got)
				if !reflect.DeepEqual(want, have) {
					t.Errorf("%s: output differs in %v", label, differingLeafCertFields(want, have))
				}

				if string(got.Raw) != string(ref.Raw) {
					t.Errorf("%s: Raw differs from ct-go's", label)
				}
			}
		}
	}

	t.Logf("corpus %d certificates: %d parses matched ct-go exactly, %d declined to ct-go, %d refused by both",
		len(corpus), fast, declined, bothRefused)

	if fast < len(corpus) {
		t.Errorf("only %d fast parses across %d certificates x 2 paths; the fast path is not being exercised", fast, len(corpus))
	}
}

// TestWrapTBSRoundTrips checks that wrapping a TBSCertificate yields a
// certificate whose TBS is byte-for-byte the input - the precondition for the
// precertificate path producing the same result as ct-go's ParseTBSCertificate.
func TestWrapTBSRoundTrips(t *testing.T) {
	for _, c := range syntheticCorpus(t)[:10] {
		parsed, err := stdx509.ParseCertificate(c.der)
		if err != nil {
			t.Fatal(err)
		}

		wrapped, ok := wrapTBS(parsed.RawTBSCertificate)
		if !ok {
			t.Fatalf("%s: wrapTBS failed", c.name)
		}

		again, err := stdx509.ParseCertificate(wrapped)
		if err != nil {
			t.Fatalf("%s: wrapped TBS does not parse: %v", c.name, err)
		}

		if string(again.RawTBSCertificate) != string(parsed.RawTBSCertificate) {
			t.Errorf("%s: TBS changed in the round trip", c.name)
		}
	}

	for _, bad := range [][]byte{nil, {0x30, 0x00}, {0x02, 0x01, 0x01}, append([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, 0x00)} {
		if _, ok := wrapTBS(bad); ok {
			t.Errorf("wrapTBS accepted malformed input %x", bad)
		}
	}
}

// TestKeyUsageBitsAgree pins the assumption behind converting the key usage
// bitmask by plain conversion: both libraries use the same bit for each usage.
func TestKeyUsageBitsAgree(t *testing.T) {
	pairs := []struct {
		std stdx509.KeyUsage
		ct  x509.KeyUsage
	}{
		{stdx509.KeyUsageDigitalSignature, x509.KeyUsageDigitalSignature},
		{stdx509.KeyUsageContentCommitment, x509.KeyUsageContentCommitment},
		{stdx509.KeyUsageKeyEncipherment, x509.KeyUsageKeyEncipherment},
		{stdx509.KeyUsageDataEncipherment, x509.KeyUsageDataEncipherment},
		{stdx509.KeyUsageKeyAgreement, x509.KeyUsageKeyAgreement},
		{stdx509.KeyUsageCertSign, x509.KeyUsageCertSign},
		{stdx509.KeyUsageCRLSign, x509.KeyUsageCRLSign},
		{stdx509.KeyUsageEncipherOnly, x509.KeyUsageEncipherOnly},
		{stdx509.KeyUsageDecipherOnly, x509.KeyUsageDecipherOnly},
	}

	for _, p := range pairs {
		if int(p.std) != int(p.ct) {
			t.Errorf("key usage bit differs: stdlib %d, ct-go %d", p.std, p.ct)
		}
	}
}

// setFastParser switches the parser for the duration of a test.
func setFastParser(t *testing.T, on bool) {
	t.Helper()

	prev := config.AppConfig.General.Scanner.FastParser
	config.AppConfig.General.Scanner.FastParser = &on

	t.Cleanup(func() { config.AppConfig.General.Scanner.FastParser = prev })
}

// TestEntryOutputIdenticalWithFastParser goes one level up from the parser:
// complete models.Data from both real entry paths - parseData for RFC 6962
// entries and parseTiledEntry for static-CT ones, each for certificates and
// precertificates - must be identical with the fast parser on and off. Only
// the Seen timestamp, which is the wall clock, is excluded.
func TestEntryOutputIdenticalWithFastParser(t *testing.T) {
	inter := makeDER(t, "Example Intermediate", nil, true)
	tw := &tiledWorker{name: "tiled", operatorName: "Op", monitoringURL: "https://ct.example.com/tiled"}

	type outputs struct{ rfc, tiled models.Data }

	run := func(t *testing.T, der []byte, precert bool) (outputs, bool) {
		t.Helper()

		ref, err := x509.ParseCertificate(der)
		if x509.IsFatal(err) || ref == nil {
			return outputs{}, false
		}

		le := referenceLeafEntry(t, precert, nil, der, inter)

		rle, err := decodeLeafEntry(9, le)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}

		rfc, err := parseData(rle, "Op", "log", "https://ct.example.com/log")
		if err != nil {
			return outputs{}, false
		}

		tiledEntry := &sunlight.LogEntry{Certificate: der, LeafIndex: 9}
		if precert {
			tiledEntry = &sunlight.LogEntry{
				Certificate: ref.RawTBSCertificate, IsPrecert: true,
				PreCertificate: der, LeafIndex: 9,
			}
		}

		tiled, err := tw.parseTiledEntry(tiledEntry, 9)
		if err != nil {
			return outputs{}, false
		}

		rfc.Seen, tiled.Data.Seen = 0, 0

		return outputs{rfc: rfc, tiled: tiled.Data}, true
	}

	compared := 0

	for _, c := range certCorpus(t) {
		for _, precert := range []bool{false, true} {
			setFastParser(t, false)
			want, okWant := run(t, c.der, precert)

			setFastParser(t, true)
			got, okGot := run(t, c.der, precert)

			if okWant != okGot {
				t.Errorf("%s precert=%v: accepted with fast parser=%v, without=%v", c.name, precert, okGot, okWant)
				continue
			}

			if !okWant {
				continue
			}

			compared++

			if !reflect.DeepEqual(want.rfc, got.rfc) {
				t.Errorf("%s precert=%v: RFC 6962 output differs in %v", c.name, precert,
					differingLeafCertFields(want.rfc.LeafCert, got.rfc.LeafCert))
			}

			if !reflect.DeepEqual(want.tiled, got.tiled) {
				t.Errorf("%s precert=%v: tiled output differs in %v", c.name, precert,
					differingLeafCertFields(want.tiled.LeafCert, got.tiled.LeafCert))
			}
		}
	}

	t.Logf("compared %d entries on both paths", compared)

	if compared < 300 {
		t.Errorf("only %d entries compared; expected the corpus on both entry types", compared)
	}
}

// TestShadowCheckDetectsDisagreement makes sure the production safety net
// actually fires: a fast-parsed certificate whose output differs from ct-go's
// must be counted.
func TestShadowCheckDetectsDisagreement(t *testing.T) {
	der := makeDER(t, "www.example.com", []string{"www.example.com"}, false)

	fast := parseWithStdlib(der, false)
	if fast == nil {
		t.Fatal("precondition: fast parse failed")
	}

	before := shadowMismatches.Load()

	shadowCheck(der, false, fast)

	if got := shadowMismatches.Load() - before; got != 0 {
		t.Fatalf("identical parses counted as %d mismatches", got)
	}

	tampered := *fast
	tampered.DNSNames = []string{"evil.example"}

	shadowCheck(der, false, &tampered)

	if got := shadowMismatches.Load() - before; got != 1 {
		t.Errorf("a differing parse counted %d mismatches, want 1", got)
	}
}
