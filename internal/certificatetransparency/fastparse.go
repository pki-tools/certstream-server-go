package certificatetransparency

import (
	stdx509 "crypto/x509"
	stdpkix "crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Certificate parsing goes to the standard library first and falls back to
// certificate-transparency-go only when the standard library refuses.
//
// ct-go's x509 package decodes through its own reflection-based fork of
// encoding/asn1. Production profiles put it at ~37% of all CPU - the largest
// single cost - and on identical DER the standard library's cryptobyte parser
// is ~3.3x faster (BenchmarkParserComparison).
//
// What makes this safe:
//
//   - One conversion. The standard library's result is translated into ct-go's
//     x509.Certificate - only the fields leafCertFromX509cert reads - and then
//     goes through the same leafCertFromX509cert as everything else. There is
//     no second copy of the logic that builds the JSON, to drift from the first.
//
//   - Fallback on any refusal. The standard library is stricter: it rejects
//     negative serial numbers, malformed SANs, invalid PrintableStrings,
//     unsupported curves and more. Each of those falls back to ct-go, which
//     admits them as before. "Lenient parses" counts what ct-go then needed lax
//     mode for; 0 in 140M production entries is what justified this.
//
//   - Declining what cannot be translated losslessly. Signature or key
//     algorithms the standard library does not recognise, and policy OIDs it
//     cannot represent as []int, also fall back rather than guess.
//
//   - Proof of equal output. TestFastParserMatchesCTGo parses a corpus of real
//     certificates both ways - system roots, Go's and ct-go's test certificates
//     including ct-go's deliberately malformed ones, and real CT
//     precertificates - and requires identical models.LeafCert output.
//
//   - Verification in production. One fast-parsed certificate in
//     shadowSampleEvery is parsed by ct-go as well and the outputs compared;
//     any difference is counted on /system and recorded on /errors. This runs
//     on live traffic, which no corpus fully represents, for ~0.03% more CPU.
//
//   - A switch. scanner.fast_parser: false restores ct-go-only parsing.

// shadowSampleEvery sets how often a fast-parsed certificate is re-parsed with
// ct-go to verify the two agree on live traffic.
const shadowSampleEvery = 1000

var (
	fastParses       atomic.Int64
	fastFallbacks    atomic.Int64
	shadowCounter    atomic.Int64
	shadowChecks     atomic.Int64
	shadowMismatches atomic.Int64
)

// FastParserStats reports how certificates were parsed.
type FastParserStats struct {
	Enabled bool
	// Fast is the number parsed by the standard library.
	Fast int64
	// Fallbacks is the number the standard library refused, parsed by ct-go.
	Fallbacks int64
	// ShadowChecks is how many fast parses were also parsed by ct-go to compare.
	ShadowChecks int64
	// ShadowMismatches is how many of those produced different output. Anything
	// above zero means the fast parser changes what is streamed.
	ShadowMismatches int64
}

// GetFastParserStats returns the parser counters.
func GetFastParserStats() FastParserStats {
	return FastParserStats{
		Enabled:          fastParserEnabled(),
		Fast:             fastParses.Load(),
		Fallbacks:        fastFallbacks.Load(),
		ShadowChecks:     shadowChecks.Load(),
		ShadowMismatches: shadowMismatches.Load(),
	}
}

func fastParserEnabled() bool {
	p := config.AppConfig.General.Scanner.FastParser
	return p == nil || *p
}

// parseLeafCertificate parses a log entry's certificate: a full DER
// certificate, or for a precertificate entry (tbsOnly) the bare
// TBSCertificate the log stores.
//
// Every entry's certificate, on both the RFC 6962 and the tiled path, comes
// through here, as do chain certificates the issuer cache has not seen.
func parseLeafCertificate(data []byte, tbsOnly bool) (*x509.Certificate, error) {
	if fastParserEnabled() {
		if cert := parseWithStdlib(data, tbsOnly); cert != nil {
			fastParses.Add(1)

			if shadowCounter.Add(1)%shadowSampleEvery == 0 {
				shadowCheck(data, tbsOnly, cert)
			}

			return cert, nil
		}

		fastFallbacks.Add(1)
	}

	cert, err := parseWithCTGo(data, tbsOnly)
	if x509.IsFatal(err) || cert == nil {
		if err == nil {
			err = errors.New("certificate parser returned no certificate")
		}

		return nil, err
	}

	// A non-fatal error means ct-go only accepted the certificate in lax mode;
	// the certificate is usable. See recordLenientParse.
	if err != nil {
		recordLenientParse()
	}

	return cert, nil
}

func parseWithCTGo(data []byte, tbsOnly bool) (*x509.Certificate, error) {
	if tbsOnly {
		return x509.ParseTBSCertificate(data)
	}

	return x509.ParseCertificate(data)
}

// parseWithStdlib returns nil whenever the standard library refuses the input
// or its result cannot be translated without loss.
func parseWithStdlib(data []byte, tbsOnly bool) *x509.Certificate {
	der := data

	if tbsOnly {
		wrapped, ok := wrapTBS(data)
		if !ok {
			return nil
		}

		der = wrapped
	}

	c, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil
	}

	out, ok := fromStdlibCertificate(c)
	if !ok {
		return nil
	}

	if tbsOnly {
		// Match ct-go's ParseTBSCertificate, whose Raw is the TBSCertificate
		// itself rather than the wrapper built here.
		out.Raw = data
	}

	return out
}

// wrapTBS turns a bare TBSCertificate into a parseable Certificate:
//
//	SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
//
// The standard library only parses whole certificates, and requires the outer
// signatureAlgorithm to equal the one inside the TBSCertificate, so that is
// copied out of the TBS. The signature is empty; nothing verifies it.
func wrapTBS(tbs []byte) ([]byte, bool) {
	s := cryptobyte.String(tbs)

	var body cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, false
	}

	// TBSCertificate ::= SEQUENCE { version [0] EXPLICIT OPTIONAL,
	//   serialNumber INTEGER, signature AlgorithmIdentifier, ... }
	var sigAlg cryptobyte.String
	if !body.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!body.SkipASN1(cbasn1.INTEGER) ||
		!body.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) {
		return nil, false
	}

	var b cryptobyte.Builder

	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(nil)
	})

	out, err := b.Bytes()
	if err != nil {
		return nil, false
	}

	return out, true
}

// fromStdlibCertificate translates the fields leafCertFromX509cert and the
// parse paths read. It declines (false) rather than guess where the two
// libraries' representations differ.
func fromStdlibCertificate(c *stdx509.Certificate) (*x509.Certificate, bool) {
	sigAlg, ok := signatureAlgorithmFromStdlib(c.SignatureAlgorithm)
	if !ok {
		return nil, false
	}

	pubAlg, ok := publicKeyAlgorithmFromStdlib(c.PublicKeyAlgorithm)
	if !ok {
		return nil, false
	}

	// PolicyIdentifiers omits OIDs that do not fit []int; Policies holds them
	// all. A difference means one would be silently lost.
	if len(c.PolicyIdentifiers) != len(c.Policies) {
		return nil, false
	}

	return &x509.Certificate{
		Raw:                     c.Raw,
		RawTBSCertificate:       c.RawTBSCertificate,
		RawSubjectPublicKeyInfo: c.RawSubjectPublicKeyInfo,
		RawSubject:              c.RawSubject,
		RawIssuer:               c.RawIssuer,
		SignatureAlgorithm:      sigAlg,
		PublicKeyAlgorithm:      pubAlg,
		PublicKey:               c.PublicKey,
		Version:                 c.Version,
		SerialNumber:            c.SerialNumber,
		Issuer:                  nameFromStdlib(c.Issuer),
		Subject:                 nameFromStdlib(c.Subject),
		NotBefore:               c.NotBefore,
		NotAfter:                c.NotAfter,
		KeyUsage:                x509.KeyUsage(c.KeyUsage),
		Extensions:              extensionsFromStdlib(c.Extensions),
		BasicConstraintsValid:   c.BasicConstraintsValid,
		IsCA:                    c.IsCA,
		MaxPathLen:              c.MaxPathLen,
		MaxPathLenZero:          c.MaxPathLenZero,
		SubjectKeyId:            c.SubjectKeyId,
		AuthorityKeyId:          c.AuthorityKeyId,
		OCSPServer:              c.OCSPServer,
		IssuingCertificateURL:   c.IssuingCertificateURL,
		DNSNames:                c.DNSNames,
		EmailAddresses:          c.EmailAddresses,
		IPAddresses:             c.IPAddresses,
		URIs:                    c.URIs,
		CRLDistributionPoints:   c.CRLDistributionPoints,
		PolicyIdentifiers:       oidsFromStdlib(c.PolicyIdentifiers),
	}, true
}

func signatureAlgorithmFromStdlib(a stdx509.SignatureAlgorithm) (x509.SignatureAlgorithm, bool) {
	switch a {
	case stdx509.MD2WithRSA:
		return x509.MD2WithRSA, true
	case stdx509.MD5WithRSA:
		return x509.MD5WithRSA, true
	case stdx509.SHA1WithRSA:
		return x509.SHA1WithRSA, true
	case stdx509.SHA256WithRSA:
		return x509.SHA256WithRSA, true
	case stdx509.SHA384WithRSA:
		return x509.SHA384WithRSA, true
	case stdx509.SHA512WithRSA:
		return x509.SHA512WithRSA, true
	case stdx509.DSAWithSHA1:
		return x509.DSAWithSHA1, true
	case stdx509.DSAWithSHA256:
		return x509.DSAWithSHA256, true
	case stdx509.ECDSAWithSHA1:
		return x509.ECDSAWithSHA1, true
	case stdx509.ECDSAWithSHA256:
		return x509.ECDSAWithSHA256, true
	case stdx509.ECDSAWithSHA384:
		return x509.ECDSAWithSHA384, true
	case stdx509.ECDSAWithSHA512:
		return x509.ECDSAWithSHA512, true
	case stdx509.SHA256WithRSAPSS:
		return x509.SHA256WithRSAPSS, true
	case stdx509.SHA384WithRSAPSS:
		return x509.SHA384WithRSAPSS, true
	case stdx509.SHA512WithRSAPSS:
		return x509.SHA512WithRSAPSS, true
	case stdx509.PureEd25519:
		return x509.PureEd25519, true
	default:
		// Unknown to the standard library; ct-go may know it.
		return x509.UnknownSignatureAlgorithm, false
	}
}

func publicKeyAlgorithmFromStdlib(a stdx509.PublicKeyAlgorithm) (x509.PublicKeyAlgorithm, bool) {
	switch a {
	case stdx509.RSA:
		return x509.RSA, true
	case stdx509.DSA:
		return x509.DSA, true
	case stdx509.ECDSA:
		return x509.ECDSA, true
	case stdx509.Ed25519:
		return x509.Ed25519, true
	default:
		return x509.UnknownPublicKeyAlgorithm, false
	}
}

func nameFromStdlib(n stdpkix.Name) pkix.Name {
	out := pkix.Name{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}

	if n.Names != nil {
		out.Names = make([]pkix.AttributeTypeAndValue, len(n.Names))
		for i, atv := range n.Names {
			out.Names[i] = pkix.AttributeTypeAndValue{Type: ctasn1.ObjectIdentifier(atv.Type), Value: atv.Value}
		}
	}

	return out
}

func extensionsFromStdlib(exts []stdpkix.Extension) []pkix.Extension {
	if exts == nil {
		return nil
	}

	out := make([]pkix.Extension, len(exts))
	for i, e := range exts {
		out[i] = pkix.Extension{Id: ctasn1.ObjectIdentifier(e.Id), Critical: e.Critical, Value: e.Value}
	}

	return out
}

func oidsFromStdlib(oids []stdasn1.ObjectIdentifier) []ctasn1.ObjectIdentifier {
	if oids == nil {
		return nil
	}

	out := make([]ctasn1.ObjectIdentifier, len(oids))
	for i, o := range oids {
		out[i] = ctasn1.ObjectIdentifier(o)
	}

	return out
}

// shadowCheck re-parses a fast-parsed certificate with ct-go and compares the
// output that would be streamed.
func shadowCheck(data []byte, tbsOnly bool, fast *x509.Certificate) {
	shadowChecks.Add(1)

	ref, err := parseWithCTGo(data, tbsOnly)
	if x509.IsFatal(err) || ref == nil {
		// The standard library accepted something ct-go refuses outright.
		// More is streamed than before, but there is no reference to check it
		// against, so report it.
		shadowMismatches.Add(1)
		RecordErrorThrottled("fastparse-mismatch", tileNoteInterval, "fast-parser", "fast parser", ErrCatParse,
			fmt.Sprintf("fast parser accepted a certificate ct-go rejects (%v); set scanner.fast_parser: false if this persists", err))

		return
	}

	if fields := differingLeafCertFields(leafCertFromX509cert(*fast), leafCertFromX509cert(*ref)); len(fields) > 0 {
		shadowMismatches.Add(1)
		RecordErrorThrottled("fastparse-mismatch", tileNoteInterval, "fast-parser", "fast parser", ErrCatParse,
			fmt.Sprintf("fast parser output differs from ct-go in %s for certificate sha256 %s; set scanner.fast_parser: false if this persists",
				strings.Join(fields, ", "), calculateSHA256(data)))
	}
}

// differingLeafCertFields names the JSON fields of two LeafCerts that differ,
// or nil if they encode identically. Encoded JSON is what clients receive, so
// in-memory differences that do not reach it (nil versus empty, say) are not
// counted here; the corpus tests hold the fast path to exact equality.
func differingLeafCertFields(a, b models.LeafCert) []string {
	aj, aerr := json.Marshal(a)
	bj, berr := json.Marshal(b)

	if aerr == nil && berr == nil && string(aj) == string(bj) {
		return nil
	}

	var am, bm map[string]json.RawMessage

	_ = json.Unmarshal(aj, &am)
	_ = json.Unmarshal(bj, &bm)

	var out []string

	for k, av := range am {
		if string(av) != string(bm[k]) {
			out = append(out, k)
		}
	}

	for k := range bm {
		if _, ok := am[k]; !ok {
			out = append(out, k)
		}
	}

	if len(out) == 0 {
		out = append(out, "(encoding)")
	}

	sort.Strings(out)

	return out
}
