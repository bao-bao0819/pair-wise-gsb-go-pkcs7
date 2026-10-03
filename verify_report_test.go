package pkcs7

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// buildMultiSignerCMS builds SignedData signed independently by two distinct
// ECDSA signers, then corrupts the signature of corruptedSigner (>= 0) and
// appends a verbatim copy of SignerInfo duplicateOf (>= 0) at the end.
func buildMultiSignerCMS(t *testing.T, corruptedSigner, duplicateOf int) *PKCS7 {
	t.Helper()

	signer1, err := createTestCertificateByIssuer("Detailed Report Signer 1", nil, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := createTestCertificateByIssuer("Detailed Report Signer 2", nil, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("multi-signer detailed verification evidence")
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	for _, signer := range []*certKeyPair{signer1, signer2} {
		if err := signedData.AddSigner(signer.Certificate, *signer.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	p7, err := Parse(mustFinishSignedData(t, signedData))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p7.Content, content) {
		t.Fatal("encapsulated content mismatch")
	}
	if len(p7.Signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(p7.Signers))
	}

	if corruptedSigner >= 0 {
		corruptSignature(p7.Signers[corruptedSigner].EncryptedDigest)
	}
	if duplicateOf >= 0 {
		p7.Signers = append(p7.Signers, p7.Signers[duplicateOf])
	}
	return p7
}

func corruptSignature(signature []byte) {
	signature[0] ^= 0xFF
}

func mustFinishSignedData(t *testing.T, signedData *SignedData) []byte {
	t.Helper()
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyReportMultipleSignersCorruptionAndDuplicate(t *testing.T) {
	p7 := buildMultiSignerCMS(t, 1, 0)
	if len(p7.Signers) != 3 {
		t.Fatalf("got %d SignerInfos, want 3", len(p7.Signers))
	}

	report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
	if err != nil {
		t.Fatalf("VerifyWithReport error: %v", err)
	}
	if len(report.Signers) != 3 {
		t.Fatalf("got %d reports, want one per SignerInfo (3)", len(report.Signers))
	}

	// Index 0 and its duplicated copy at index 2 are genuinely valid; the
	// overall failure must not discard that evidence.
	for _, index := range []int{0, 2} {
		signerReport := report.Signers[index]
		if !signerReport.Valid {
			t.Fatalf("signer %d should be valid, got error %v", index, signerReport.Err)
		}
		if signerReport.CertificateMatch.Status != CheckPassed ||
			signerReport.ContentDigest.Status != CheckPassed ||
			signerReport.Signature.Status != CheckPassed {
			t.Fatalf("signer %d expected all content checks passed: %+v", index, signerReport)
		}
		if signerReport.TrustChain.Status != CheckSkipped {
			t.Fatalf("signer %d trust chain should be skipped without roots", index)
		}
		if !signerReport.HasSigningTime {
			t.Fatalf("signer %d should carry a signingTime claim", index)
		}
		if signerReport.CertificateFingerprint == nil || signerReport.PublicKeyFingerprint == nil {
			t.Fatalf("signer %d should expose identity fingerprints", index)
		}
	}

	corrupted := report.Signers[1]
	if corrupted.Valid {
		t.Fatal("corrupted signer must not be valid")
	}
	if corrupted.Signature.Status != CheckFailed || !errors.Is(corrupted.Signature.Err, ErrInvalidSignature) {
		t.Fatalf("corrupted signer signature check: %+v", corrupted.Signature)
	}
	if corrupted.ContentDigest.Status != CheckPassed {
		t.Fatalf("content digest is independent of signature verification: %+v", corrupted.ContentDigest)
	}
	if corrupted.CertificateMatch.Status != CheckPassed {
		t.Fatalf("certificate match still passes for corrupted signature: %+v", corrupted.CertificateMatch)
	}

	if report.Accepted {
		t.Fatal("PolicyAll must reject when one SignerInfo is corrupted")
	}
	var policyErr *PolicyError
	if !errors.As(report.Err, &policyErr) || policyErr.Policy != PolicyAll {
		t.Fatalf("want *PolicyError for PolicyAll, got %v", report.Err)
	}
	if len(report.ValidSigners) != 2 {
		t.Fatalf("got %d valid signers, want 2 (the duplicate still verifies)", len(report.ValidSigners))
	}

	// Any valid signature is sufficient under PolicyAny.
	anyReport, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAny})
	if err != nil {
		t.Fatal(err)
	}
	if !anyReport.Accepted {
		t.Fatalf("PolicyAny should accept: %v", anyReport.Err)
	}

	// The duplicate is the same certificate and the same public key: it cannot
	// inflate the k-of-distinct count to 2 on either identity basis.
	for _, basis := range []IdentityBasis{IdentityCertificateFingerprint, IdentityPublicKeyFingerprint} {
		k2Report, err := p7.VerifyWithReport(VerifyReportOptions{
			Policy:        PolicyAtLeastKDistinct,
			K:             2,
			IdentityBasis: basis,
		})
		if err != nil {
			t.Fatal(err)
		}
		if k2Report.Accepted {
			t.Fatalf("duplicate SignerInfo must not satisfy k=2 for basis %d", basis)
		}
		if got := len(k2Report.DistinctValidIdentities); got != 1 {
			t.Fatalf("basis %d: got %d distinct identities, want 1", basis, got)
		}

		k1Report, err := p7.VerifyWithReport(VerifyReportOptions{
			Policy:        PolicyAtLeastKDistinct,
			K:             1,
			IdentityBasis: basis,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !k1Report.Accepted {
			t.Fatalf("basis %d: k=1 with one distinct identity should accept: %v", basis, k1Report.Err)
		}
	}

	// Old behavior stays unchanged: Verify fails when a signer is corrupted and
	// succeeds when every signer is intact.
	if err := p7.Verify(); err == nil {
		t.Fatal("legacy Verify should fail on the corrupted SignerInfo")
	}
	intact := buildMultiSignerCMS(t, -1, -1)
	if err := intact.Verify(); err != nil {
		t.Fatalf("legacy Verify failed for intact CMS: %v", err)
	}
}

func TestVerifyReportAllValidSignersSatisfyK(t *testing.T) {
	p7 := buildMultiSignerCMS(t, -1, -1)
	report, err := p7.VerifyWithReport(VerifyReportOptions{
		Policy:        PolicyAtLeastKDistinct,
		K:             2,
		IdentityBasis: IdentityCertificateFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Accepted {
		t.Fatalf("two distinct signers should satisfy k=2: %v", report.Err)
	}
	if got := len(report.DistinctValidIdentities); got != 2 {
		t.Fatalf("got %d distinct identities, want 2", got)
	}
	if len(report.ValidSigners) != 2 {
		t.Fatalf("got %d valid signers, want 2", len(report.ValidSigners))
	}
}

func TestVerifyReportInvalidThreshold(t *testing.T) {
	p7 := buildMultiSignerCMS(t, -1, -1)
	if _, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAtLeastKDistinct, K: 0}); err == nil {
		t.Fatal("k=0 should be rejected")
	}
}

func TestVerifyReportNoSigners(t *testing.T) {
	p7 := buildMultiSignerCMS(t, -1, -1)
	p7.Signers = nil
	if _, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll}); err == nil {
		t.Fatal("expected error for SignedData without signers")
	}
}

func TestVerifyReportMissingCertificate(t *testing.T) {
	p7 := buildMultiSignerCMS(t, -1, -1)
	p7.Certificates = nil

	report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
	if err != nil {
		t.Fatal(err)
	}
	for index, signerReport := range report.Signers {
		if signerReport.Valid {
			t.Fatalf("signer %d cannot be valid without its certificate", index)
		}
		if signerReport.CertificateMatch.Status != CheckFailed ||
			!errors.Is(signerReport.CertificateMatch.Err, ErrCertificateNotFound) {
			t.Fatalf("signer %d cert check: %+v", index, signerReport.CertificateMatch)
		}
		if signerReport.Signature.Status != CheckSkipped {
			t.Fatalf("signer %d signature check must be skipped without cert", index)
		}
		if signerReport.TrustChain.Status != CheckSkipped {
			t.Fatalf("signer %d trust chain must be skipped without cert", index)
		}
	}
	if report.Accepted {
		t.Fatal("PolicyAll must reject when certificates are missing")
	}
}

// selfSignedECDSACertificateWithSerial creates a self-signed P-256 certificate
// with the given subject and serial number.
func selfSignedECDSACertificateWithSerial(t *testing.T, commonName string, serial *big.Int, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Acme Co"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyReportAmbiguousCertificate(t *testing.T) {
	p7 := buildMultiSignerCMS(t, -1, -1)
	target := p7.Signers[0]
	original := getCertFromCertsByIssuerAndSerial(p7.Certificates, target.IssuerAndSerialNumber)
	if original == nil {
		t.Fatal("original signer certificate not found")
	}

	// A second, distinct self-signed certificate with a different key but the
	// same subject/issuer/serial creates two distinct candidates.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := selfSignedECDSACertificateWithSerial(t, original.Subject.CommonName, original.SerialNumber, otherKey)
	if !bytes.Equal(duplicate.RawIssuer, original.RawIssuer) ||
		duplicate.SerialNumber.Cmp(original.SerialNumber) != 0 {
		t.Fatal("test setup: duplicate cert does not share issuer/serial")
	}
	p7.Certificates = append(p7.Certificates, duplicate)

	report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAny})
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := report.Signers[0]
	if ambiguous.CertificateMatch.Status != CheckFailed ||
		!errors.Is(ambiguous.CertificateMatch.Err, ErrCertificateAmbiguous) {
		t.Fatalf("expected ambiguous certificate, got %+v", ambiguous.CertificateMatch)
	}
	if ambiguous.Signature.Status != CheckSkipped || ambiguous.TrustChain.Status != CheckSkipped {
		t.Fatalf("downstream checks must be skipped for ambiguous cert: %+v %+v",
			ambiguous.Signature, ambiguous.TrustChain)
	}
	if ambiguous.Valid {
		t.Fatal("an ambiguous signer cannot be considered valid")
	}
	// The second, unaffected signer still provides genuine valid evidence.
	if !report.Signers[1].Valid {
		t.Fatalf("unrelated signer evidence must be preserved: %+v", report.Signers[1])
	}
	if !report.Accepted {
		t.Fatal("PolicyAny should accept via the unaffected second signer")
	}

	// Byte-identical duplicate certificates are harmless and collapse to one
	// candidate, so the ambiguity disappears.
	collapsed := buildMultiSignerCMS(t, -1, -1)
	collapsedOriginal := getCertFromCertsByIssuerAndSerial(collapsed.Certificates, collapsed.Signers[0].IssuerAndSerialNumber)
	collapsed.Certificates = append(collapsed.Certificates, collapsedOriginal)
	reportCollapsed, err := collapsed.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
	if err != nil {
		t.Fatal(err)
	}
	if !reportCollapsed.Accepted {
		t.Fatalf("identical duplicate certs should not be ambiguous: %v", reportCollapsed.Err)
	}
}

func TestVerifyReportUnsupportedAlgorithmAndDigestMismatch(t *testing.T) {
	t.Run("unsupported signature algorithm", func(t *testing.T) {
		p7 := buildMultiSignerCMS(t, -1, -1)
		p7.Signers[0].DigestEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}

		report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAny})
		if err != nil {
			t.Fatal(err)
		}
		signerReport := report.Signers[0]
		if signerReport.Signature.Status != CheckFailed ||
			!errors.Is(signerReport.Signature.Err, ErrUnsupportedAlgorithm) {
			t.Fatalf("expected unsupported algorithm, got %+v", signerReport.Signature)
		}
		if signerReport.ContentDigest.Status != CheckPassed {
			t.Fatalf("digest should still be verifiable: %+v", signerReport.ContentDigest)
		}
		// PolicyAny still accepts through the untouched second signer.
		if !report.Accepted {
			t.Fatalf("PolicyAny should accept via the second signer: %v", report.Err)
		}
	})

	t.Run("unsupported digest algorithm", func(t *testing.T) {
		p7 := buildMultiSignerCMS(t, -1, -1)
		p7.Signers[0].DigestAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 7}

		report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
		if err != nil {
			t.Fatal(err)
		}
		signerReport := report.Signers[0]
		if signerReport.ContentDigest.Status != CheckFailed ||
			!errors.Is(signerReport.ContentDigest.Err, ErrUnsupportedAlgorithm) {
			t.Fatalf("expected unsupported digest algorithm, got %+v", signerReport.ContentDigest)
		}
		if !report.Signers[1].Valid || report.Signers[1].ContentDigest.Status != CheckPassed {
			t.Fatal("second signer's evidence must be retained")
		}
	})

	t.Run("digest mismatch separated from signature failure", func(t *testing.T) {
		p7 := buildMultiSignerCMS(t, -1, -1)
		p7.Content = []byte("tampered encapsulated content after signing")

		report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
		if err != nil {
			t.Fatal(err)
		}
		for index, signerReport := range report.Signers {
			if signerReport.ContentDigest.Status != CheckFailed ||
				!errors.Is(signerReport.ContentDigest.Err, ErrDigestMismatch) {
				t.Fatalf("signer %d expected digest mismatch, got %+v", index, signerReport.ContentDigest)
			}
			// The signature covers the authenticated attributes, which are
			// unchanged, so it still verifies: digest and signature evidence
			// stay independent.
			if signerReport.Signature.Status != CheckPassed {
				t.Fatalf("signer %d signature over attributes should still pass, got %+v",
					index, signerReport.Signature)
			}
			if signerReport.CertificateMatch.Status != CheckPassed {
				t.Fatalf("certificate is still valid evidence: %+v", signerReport.CertificateMatch)
			}
		}
		if report.Accepted {
			t.Fatal("PolicyAll must reject tampered content")
		}
	})
}

func TestVerifyReportTrustChainUsesCallerTime(t *testing.T) {
	root, err := createTestCertificateByIssuer("Detailed Report Root", nil, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := createTestCertificateByIssuer("Detailed Report Leaf", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("trust chain evidence"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.AddSignerChain(leaf.Certificate, *leaf.PrivateKey,
		[]*x509.Certificate{root.Certificate}, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(mustFinishSignedData(t, signedData))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)

	// Valid at the current caller time.
	now := time.Now()
	report, err := p7.VerifyWithReport(VerifyReportOptions{
		Policy:      PolicyAll,
		Roots:       roots,
		CurrentTime: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Accepted {
		t.Fatalf("chain should verify now: %v", report.Err)
	}
	if report.Signers[0].TrustChain.Status != CheckPassed {
		t.Fatalf("trust chain: %+v", report.Signers[0].TrustChain)
	}

	// A caller time well after expiry fails regardless of the signed
	// signingTime claim, which is around now.
	expired := now.AddDate(10, 0, 0)
	expiredReport, err := p7.VerifyWithReport(VerifyReportOptions{
		Policy:      PolicyAll,
		Roots:       roots,
		CurrentTime: expired,
	})
	if err != nil {
		t.Fatal(err)
	}
	signerReport := expiredReport.Signers[0]
	if signerReport.TrustChain.Status != CheckFailed {
		t.Fatalf("expected chain failure at %s, got %+v", expired, signerReport.TrustChain)
	}
	if !signerReport.HasSigningTime {
		t.Fatal("signingTime claim should still be reported")
	}
	if expiredReport.Accepted {
		t.Fatal("expired caller time must reject even with a valid signingTime claim")
	}
}

func TestVerifyReportPublicKeyDeduplicationAcrossCertificates(t *testing.T) {
	// Two distinct certificates that share the same public key.
	sharedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert1 := selfSignedECDSACertificateWithSerial(t, "Shared Key Identity One", big.NewInt(9001), sharedKey)
	cert2 := selfSignedECDSACertificateWithSerial(t, "Shared Key Identity Two", big.NewInt(9002), sharedKey)

	signedData, err := NewSignedData([]byte("same key, different certificates"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	for _, cert := range []*x509.Certificate{cert1, cert2} {
		if err := signedData.AddSigner(cert, sharedKey, SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	p7, err := Parse(mustFinishSignedData(t, signedData))
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(p7.Signers))
	}

	// Certificate fingerprint basis counts two distinct identities.
	certReport, err := p7.VerifyWithReport(VerifyReportOptions{
		Policy:        PolicyAtLeastKDistinct,
		K:             2,
		IdentityBasis: IdentityCertificateFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !certReport.Accepted || len(certReport.DistinctValidIdentities) != 2 {
		t.Fatalf("certificate basis: accepted=%v distinct=%d",
			certReport.Accepted, len(certReport.DistinctValidIdentities))
	}

	// Public-key fingerprint basis must collapse them to one identity, so the
	// same person cannot satisfy k=2 by re-signing with a renewed certificate.
	keyReport, err := p7.VerifyWithReport(VerifyReportOptions{
		Policy:        PolicyAtLeastKDistinct,
		K:             2,
		IdentityBasis: IdentityPublicKeyFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if keyReport.Accepted {
		t.Fatal("public-key basis must not count shared-key certificates twice")
	}
	if got := len(keyReport.DistinctValidIdentities); got != 1 {
		t.Fatalf("got %d public-key identities, want 1", got)
	}
	if !bytes.Equal(certReport.Signers[0].PublicKeyFingerprint,
		certReport.Signers[1].PublicKeyFingerprint) {
		t.Fatal("shared-key certificates should have equal public-key fingerprints")
	}
}

func TestVerifyReportSignerWithoutAttributes(t *testing.T) {
	pair, err := createTestCertificateByIssuer("No Attributes Signer", nil, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("signature directly over content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(mustFinishSignedData(t, signedData))
	if err != nil {
		t.Fatal(err)
	}
	report, err := p7.VerifyWithReport(VerifyReportOptions{Policy: PolicyAll})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Accepted {
		t.Fatalf("SignWithoutAttr CMS should verify: %v", report.Err)
	}
	signerReport := report.Signers[0]
	if signerReport.ContentDigest.Status != CheckSkipped {
		t.Fatalf("content digest must be skipped without attributes: %+v", signerReport.ContentDigest)
	}
	if signerReport.Signature.Status != CheckPassed {
		t.Fatalf("direct content signature must pass: %+v", signerReport.Signature)
	}
}
