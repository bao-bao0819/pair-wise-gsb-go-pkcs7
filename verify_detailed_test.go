package pkcs7

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"
)

func buildMultiSignerFixture(t *testing.T) (*PKCS7, *x509.CertPool, *certKeyPair, *certKeyPair) {
	t.Helper()
	content := []byte("multi-signer detailed verification content")
	root, err := createTestCertificateByIssuer("PKCS7 Detailed Root CA", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatalf("cannot generate root cert: %s", err)
	}
	signerA, err := createTestCertificateByIssuer("PKCS7 Detailed Signer A", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatalf("cannot generate signer A cert: %s", err)
	}
	signerB, err := createTestCertificateByIssuer("PKCS7 Detailed Signer B", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatalf("cannot generate signer B cert: %s", err)
	}
	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)

	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(signerA.Certificate, *signerA.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add signer A: %s", err)
	}
	if err := sd.AddSigner(signerB.Certificate, *signerB.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add signer B: %s", err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatalf("cannot finish signed data: %s", err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatalf("cannot parse signed data: %s", err)
	}
	return p7, truststore, signerA, signerB
}

func TestVerifyDetailedMultipleSigners(t *testing.T) {
	p7, truststore, _, _ := buildMultiSignerFixture(t)

	// A third SignerInfo with a corrupted signature, and a fourth that is an
	// exact copy of the first (same signer attaching a second signature).
	corrupted := p7.Signers[0]
	corrupted.EncryptedDigest = append([]byte(nil), corrupted.EncryptedDigest...)
	corrupted.EncryptedDigest[0] ^= 0xff
	duplicate := p7.Signers[0]
	p7.Signers = append(p7.Signers, corrupted, duplicate)

	policy := VerifyPolicy{Mode: RequireAtLeastK, Threshold: 2, Identity: IdentityByPublicKeyFingerprint}
	result, err := p7.VerifyDetailed(x509.VerifyOptions{
		Roots:       truststore,
		CurrentTime: time.Now(),
	}, policy)
	if err != nil {
		t.Fatalf("VerifyDetailed failed: %s", err)
	}

	if len(result.Signers) != 4 {
		t.Fatalf("expected 4 signer reports, got %d", len(result.Signers))
	}
	for _, index := range []int{0, 1, 3} {
		if !result.Signers[index].OK() {
			t.Errorf("signer report %d should be valid: %+v", index, result.Signers[index])
		}
	}
	if result.Signers[2].OK() {
		t.Error("corrupted signer report should not be valid")
	}
	if result.Signers[2].SignatureErr == nil {
		t.Error("corrupted signer report should carry a signature error")
	}
	if result.Signers[2].DigestErr != nil || result.Signers[2].ChainErr != nil {
		t.Error("corrupted signer should still pass digest and chain checks")
	}
	if result.ValidSignatures != 3 {
		t.Errorf("expected 3 valid signatures, got %d", result.ValidSignatures)
	}
	// The duplicated SignerInfo shares signer A's identity and must not
	// count twice towards the threshold.
	if result.DistinctIdentities != 2 {
		t.Errorf("expected 2 distinct identities, got %d", result.DistinctIdentities)
	}
	if !bytes.Equal(result.Signers[0].Identity, result.Signers[3].Identity) {
		t.Error("duplicated SignerInfo should map to the same identity")
	}
	if bytes.Equal(result.Signers[0].Identity, result.Signers[1].Identity) {
		t.Error("different signers should map to different identities")
	}

	// Overall failure must not discard the valid signers' evidence.
	if !result.Accepted {
		t.Error("expected acceptance with threshold 2 and 2 distinct identities")
	}
	if result.Accept(VerifyPolicy{Mode: RequireAtLeastK, Threshold: 3, Identity: IdentityByPublicKeyFingerprint}) {
		t.Error("threshold 3 must not be satisfied by 2 distinct identities")
	}
	if result.Accept(VerifyPolicy{Mode: RequireAll}) {
		t.Error("RequireAll must reject while the corrupted signer fails")
	}
	if !result.Accept(VerifyPolicy{Mode: RequireAny}) {
		t.Error("RequireAny must accept with valid signatures present")
	}

	// Certificate fingerprints must dedup the same way.
	byCert, err := p7.VerifyDetailed(x509.VerifyOptions{Roots: truststore, CurrentTime: time.Now()},
		VerifyPolicy{Mode: RequireAtLeastK, Threshold: 2, Identity: IdentityByCertificateFingerprint})
	if err != nil {
		t.Fatalf("VerifyDetailed failed: %s", err)
	}
	if byCert.DistinctIdentities != 2 || !byCert.Accepted {
		t.Errorf("certificate fingerprint dedup: got %d identities, accepted=%v",
			byCert.DistinctIdentities, byCert.Accepted)
	}

	// The signing-time attribute is reported as a claim only.
	if result.Signers[0].SigningTime == nil {
		t.Error("expected the claimed signing time to be reported")
	}
}

func TestVerifyDetailedDuplicateCannotSatisfyThreshold(t *testing.T) {
	p7, truststore, _, _ := buildMultiSignerFixture(t)

	// Keep only signer A plus a copy of its SignerInfo: two valid
	// signatures but a single identity.
	duplicate := p7.Signers[0]
	p7.Signers = []signerInfo{p7.Signers[0], duplicate}

	result, err := p7.VerifyDetailed(x509.VerifyOptions{Roots: truststore, CurrentTime: time.Now()},
		VerifyPolicy{Mode: RequireAtLeastK, Threshold: 2, Identity: IdentityByPublicKeyFingerprint})
	if err != nil {
		t.Fatalf("VerifyDetailed failed: %s", err)
	}
	if result.ValidSignatures != 2 {
		t.Errorf("expected 2 valid signatures, got %d", result.ValidSignatures)
	}
	if result.DistinctIdentities != 1 {
		t.Errorf("expected 1 distinct identity, got %d", result.DistinctIdentities)
	}
	if result.Accepted {
		t.Error("the same signer must not satisfy a threshold of 2 by re-signing")
	}
}

func TestVerifyDetailedErrorCategories(t *testing.T) {
	p7, truststore, signerA, _ := buildMultiSignerFixture(t)

	verify := func(p7 *PKCS7) *DetailedVerification {
		t.Helper()
		result, err := p7.VerifyDetailed(x509.VerifyOptions{Roots: truststore, CurrentTime: time.Now()},
			VerifyPolicy{Mode: RequireAll, Identity: IdentityByCertificateFingerprint})
		if err != nil {
			t.Fatalf("VerifyDetailed failed: %s", err)
		}
		return result
	}

	t.Run("missing certificate", func(t *testing.T) {
		missing := *p7
		missing.Certificates = nil
		result := verify(&missing)
		for i := range result.Signers {
			if !errors.Is(result.Signers[i].CertificateErr, ErrSignerCertificateNotFound) {
				t.Errorf("signer %d: expected ErrSignerCertificateNotFound, got %v", i, result.Signers[i].CertificateErr)
			}
			if result.Signers[i].Certificate != nil {
				t.Errorf("signer %d: expected no certificate", i)
			}
		}
	})

	t.Run("ambiguous certificate", func(t *testing.T) {
		ambiguous := *p7
		ambiguous.Certificates = append(append([]*x509.Certificate{}, p7.Certificates...), signerA.Certificate)
		result := verify(&ambiguous)
		// SignerInfos are a SET, so report order is not guaranteed: exactly
		// one signer must report the ambiguity and the other must stay valid.
		ambiguousCount, validCount := 0, 0
		for i := range result.Signers {
			if errors.Is(result.Signers[i].CertificateErr, ErrSignerCertificateAmbiguous) {
				ambiguousCount++
			}
			if result.Signers[i].OK() {
				validCount++
			}
		}
		if ambiguousCount != 1 {
			t.Errorf("expected exactly 1 ambiguous signer, got %d", ambiguousCount)
		}
		if validCount != 1 {
			t.Errorf("the unambiguous signer's evidence must survive, got %d valid reports", validCount)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		tampered := *p7
		tampered.Content = []byte("tampered content")
		result := verify(&tampered)
		for i := range result.Signers {
			var mismatch *MessageDigestMismatchError
			if !errors.As(result.Signers[i].DigestErr, &mismatch) {
				t.Errorf("signer %d: expected MessageDigestMismatchError, got %v", i, result.Signers[i].DigestErr)
			}
			if result.Signers[i].SignatureErr != nil {
				t.Errorf("signer %d: signature over the unchanged attributes should still verify, got %v", i, result.Signers[i].SignatureErr)
			}
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		unsupported := *p7
		unsupported.Signers = append([]signerInfo{}, p7.Signers...)
		unsupported.Signers[0].DigestEncryptionAlgorithm = pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmDSASHA1}
		result := verify(&unsupported)
		if result.Signers[0].AlgorithmErr == nil {
			t.Error("expected an unsupported algorithm error")
		}
		if result.Signers[0].SignatureErr != nil {
			t.Errorf("signature check should be skipped for unsupported algorithms, got %v", result.Signers[0].SignatureErr)
		}
		if result.Signers[0].CertificateErr != nil || result.Signers[0].DigestErr != nil || result.Signers[0].ChainErr != nil {
			t.Error("other checks should still pass for the unsupported-algorithm signer")
		}
		if !result.Signers[1].OK() {
			t.Error("signer B evidence must survive signer A's unsupported algorithm")
		}
	})

	t.Run("chain failure", func(t *testing.T) {
		result, err := p7.VerifyDetailed(x509.VerifyOptions{Roots: x509.NewCertPool(), CurrentTime: time.Now()},
			VerifyPolicy{Mode: RequireAll, Identity: IdentityByCertificateFingerprint})
		if err != nil {
			t.Fatalf("VerifyDetailed failed: %s", err)
		}
		for i := range result.Signers {
			if result.Signers[i].ChainErr == nil {
				t.Errorf("signer %d: expected a chain error with an empty root pool", i)
			}
			if result.Signers[i].SignatureErr != nil {
				t.Errorf("signer %d: signature evidence must survive the chain failure", i)
			}
		}
	})
}

func TestVerifyDetailedNoSigners(t *testing.T) {
	p7 := &PKCS7{}
	if _, err := p7.VerifyDetailed(x509.VerifyOptions{}, VerifyPolicy{Mode: RequireAny}); err == nil {
		t.Error("expected an error for a message without signers")
	}
}

func TestVerifyDetailedInvalidPolicy(t *testing.T) {
	p7, _, _, _ := buildMultiSignerFixture(t)
	if _, err := p7.VerifyDetailed(x509.VerifyOptions{}, VerifyPolicy{Mode: RequireAtLeastK, Threshold: 0}); err == nil {
		t.Error("expected an error for a zero threshold")
	}
	if _, err := p7.VerifyDetailed(x509.VerifyOptions{}, VerifyPolicy{Mode: VerifyMode(42)}); err == nil {
		t.Error("expected an error for an unknown policy mode")
	}
}
