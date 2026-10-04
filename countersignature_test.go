package pkcs7

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func createMLDSATestCertificateWithSerial(t *testing.T, test mlDSATestCase, serial int64) (*x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	privateKey, err := mldsa.GenerateKey(test.parameters)
	if err != nil {
		t.Fatalf("generate %s key: %v", test.name, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: test.name + " CMS countersigner test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    test.signatureAlgorithm,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.PublicKey(), privateKey)
	if err != nil {
		t.Fatalf("create %s certificate: %v", test.name, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s certificate: %v", test.name, err)
	}
	return certificate, privateKey
}

func newCountersignatureTestPair(t *testing.T, name string, sigalg x509.SignatureAlgorithm) *certKeyPair {
	t.Helper()
	pair, err := createTestCertificateByIssuer(name, nil, sigalg, true)
	if err != nil {
		t.Fatalf("cannot create %s certificate: %v", name, err)
	}
	return pair
}

func buildCountersignedData(t *testing.T, sigalg, countersigalg x509.SignatureAlgorithm) ([]byte, *certKeyPair, *certKeyPair, *x509.CertPool) {
	t.Helper()
	root := newCountersignatureTestPair(t, "PKCS7 Countersignature Root CA", sigalg)
	signerPair, err := createTestCertificateByIssuer("PKCS7 Countersignature Signer", root, sigalg, false)
	if err != nil {
		t.Fatalf("cannot create signer certificate: %v", err)
	}
	counterRoot := newCountersignatureTestPair(t, "PKCS7 Countersignature Counter Root CA", countersigalg)
	counterPair, err := createTestCertificateByIssuer("PKCS7 Countersignature Second Signer", counterRoot, countersigalg, false)
	if err != nil {
		t.Fatalf("cannot create countersigner certificate: %v", err)
	}

	content := []byte("countersignature test content")
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	signerDigest, err := GetDigestOIDForSignatureAlgorithm(signerPair.Certificate.SignatureAlgorithm)
	if err != nil {
		t.Fatalf("GetDigestOIDForSignatureAlgorithm: %v", err)
	}
	signedData.SetDigestAlgorithm(signerDigest)
	if err := signedData.AddSignerChain(signerPair.Certificate, *signerPair.PrivateKey, nil, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSignerChain: %v", err)
	}
	if err := signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatalf("AddCountersigner: %v", err)
	}
	der, err := signedData.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	roots.AddCert(counterRoot.Certificate)
	return der, signerPair, counterPair, roots
}

func hasAttribute(attrs []attribute, oid asn1.ObjectIdentifier) bool {
	for _, attr := range attrs {
		if attr.Type.Equal(oid) {
			return true
		}
	}
	return false
}

func cloneAttributes(attrs []attribute) []attribute {
	clone := make([]attribute, len(attrs))
	copy(clone, attrs)
	return clone
}

// mutateCountersignature replaces the nth countersignature SignerInfo inside
// the signer's id-countersignature attribute with the result of mutate, then
// re-encodes the SET value. The verifier reads p7.Signers directly.
func mutateCountersignature(t *testing.T, p7 *PKCS7, index int, mutate func(*signerInfo)) {
	t.Helper()
	signer := &p7.Signers[0]
	for i := range signer.UnauthenticatedAttributes {
		attr := &signer.UnauthenticatedAttributes[i]
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		members, err := countersignatureSetMembers(attr.Value.Bytes)
		if err != nil {
			t.Fatalf("countersignature set members: %v", err)
		}
		rest := members
		var counters []signerInfo
		for len(rest) > 0 {
			var counter signerInfo
			rest, err = asn1.Unmarshal(rest, &counter)
			if err != nil {
				t.Fatalf("unmarshal countersignature: %v", err)
			}
			counters = append(counters, counter)
		}
		if index >= len(counters) {
			t.Fatalf("countersignature index %d out of range (have %d)", index, len(counters))
		}
		mutate(&counters[index])
		var encoded []byte
		for j := range counters {
			b, err := asn1.Marshal(counters[j])
			if err != nil {
				t.Fatalf("marshal countersignature: %v", err)
			}
			encoded = append(encoded, b...)
		}
		setTLV, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: encoded})
		if err != nil {
			t.Fatalf("marshal countersignature set: %v", err)
		}
		attr.Value.Bytes = setTLV
		attr.Value.FullBytes = nil
		return
	}
	t.Fatal("no countersignature attribute found")
}

func TestCountersignature(t *testing.T) {
	for _, sigalg := range []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.ECDSAWithSHA256,
		x509.PureEd25519,
	} {
		t.Run(sigalg.String(), func(t *testing.T) {
			der, _, counterPair, roots := buildCountersignedData(t, sigalg, sigalg)
			p7, err := Parse(der)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(p7.Signers) != 1 {
				t.Fatalf("signer count = %d, want 1", len(p7.Signers))
			}
			signer := p7.Signers[0]
			if !hasAttribute(signer.UnauthenticatedAttributes, OIDAttributeCountersignature) {
				t.Fatal("countersignature unsigned attribute missing")
			}

			reports, structuralErr := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
			if structuralErr != nil {
				t.Fatalf("VerifySignatures structural error: %v", structuralErr)
			}
			if err := ReportsError(reports); err != nil {
				t.Fatalf("verification reports error: %v", err)
			}
			report := reports[0]
			if report.OriginalError != nil {
				t.Fatalf("original signature error: %v", report.OriginalError)
			}
			if len(report.Countersignatures) != 1 {
				t.Fatalf("countersignature count = %d, want 1", len(report.Countersignatures))
			}
			counter := report.Countersignatures[0]
			if counter.Error != nil {
				t.Fatalf("countersignature error: %v", counter.Error)
			}
			if !counter.Countersigner.Equal(counterPair.Certificate) {
				t.Error("countersigner certificate mismatch")
			}
			if counter.Countersigner.Equal(report.Signer) {
				t.Error("countersigner must differ from primary signer")
			}

			// Legacy verification still succeeds and ignores the unsigned
			// countersignature attribute.
			if err := p7.VerifyWithChain(roots); err != nil {
				t.Fatalf("VerifyWithChain after countersigning: %v", err)
			}
		})
	}
}

func TestCountersignatureMLDSA(t *testing.T) {
	test := mlDSATestCases[0]
	signerCert, signerKey := createMLDSATestCertificate(t, test)
	content := []byte("mldsa countersignature content")
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA512)
	if err := signedData.AddSigner(signerCert, signerKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	counterCert, counterKey := createMLDSATestCertificateWithSerial(t, test, 2)
	if err := signedData.AddCountersigner(0, counterCert, counterKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	reports, structuralErr := p7.VerifySignatures(x509.VerifyOptions{})
	if structuralErr != nil {
		t.Fatal(structuralErr)
	}
	if err := ReportsError(reports); err != nil {
		t.Fatalf("ML-DSA countersignature verification failed: %v", err)
	}
}

func TestCountersignatureDoesNotChangeOriginalSigner(t *testing.T) {
	content := []byte("original signature stays intact")
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	signerPair, err := createTestCertificateByIssuer("Original Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterPair, err := createTestCertificateByIssuer("Countersigner", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}

	originalSigner := signedData.sd.SignerInfos[0]
	originalAuthenticated := cloneAttributes(originalSigner.AuthenticatedAttributes)
	originalDigest := append([]byte(nil), originalSigner.EncryptedDigest...)

	if err := signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	updated := signedData.sd.SignerInfos[0]
	if !reflect.DeepEqual(updated.AuthenticatedAttributes, originalAuthenticated) {
		t.Error("adding a countersignature modified the original signed attributes")
	}
	if !reflect.DeepEqual(updated.EncryptedDigest, originalDigest) {
		t.Error("adding a countersignature modified the original signatureValue")
	}
}

func TestMultipleCountersignaturesReportedSeparately(t *testing.T) {
	content := []byte("two approvers")
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	signerPair, err := createTestCertificateByIssuer("Original Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterOne, err := createTestCertificateByIssuer("Countersigner One", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterTwo, err := createTestCertificateByIssuer("Countersigner Two", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatal(err)
	}

	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddCountersigner(0, counterOne.Certificate, *counterOne.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddCountersigner(0, counterTwo.Certificate, *counterTwo.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt only the second countersignature signatureValue.
	mutateCountersignature(t, p7, 1, func(counter *signerInfo) {
		counter.EncryptedDigest[0] ^= 0xFF
	})

	reports, err := p7.VerifySignatures(x509.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	counters := reports[0].Countersignatures
	if len(counters) != 2 {
		t.Fatalf("countersignature count = %d, want 2", len(counters))
	}
	if counters[0].Error != nil {
		t.Errorf("first countersignature should still verify, got %v", counters[0].Error)
	}
	if counters[1].Error == nil {
		t.Error("second countersignature should fail after its signatureValue was corrupted")
	}
	if reports[0].OriginalError != nil {
		t.Errorf("original signature must remain valid, got %v", reports[0].OriginalError)
	}
}

func TestCountersignatureTamperScenarios(t *testing.T) {
	der, _, _, roots := buildCountersignedData(t, x509.SHA256WithRSA, x509.SHA256WithRSA)

	t.Run("content modified", func(t *testing.T) {
		p7, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		p7.Content = []byte("tampered content")
		reports, err := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
		if err != nil {
			t.Fatal(err)
		}
		var digestMismatch *MessageDigestMismatchError
		if !errors.As(reports[0].OriginalError, &digestMismatch) {
			t.Fatalf("original error = %v, want MessageDigestMismatchError", reports[0].OriginalError)
		}
		for i, counter := range reports[0].Countersignatures {
			if counter.Error != nil {
				t.Errorf("countersignature %d must still verify after content tampering: %v", i, counter.Error)
			}
		}
	})

	t.Run("original signatureValue modified", func(t *testing.T) {
		p7, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		p7.Signers[0].EncryptedDigest[0] ^= 0xFF
		reports, err := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
		if err != nil {
			t.Fatal(err)
		}
		if reports[0].OriginalError == nil {
			t.Fatal("original signature should fail")
		}
		var digestMismatch *MessageDigestMismatchError
		if errors.As(reports[0].OriginalError, &digestMismatch) {
			t.Fatal("original failure must be a cryptographic signature failure, not a content digest mismatch")
		}
		counter := reports[0].Countersignatures[0]
		var counterDigestMismatch *CountersignatureDigestMismatchError
		if !errors.As(counter.Error, &counterDigestMismatch) {
			t.Fatalf("countersignature error = %v, want countersigned messageDigest mismatch", counter.Error)
		}
	})

	t.Run("only countersignature modified", func(t *testing.T) {
		p7, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		mutateCountersignature(t, p7, 0, func(counter *signerInfo) {
			counter.EncryptedDigest[0] ^= 0xFF
		})
		reports, err := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
		if err != nil {
			t.Fatal(err)
		}
		if reports[0].OriginalError != nil {
			t.Fatalf("original signature should remain valid, got %v", reports[0].OriginalError)
		}
		counter := reports[0].Countersignatures[0]
		if counter.Error == nil {
			t.Fatal("countersignature should fail after tampering")
		}
		var digestMismatch *MessageDigestMismatchError
		var counterDigestMismatch *CountersignatureDigestMismatchError
		if errors.As(counter.Error, &digestMismatch) || errors.As(counter.Error, &counterDigestMismatch) {
			t.Fatalf("counter failure must be a cryptographic signature failure, got digest mismatch: %v", counter.Error)
		}
	})
}

func TestAddCountersignerRejectsContentType(t *testing.T) {
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	signerPair, err := createTestCertificateByIssuer("Original Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterPair, err := createTestCertificateByIssuer("Countersigner", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("forbidden attribute"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	contentTypeValue, err := asn1.Marshal(OIDData)
	if err != nil {
		t.Fatal(err)
	}
	err = signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{
		ExtraSignedAttributes: []Attribute{{
			Type:  OIDAttributeContentType,
			Value: asn1.RawValue{Bytes: contentTypeValue},
		}},
	})
	if !errors.Is(err, ErrCountersignatureForbiddenContentType) {
		t.Fatalf("AddCountersigner error = %v, want ErrCountersignatureForbiddenContentType", err)
	}
}

func TestVerifyCountersignatureRejectsContentType(t *testing.T) {
	der, _, _, roots := buildCountersignedData(t, x509.SHA256WithRSA, x509.SHA256WithRSA)
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	contentTypeValue, err := asn1.Marshal(OIDData)
	if err != nil {
		t.Fatal(err)
	}
	mutateCountersignature(t, p7, 0, func(counter *signerInfo) {
		counter.AuthenticatedAttributes = append(counter.AuthenticatedAttributes, attribute{
			Type:  OIDAttributeContentType,
			Value: asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: contentTypeValue},
		})
	})
	reports, err := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(reports[0].Countersignatures[0].Error, ErrCountersignatureForbiddenContentType) {
		t.Fatalf("countersignature error = %v, want ErrCountersignatureForbiddenContentType",
			reports[0].Countersignatures[0].Error)
	}
	if reports[0].OriginalError != nil {
		t.Fatalf("original signature should still verify: %v", reports[0].OriginalError)
	}
}

func TestCountersignatureMissingCertificate(t *testing.T) {
	der, _, _, roots := buildCountersignedData(t, x509.SHA256WithRSA, x509.SHA256WithRSA)
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	p7.Certificates = nil
	reports, err := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].OriginalError == nil {
		t.Error("original signature should fail without a signer certificate")
	}
	if got := reports[0].Countersignatures[0].Error; got == nil || got.Error() != "pkcs7: No certificate for countersigner" {
		t.Fatalf("countersignature error = %v, want missing countersigner certificate", got)
	}
}

func TestAddCountersignerIndexValidation(t *testing.T) {
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	counterPair, err := createTestCertificateByIssuer("Countersigner", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("no signers yet"))
	if err != nil {
		t.Fatal(err)
	}
	err = signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{})
	if err == nil {
		t.Fatal("AddCountersigner should reject an out-of-range target index")
	}
	err = signedData.AddCountersigner(-1, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{})
	if err == nil {
		t.Fatal("AddCountersigner should reject a negative target index")
	}
}

func TestCountersignatureChainVerification(t *testing.T) {
	der, signerPair, counterPair, roots := buildCountersignedData(t, x509.SHA256WithRSA, x509.ECDSAWithSHA256)
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	reports, structuralErr := p7.VerifySignatures(x509.VerifyOptions{Roots: roots})
	if structuralErr != nil {
		t.Fatal(structuralErr)
	}
	if err := ReportsError(reports); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
	if !reports[0].Signer.Equal(signerPair.Certificate) {
		t.Error("primary signer cert mismatch")
	}
	if !reports[0].Countersignatures[0].Countersigner.Equal(counterPair.Certificate) {
		t.Error("countersigner cert mismatch")
	}

	// An unrelated truststore must fail both layers with chain errors rather
	// than digest or signature errors.
	otherRoot := newCountersignatureTestPair(t, "Unrelated Root", x509.SHA256WithRSA)
	otherPool := x509.NewCertPool()
	otherPool.AddCert(otherRoot.Certificate)
	reports, structuralErr = p7.VerifySignatures(x509.VerifyOptions{Roots: otherPool})
	if structuralErr != nil {
		t.Fatal(structuralErr)
	}
	if reports[0].OriginalError == nil {
		t.Error("primary signature must fail chain verification against an unrelated root")
	}
	counter := reports[0].Countersignatures[0]
	if counter.Error == nil {
		t.Error("countersignature must fail chain verification against an unrelated root")
	}
}

func TestCountersignatureDetachedContent(t *testing.T) {
	content := []byte("detached countersignature content")
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	signerPair, err := createTestCertificateByIssuer("Original Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterPair, err := createTestCertificateByIssuer("Countersigner", root, x509.ECDSAWithSHA384, false)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{SkipSigningTime: true}); err != nil {
		t.Fatal(err)
	}
	signedData.Detach()
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	p7.Content = content
	reports, err := p7.VerifySignatures(x509.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReportsError(reports); err != nil {
		t.Fatalf("detached countersigned data failed: %v", err)
	}
	if len(reports[0].Countersignatures) != 1 {
		t.Fatalf("countersignature count = %d, want 1", len(reports[0].Countersignatures))
	}
}

func TestCountersignatureDigestCoversSignatureValue(t *testing.T) {
	root := newCountersignatureTestPair(t, "Root", x509.SHA256WithRSA)
	signerPair, err := createTestCertificateByIssuer("Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterPair, err := createTestCertificateByIssuer("Counter", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := NewSignedData([]byte("digest coverage"))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	originalSignature := append([]byte(nil), sd.sd.SignerInfos[0].EncryptedDigest...)
	if err := sd.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	attr := p7.Signers[0].UnauthenticatedAttributes[0]
	if !attr.Type.Equal(OIDAttributeCountersignature) {
		t.Fatal("wrong attribute OID")
	}
	members, err := countersignatureSetMembers(attr.Value.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var counter signerInfo
	if _, err := asn1.Unmarshal(members, &counter); err != nil {
		t.Fatal(err)
	}
	var digest []byte
	if err := unmarshalAttribute(counter.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(originalSignature)
	if !bytes.Equal(digest, sum[:]) {
		t.Fatalf("countersigned digest = %x, want SHA-256 over original signatureValue %x", digest, sum)
	}
	contentSum := sha256.Sum256([]byte("digest coverage"))
	if bytes.Equal(digest, contentSum[:]) {
		t.Fatal("countersigned digest incorrectly covers the content")
	}
	if !bytes.Equal(p7.Signers[0].EncryptedDigest, originalSignature) {
		t.Fatal("original signatureValue changed after countersigning and re-parsing")
	}
}

func TestNestedCountersignatureRejected(t *testing.T) {
	der, _, _, _ := buildCountersignedData(t, x509.SHA256WithRSA, x509.SHA256WithRSA)
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	mutateCountersignature(t, p7, 0, func(counter *signerInfo) {
		counter.UnauthenticatedAttributes = append(counter.UnauthenticatedAttributes, attribute{
			Type:  OIDAttributeCountersignature,
			Value: asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{0x30, 0x00}},
		})
	})
	reports, err := p7.VerifySignatures(x509.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	counter := reports[0].Countersignatures[0]
	if !errors.Is(counter.Error, ErrNestedCountersignature) {
		t.Fatalf("countersignature error = %v, want ErrNestedCountersignature", counter.Error)
	}
	if len(counter.NestedRaw) != 1 {
		t.Fatalf("nested raw attribute count = %d, want 1", len(counter.NestedRaw))
	}
	if reports[0].OriginalError != nil {
		t.Fatalf("original signature should still verify: %v", reports[0].OriginalError)
	}

	// Creating a nested countersignature through the builder is also rejected.
	root := newCountersignatureTestPair(t, "Root2", x509.SHA256WithRSA)
	signedData, err := NewSignedData([]byte("nested creation rejected"))
	if err != nil {
		t.Fatal(err)
	}
	signerPair, err := createTestCertificateByIssuer("Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	counterPair, err := createTestCertificateByIssuer("Countersigner", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(signerPair.Certificate, *signerPair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{}); err != nil {
		t.Fatal(err)
	}
	err = signedData.AddCountersigner(0, counterPair.Certificate, *counterPair.PrivateKey, CountersignerConfig{
		ExtraUnsignedAttributes: []Attribute{{
			Type:  OIDAttributeCountersignature,
			Value: asn1.RawValue{},
		}},
	})
	if !errors.Is(err, ErrNestedCountersignature) {
		t.Fatalf("AddCountersigner error = %v, want ErrNestedCountersignature", err)
	}
}
