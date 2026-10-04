package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func newCounterTestCert(t *testing.T, name string, isCA bool) *certKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %q: %v", name, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial for %q: %v", name, err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert %q: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert %q: %v", name, err)
	}
	var key crypto.PrivateKey = priv
	return &certKeyPair{Certificate: cert, PrivateKey: &key}
}

func newCounterSignedMessage(t *testing.T, content []byte) (signedBytes []byte, p7 *PKCS7, primary, counter *certKeyPair) {
	t.Helper()
	primary = newCounterTestCert(t, "primary signer", false)
	counter = newCounterTestCert(t, "countersigner", false)

	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(primary.Certificate, *primary.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner: %v", err)
	}
	signedBytes, err = sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	p7, err = Parse(signedBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := p7.AddCountersignature(0, counter.Certificate, *counter.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddCountersignature: %v", err)
	}
	return signedBytes, p7, primary, counter
}

func TestCountersignatureRoundTrip(t *testing.T) {
	content := []byte("countersign me")
	originalBytes, p7, _, counter := newCounterSignedMessage(t, content)

	// The original signed message bytes must be untouched apart from the
	// unsigned attributes of the target SignerInfo: authenticated attributes
	// and the primary signatureValue stay byte-identical.
	original, err := Parse(originalBytes)
	if err != nil {
		t.Fatalf("Parse original: %v", err)
	}
	originalAttrBytes, err := marshalAttributes(original.Signers[0].AuthenticatedAttributes)
	if err != nil {
		t.Fatalf("marshal original attrs: %v", err)
	}
	counterAttrBytes, err := marshalAttributes(p7.Signers[0].AuthenticatedAttributes)
	if err != nil {
		t.Fatalf("marshal counter attrs: %v", err)
	}
	if !bytes.Equal(originalAttrBytes, counterAttrBytes) {
		t.Fatal("adding a countersignature changed the original authenticated attributes")
	}
	if !bytes.Equal(original.Signers[0].EncryptedDigest, p7.Signers[0].EncryptedDigest) {
		t.Fatal("adding a countersignature changed the original signatureValue")
	}

	counterBytes, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(counterBytes)
	if err != nil {
		t.Fatalf("Parse countersigned: %v", err)
	}

	// Legacy verification still covers the original signature only and passes.
	if err := parsed.Verify(); err != nil {
		t.Fatalf("original signature verification failed: %v", err)
	}

	results, err := parsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 signer result, got %d", len(results))
	}
	if results[0].PrimaryError != nil {
		t.Fatalf("primary signature error: %v", results[0].PrimaryError)
	}
	if len(results[0].Countersignatures) != 1 {
		t.Fatalf("expected 1 countersignature, got %d", len(results[0].Countersignatures))
	}
	if results[0].Countersignatures[0].Error != nil {
		t.Fatalf("countersignature verification failed: %v", results[0].Countersignatures[0].Error)
	}
	if !results[0].Countersignatures[0].Certificate.Equal(counter.Certificate) {
		t.Fatal("countersigner certificate was not carried in the message")
	}

	raw, err := parsed.RawCountersignatures(0)
	if err != nil {
		t.Fatalf("RawCountersignatures: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("expected 1 raw countersignature, got %d", len(raw))
	}
}

func TestCountersignatureRequiresValidSignerIndex(t *testing.T) {
	_, p7, _, counter := newCounterSignedMessage(t, []byte("x"))
	for _, index := range []int{-1, 1, 7} {
		if err := p7.AddCountersignature(index, counter.Certificate, *counter.PrivateKey, SignerInfoConfig{}); err == nil {
			t.Fatalf("expected error for signer index %d", index)
		}
	}
}

func TestCountersignatureForbidsContentType(t *testing.T) {
	_, p7, _, counter := newCounterSignedMessage(t, []byte("x"))
	config := SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{Type: OIDAttributeContentType, Value: OIDData},
		},
	}
	err := p7.AddCountersignature(0, counter.Certificate, *counter.PrivateKey, config)
	if !errors.Is(err, ErrCountersignatureContentTypeForbidden) {
		t.Fatalf("expected ErrCountersignatureContentTypeForbidden, got %v", err)
	}
}

func TestMultipleCountersignaturesReportedIndividually(t *testing.T) {
	content := []byte("two approvals")
	_, p7, _, _ := newCounterSignedMessage(t, content)
	counter2 := newCounterTestCert(t, "second countersigner", false)
	counter3 := newCounterTestCert(t, "third countersigner", false)

	if err := p7.AddCountersignature(0, counter2.Certificate, *counter2.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("second countersignature: %v", err)
	}
	// Multiple countersignatures are grouped in one attribute SET and must
	// each be reported as a separate result.
	if err := p7.AddCountersignature(0, counter3.Certificate, *counter3.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("third countersignature: %v", err)
	}

	countersigned, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(countersigned)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	results, err := parsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if got := len(results[0].Countersignatures); got != 3 {
		t.Fatalf("expected 3 countersignature results, got %d", got)
	}
	for i, cs := range results[0].Countersignatures {
		if cs.Error != nil {
			t.Fatalf("countersignature %d failed: %v", i, cs.Error)
		}
	}

	// Force a second attribute occurrence by splitting the three accumulated
	// SignerInfos across two countersignature attributes, then confirm both
	// occurrences are reported with distinct AttributeOrder values.
	attrs := parsed.Signers[0].UnauthenticatedAttributes
	for i := range attrs {
		if attrs[i].Type.Equal(OIDAttributeCountersignature) {
			// Split the three accumulated SignerInfos: move the last one
			// into a new attribute occurrence.
			setBytes := attrs[i].Value.Bytes
			var first asn1.RawValue
			rest, err := asn1.Unmarshal(setBytes, &first)
			if err != nil {
				t.Fatalf("unmarshal set: %v", err)
			}
			var second asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &second)
			if err != nil {
				t.Fatalf("unmarshal set: %v", err)
			}
			var third asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &third); err != nil {
				t.Fatalf("unmarshal set: %v", err)
			}
			attrs[i].Value.Bytes = append(first.FullBytes, second.FullBytes...)
			attrs[i].Value.FullBytes = nil
			parsed.Signers[0].UnauthenticatedAttributes = append(attrs, attribute{
				Type:  OIDAttributeCountersignature,
				Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: third.FullBytes},
			})
			if err := parsed.syncRawSignedData(); err != nil {
				t.Fatalf("sync: %v", err)
			}
			break
		}
	}
	rebuilt, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("Marshal split: %v", err)
	}
	reparsed, err := Parse(rebuilt)
	if err != nil {
		t.Fatalf("Parse split: %v", err)
	}
	splitResults, err := reparsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers split: %v", err)
	}
	counters := splitResults[0].Countersignatures
	if len(counters) != 3 {
		t.Fatalf("expected 3 countersignatures across 2 attribute occurrences, got %d", len(counters))
	}
	if counters[0].AttributeOrder != 0 || counters[1].AttributeOrder != 0 || counters[2].AttributeOrder != 1 {
		t.Fatalf("unexpected attribute occurrence ordering: %d %d %d",
			counters[0].AttributeOrder, counters[1].AttributeOrder, counters[2].AttributeOrder)
	}
	for i, cs := range counters {
		if cs.Error != nil {
			t.Fatalf("split countersignature %d failed: %v", i, cs.Error)
		}
	}
}

func TestCountersignatureTargetsSelectedSignerInfo(t *testing.T) {
	content := []byte("two primary signers")
	signer1 := newCounterTestCert(t, "primary one", false)
	signer2 := newCounterTestCert(t, "primary two", false)
	counter := newCounterTestCert(t, "approver", false)

	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(signer1.Certificate, *signer1.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner 1: %v", err)
	}
	if err := sd.AddSigner(signer2.Certificate, *signer2.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner 2: %v", err)
	}
	raw, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	p7, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := p7.AddCountersignature(1, counter.Certificate, *counter.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddCountersignature: %v", err)
	}
	countersigned, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(countersigned)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(parsed.Signers[0].UnauthenticatedAttributes) != 0 {
		t.Fatal("countersignature was attached to signer index 0 instead of the selected index 1")
	}
	results, err := parsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 signer results, got %d", len(results))
	}
	if len(results[0].Countersignatures) != 0 {
		t.Fatalf("signer 0 should have no countersignatures, got %d", len(results[0].Countersignatures))
	}
	if len(results[1].Countersignatures) != 1 {
		t.Fatalf("signer 1 should have 1 countersignature, got %d", len(results[1].Countersignatures))
	}
	if results[1].Countersignatures[0].Error != nil {
		t.Fatalf("countersignature failed: %v", results[1].Countersignatures[0].Error)
	}
	if results[0].PrimaryError != nil || results[1].PrimaryError != nil {
		t.Fatalf("primary signature errors: %v / %v", results[0].PrimaryError, results[1].PrimaryError)
	}
}

func TestRecursiveCountersignatureRejected(t *testing.T) {
	_, p7, _, _ := newCounterSignedMessage(t, []byte("x"))
	nested := newCounterTestCert(t, "nested approver", false)
	digestOID := OIDDigestAlgorithmSHA256
	hash, _ := getHashForOID(digestOID)
	var existing signerInfo
	if err := firstCountersignature(p7, &existing); err != nil {
		t.Fatalf("read countersignature: %v", err)
	}
	h := hash.New()
	h.Write(existing.EncryptedDigest)
	innerAttrs := &attributes{}
	innerAttrs.Add(OIDAttributeMessageDigest, h.Sum(nil))
	innerAttrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	finalInnerAttrs, err := innerAttrs.ForMarshalling()
	if err != nil {
		t.Fatalf("inner attrs: %v", err)
	}
	innerAttrBytes, err := marshalAttributes(finalInnerAttrs)
	if err != nil {
		t.Fatalf("marshal inner attrs: %v", err)
	}
	algorithm, err := getCMSSignerAlgorithm(*nested.PrivateKey, digestOID, nil)
	if err != nil {
		t.Fatalf("algorithm: %v", err)
	}
	nestedSignature, err := algorithm.sign(*nested.PrivateKey, innerAttrBytes, hash)
	if err != nil {
		t.Fatalf("nested sign: %v", err)
	}
	existing.UnauthenticatedAttributes = []attribute{{
		Type: OIDAttributeCountersignature,
		Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: mustMarshal(t, signerInfo{
			Version:                   1,
			IssuerAndSerialNumber:     cert2issuerAndSerial(nested.Certificate),
			DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: digestOID},
			DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm.signatureOID},
			AuthenticatedAttributes:   finalInnerAttrs,
			EncryptedDigest:           nestedSignature,
		})},
	}}
	p7.Certificates = append(p7.Certificates, nested.Certificate)
	replaceFirstCountersignature(t, p7, existing)
	rebuilt, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal with nested countersignature: %v", err)
	}
	reparsed, err := Parse(rebuilt)
	if err != nil {
		t.Fatalf("Parse nested: %v", err)
	}
	results, err := reparsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if len(results[0].Countersignatures) != 1 {
		t.Fatalf("expected 1 countersignature result, got %d", len(results[0].Countersignatures))
	}
	if !errors.Is(results[0].Countersignatures[0].Error, ErrUnsupportedRecursiveCountersignature) {
		t.Fatalf("expected ErrUnsupportedRecursiveCountersignature, got %v", results[0].Countersignatures[0].Error)
	}
	// The original signature is unaffected by the unprocessed nested value.
	if results[0].PrimaryError != nil {
		t.Fatalf("primary signature should remain valid, got %v", results[0].PrimaryError)
	}
}

func TestTamperContentFailsMessageDigestOnly(t *testing.T) {
	content := []byte("tamper the body text!!")
	_, p7, _, _ := newCounterSignedMessage(t, content)
	counterBytes, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Flip bytes inside the encapsulated content (same length keeps DER valid).
	tampered := bytes.Clone(counterBytes)
	index := bytes.Index(tampered, content)
	if index < 0 {
		t.Fatal("content not located in encoded message")
	}
	tampered[index] ^= 0xFF

	parsed, err := Parse(tampered)
	if err != nil {
		t.Fatalf("Parse tampered: %v", err)
	}
	if err := parsed.Verify(); !isDigestMismatch(err) {
		t.Fatalf("legacy verify expected MessageDigestMismatchError, got %v", err)
	}
	results, err := parsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if !isDigestMismatch(results[0].PrimaryError) {
		t.Fatalf("primary expected messageDigest mismatch, got %v", results[0].PrimaryError)
	}
	// The countersignature binds the original signatureValue, which is intact.
	if results[0].Countersignatures[0].Error != nil {
		t.Fatalf("countersignature should still verify, got %v", results[0].Countersignatures[0].Error)
	}
}

func TestTamperOriginalSignatureFailsBothLayersDifferently(t *testing.T) {
	_, p7, _, _ := newCounterSignedMessage(t, []byte("tamper the original signature"))
	counterBytes, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(counterBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	counterRaw, err := parsed.RawCountersignatures(0)
	if err != nil || len(counterRaw) != 1 {
		t.Fatalf("RawCountersignatures: %v", err)
	}

	// Flip a byte of the primary signatureValue. It is covered by the
	// countersignature's messageDigest, so both layers fail, with distinct
	// reasons (signature failure vs digest mismatch).
	tampered := bytes.Clone(counterBytes)
	index := bytes.Index(tampered, parsed.Signers[0].EncryptedDigest)
	if index < 0 {
		t.Fatal("primary signatureValue not located in encoded message")
	}
	tampered[index] ^= 0xFF

	reparsed, err := Parse(tampered)
	if err != nil {
		t.Fatalf("Parse tampered: %v", err)
	}
	results, err := reparsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if isDigestMismatch(results[0].PrimaryError) {
		t.Fatalf("primary failure should be a signature error, got digest mismatch: %v", results[0].PrimaryError)
	}
	if results[0].PrimaryError == nil {
		t.Fatal("primary signature should fail after signatureValue tampering")
	}
	counterErr := results[0].Countersignatures[0].Error
	if !isDigestMismatch(counterErr) {
		t.Fatalf("countersignature expected messageDigest mismatch, got %v", counterErr)
	}
}

func TestTamperCountersignatureFailsOnlyCountersignature(t *testing.T) {
	_, p7, _, _ := newCounterSignedMessage(t, []byte("tamper the countersignature"))
	counterBytes, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(counterBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	counterRaw, err := parsed.RawCountersignatures(0)
	if err != nil || len(counterRaw) != 1 {
		t.Fatalf("RawCountersignatures: %v", err)
	}

	var counterSI signerInfo
	if _, err := asn1.Unmarshal(counterRaw[0], &counterSI); err != nil {
		t.Fatalf("unmarshal counter: %v", err)
	}
	// Flip a byte inside the countersignature's own signatureValue.
	tampered := bytes.Clone(counterBytes)
	sigIndex := bytes.Index(tampered, counterSI.EncryptedDigest)
	if sigIndex < 0 {
		t.Fatal("countersignature signatureValue not located")
	}
	// Skip an accidental match earlier in the blob: the countersignature is
	// encoded after the primary SignerInfo.
	primaryEnd := bytes.Index(tampered, counterRaw[0])
	for sigIndex >= 0 && sigIndex < primaryEnd {
		next := bytes.Index(tampered[sigIndex+1:], counterSI.EncryptedDigest)
		if next < 0 {
			sigIndex = -1
			break
		}
		sigIndex = next + sigIndex + 1
	}
	if sigIndex < 0 {
		t.Fatal("countersignature signatureValue not located after primary signer")
	}
	tampered[sigIndex] ^= 0xFF

	reparsed, err := Parse(tampered)
	if err != nil {
		t.Fatalf("Parse tampered: %v", err)
	}
	// Legacy verification ignores unsigned attributes entirely.
	if err := reparsed.Verify(); err != nil {
		t.Fatalf("original signature should still verify: %v", err)
	}
	results, err := reparsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if results[0].PrimaryError != nil {
		t.Fatalf("primary signature should remain valid, got %v", results[0].PrimaryError)
	}
	counterErr := results[0].Countersignatures[0].Error
	if counterErr == nil {
		t.Fatal("countersignature should fail after its signatureValue was tampered")
	}
	if isDigestMismatch(counterErr) {
		t.Fatalf("countersignature failure should be a signature error, not a digest mismatch: %v", counterErr)
	}
}

func TestCountersignatureContentTypeAttributeRejectedOnVerify(t *testing.T) {
	_, p7, _, counter := newCounterSignedMessage(t, []byte("forbidden attr"))
	var counterSI signerInfo
	if err := firstCountersignature(p7, &counterSI); err != nil {
		t.Fatalf("read countersignature: %v", err)
	}
	badAttrs := &attributes{}
	badAttrs.Add(OIDAttributeContentType, OIDData)
	badAttrs.Add(OIDAttributeMessageDigest, mustAttributeDigest(t, counterSI, p7.Signers[0]))
	badAttrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	var err error
	counterSI.AuthenticatedAttributes, err = badAttrs.ForMarshalling()
	if err != nil {
		t.Fatalf("attrs: %v", err)
	}
	attrBytes, err := marshalAttributes(counterSI.AuthenticatedAttributes)
	if err != nil {
		t.Fatalf("marshal attrs: %v", err)
	}
	hash, _ := getHashForOID(counterSI.DigestAlgorithm.Algorithm)
	signature, err := getCMSSignerAlgorithm(*counter.PrivateKey, counterSI.DigestAlgorithm.Algorithm, nil)
	if err != nil {
		t.Fatalf("algorithm: %v", err)
	}
	if counterSI.EncryptedDigest, err = signature.sign(*counter.PrivateKey, attrBytes, hash); err != nil {
		t.Fatalf("sign: %v", err)
	}
	replaceFirstCountersignature(t, p7, counterSI)
	counterBytes, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := Parse(counterBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	results, err := reparsed.VerifyLayers()
	if err != nil {
		t.Fatalf("VerifyLayers: %v", err)
	}
	if !errors.Is(results[0].Countersignatures[0].Error, ErrCountersignatureContentTypeForbidden) {
		t.Fatalf("expected ErrCountersignatureContentTypeForbidden, got %v", results[0].Countersignatures[0].Error)
	}
	if results[0].PrimaryError != nil {
		t.Fatalf("primary signature should remain valid, got %v", results[0].PrimaryError)
	}
}

func mustAttributeDigest(t *testing.T, counterSI signerInfo, target signerInfo) []byte {
	t.Helper()
	hash, err := getHashForOID(counterSI.DigestAlgorithm.Algorithm)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h := hash.New()
	h.Write(target.EncryptedDigest)
	return h.Sum(nil)
}

func TestCountersignatureWithCertificateChain(t *testing.T) {
	content := []byte("chain verified countersignature")
	root := newCounterTestCert(t, "counter test root", true)

	primary, err := createTestCertificateByIssuer("primary chain signer", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatalf("primary cert: %v", err)
	}
	counter, err := createTestCertificateByIssuer("chain countersigner", root, x509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatalf("counter cert: %v", err)
	}

	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSignerChain(primary.Certificate, *primary.PrivateKey,
		[]*x509.Certificate{root.Certificate}, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSignerChain: %v", err)
	}
	raw, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	p7, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := p7.AddCountersignatureChain(0, counter.Certificate, *counter.PrivateKey,
		[]*x509.Certificate{root.Certificate}, SignerInfoConfig{}); err != nil {
		t.Fatalf("AddCountersignatureChain: %v", err)
	}
	countersigned, err := p7.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(countersigned)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)
	results, err := parsed.VerifyLayersWithChain(truststore)
	if err != nil {
		t.Fatalf("VerifyLayersWithChain: %v", err)
	}
	if results[0].PrimaryError != nil {
		t.Fatalf("primary chain verification failed: %v", results[0].PrimaryError)
	}
	if results[0].Countersignatures[0].Error != nil {
		t.Fatalf("countersignature chain verification failed: %v", results[0].Countersignatures[0].Error)
	}

	// Chain checking must also surface an untrusted countersigner distinctly.
	emptyPool := x509.NewCertPool()
	failed, err := parsed.VerifyLayersWithChain(emptyPool)
	if err != nil {
		t.Fatalf("VerifyLayersWithChain untrusted: %v", err)
	}
	if failed[0].Countersignatures[0].Error == nil {
		t.Fatal("expected countersigner chain failure against an empty trust store")
	}
}

func isDigestMismatch(err error) bool {
	var mismatch *MessageDigestMismatchError
	return errors.As(err, &mismatch)
}

func firstCountersignature(p7 *PKCS7, out *signerInfo) error {
	raw, err := p7.RawCountersignatures(0)
	if err != nil {
		return err
	}
	if len(raw) != 1 {
		return fmt.Errorf("expected 1 countersignature, got %d", len(raw))
	}
	_, err = asn1.Unmarshal(raw[0], out)
	return err
}

// replaceFirstCountersignature overwrites the first SignerInfo inside the
// target's countersignature attribute with the provided value.
func replaceFirstCountersignature(t *testing.T, p7 *PKCS7, counter signerInfo) {
	t.Helper()
	for i := range p7.Signers[0].UnauthenticatedAttributes {
		attr := &p7.Signers[0].UnauthenticatedAttributes[i]
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(attr.Value.Bytes, &raw)
		if err != nil {
			t.Fatalf("unmarshal countersignature set entry: %v", err)
		}
		attr.Value.Bytes = append(mustMarshal(t, counter), rest...)
		attr.Value.FullBytes = nil
		if err := p7.syncRawSignedData(); err != nil {
			t.Fatalf("sync: %v", err)
		}
		return
	}
	t.Fatal("no countersignature attribute found")
}

func mustMarshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %T: %v", value, err)
	}
	return encoded
}
