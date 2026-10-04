package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
	"time"
)

func newStrictTestMessage(t *testing.T) *PKCS7 {
	t.Helper()
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("strict structure test content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.AddSigner(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
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
	return p7
}

func makeRawAttribute(t *testing.T, oid asn1.ObjectIdentifier, values ...interface{}) attribute {
	t.Helper()
	var buf []byte
	for _, value := range values {
		der, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, der...)
	}
	return attribute{Type: oid, Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: buf}}
}

func findAttribute(attrs []attribute, oid asn1.ObjectIdentifier) int {
	for i, attr := range attrs {
		if attr.Type.Equal(oid) {
			return i
		}
	}
	return -1
}

func removeAttribute(attrs []attribute, oid asn1.ObjectIdentifier) []attribute {
	filtered := attrs[:0]
	for _, attr := range attrs {
		if !attr.Type.Equal(oid) {
			filtered = append(filtered, attr)
		}
	}
	return filtered
}

func requireStructureError(t *testing.T, err error, signer int, oid asn1.ObjectIdentifier) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected structural error for signer %d oid %v, got nil", signer, oid)
	}
	var serr *StructureError
	if !errors.As(err, &serr) {
		t.Fatalf("expected *StructureError, got %T: %v", err, err)
	}
	if serr.Signer != signer {
		t.Fatalf("expected signer index %d, got %d (%v)", signer, serr.Signer, serr)
	}
	if oid != nil && !serr.OID.Equal(oid) {
		t.Fatalf("expected oid %v, got %v (%v)", oid, serr.OID, serr)
	}
}

func TestCheckStructureValid(t *testing.T) {
	p7 := newStrictTestMessage(t)
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("CheckStructure failed on a valid message: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("VerifyStrict failed on a valid message: %v", err)
	}
	if err := p7.VerifyWithChainStrict(nil); err != nil {
		t.Fatalf("VerifyWithChainStrict failed on a valid message: %v", err)
	}
}

func TestCheckStructureDigestAlgorithmNotInSet(t *testing.T) {
	p7 := newStrictTestMessage(t)
	raw := p7.raw.(signedData)
	raw.DigestAlgorithmIdentifiers = nil
	p7.raw = raw

	requireStructureError(t, p7.CheckStructure(), 0, OIDDigestAlgorithmSHA256)
	requireStructureError(t, p7.VerifyStrict(), 0, OIDDigestAlgorithmSHA256)
	// The default compatible entry point does not consult the digest
	// algorithm set and keeps accepting the message.
	if err := p7.Verify(); err != nil {
		t.Fatalf("default Verify must remain unaffected by the strict policy: %v", err)
	}
}

func TestCheckStructureDigestAlgorithmParameters(t *testing.T) {
	arbitraryDER := asn1.RawValue{
		Tag:       asn1.TagOctetString,
		Bytes:     []byte{0x01, 0x02},
		FullBytes: []byte{0x04, 0x02, 0x01, 0x02},
	}

	p7 := newStrictTestMessage(t)
	p7.Signers[0].DigestAlgorithm.Parameters = arbitraryDER
	requireStructureError(t, p7.CheckStructure(), 0, OIDDigestAlgorithmSHA256)
	// NULL parameters are not the same as arbitrary DER and stay valid.
	p7.Signers[0].DigestAlgorithm.Parameters = asn1.NullRawValue
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("NULL digest parameters must be accepted: %v", err)
	}

	// The default entry point ignores digest parameters entirely.
	p7 = newStrictTestMessage(t)
	p7.Signers[0].DigestAlgorithm.Parameters = arbitraryDER
	if err := p7.Verify(); err != nil {
		t.Fatalf("default Verify must remain unaffected by the strict policy: %v", err)
	}
	requireStructureError(t, p7.VerifyStrict(), 0, OIDDigestAlgorithmSHA256)
}

func TestCheckStructureSignatureAlgorithmParameters(t *testing.T) {
	p7 := newStrictTestMessage(t)
	p7.Signers[0].DigestEncryptionAlgorithm.Parameters = asn1.RawValue{
		Tag:       asn1.TagOctetString,
		Bytes:     []byte{0x01},
		FullBytes: []byte{0x04, 0x01, 0x01},
	}
	requireStructureError(t, p7.CheckStructure(), 0, OIDEncryptionAlgorithmRSASHA256)

	p7.Signers[0].DigestEncryptionAlgorithm.Parameters = asn1.NullRawValue
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("NULL signature parameters must be accepted: %v", err)
	}
}

func TestCheckStructureSignatureDigestMismatch(t *testing.T) {
	p7 := newStrictTestMessage(t)
	p7.Signers[0].DigestEncryptionAlgorithm.Algorithm = OIDEncryptionAlgorithmRSASHA1
	requireStructureError(t, p7.CheckStructure(), 0, OIDEncryptionAlgorithmRSASHA1)
	// The default entry point derives the hash from the digest algorithm
	// alone and keeps accepting the message.
	if err := p7.Verify(); err != nil {
		t.Fatalf("default Verify must remain unaffected by the strict policy: %v", err)
	}
}

func TestCheckStructureDuplicateContentType(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	dup := makeRawAttribute(t, OIDAttributeContentType, OIDData)
	p7.Signers[0].AuthenticatedAttributes = append(attrs, dup)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeContentType)
}

func TestCheckStructureContentTypeValueCount(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	i := findAttribute(attrs, OIDAttributeContentType)
	if i < 0 {
		t.Fatal("contentType attribute not found")
	}
	attrs[i] = makeRawAttribute(t, OIDAttributeContentType, OIDData, OIDData)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeContentType)
}

func TestCheckStructureContentTypeMismatch(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	i := findAttribute(attrs, OIDAttributeContentType)
	if i < 0 {
		t.Fatal("contentType attribute not found")
	}
	attrs[i] = makeRawAttribute(t, OIDAttributeContentType, OIDSignedData)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeContentType)
}

func TestCheckStructureMissingMessageDigest(t *testing.T) {
	p7 := newStrictTestMessage(t)
	p7.Signers[0].AuthenticatedAttributes =
		removeAttribute(p7.Signers[0].AuthenticatedAttributes, OIDAttributeMessageDigest)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeMessageDigest)
}

func TestCheckStructureMessageDigestValueCount(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	i := findAttribute(attrs, OIDAttributeMessageDigest)
	if i < 0 {
		t.Fatal("messageDigest attribute not found")
	}
	digest := make([]byte, 32)
	attrs[i] = makeRawAttribute(t, OIDAttributeMessageDigest, digest, digest)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeMessageDigest)
}

func TestCheckStructureMessageDigestLength(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	i := findAttribute(attrs, OIDAttributeMessageDigest)
	if i < 0 {
		t.Fatal("messageDigest attribute not found")
	}
	attrs[i] = makeRawAttribute(t, OIDAttributeMessageDigest, make([]byte, 5))
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeMessageDigest)
}

func TestCheckStructureDuplicateSigningTime(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	dup := makeRawAttribute(t, OIDAttributeSigningTime, time.Now().UTC())
	p7.Signers[0].AuthenticatedAttributes = append(attrs, dup)
	requireStructureError(t, p7.CheckStructure(), 0, OIDAttributeSigningTime)
}

func TestCheckStructureNoSignedAttrs(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("attr-less content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
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
	// Signatures without signedAttrs follow their own legal path and must
	// not be forbidden wholesale.
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("CheckStructure rejected a legal attr-less signature: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("VerifyStrict rejected a legal attr-less signature: %v", err)
	}
}

func TestCheckStructureNoSignedAttrsNonDataContent(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("attr-less non-data content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	signedData.SetContentType(OIDSignedData)
	if err := signedData.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
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
	requireStructureError(t, p7.CheckStructure(), 0, OIDSignedData)
}

func TestCheckStructureUnknownUnsignedAttributesPreserved(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("unsigned attribute content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	config := SignerInfoConfig{
		ExtraUnsignedAttributes: []Attribute{{Type: unknownOID, Value: "preserved"}},
	}
	if err := signedData.AddSigner(pair.Certificate, *pair.PrivateKey, config); err != nil {
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
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("unknown unsigned attributes must not be rejected: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("VerifyStrict failed with unknown unsigned attributes: %v", err)
	}
	if findAttribute(p7.Signers[0].UnauthenticatedAttributes, unknownOID) < 0 {
		t.Fatal("unknown unsigned attribute was not preserved")
	}
}

func TestCheckStructureAttributeOrder(t *testing.T) {
	p7 := newStrictTestMessage(t)
	attrs := p7.Signers[0].AuthenticatedAttributes
	if len(attrs) < 2 {
		t.Fatal("test message should carry several signed attributes")
	}
	// Reordering a legal SET OF attributes must not cause a spurious
	// structural rejection.
	for i, j := 0, len(attrs)-1; i < j; i, j = i+1, j-1 {
		attrs[i], attrs[j] = attrs[j], attrs[i]
	}
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("reordered attributes must not be rejected: %v", err)
	}
}

func TestCheckStructureReportsSignerIndex(t *testing.T) {
	first, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData([]byte("multi signer content"))
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.AddSigner(first.Certificate, *first.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := signedData.AddSigner(second.Certificate, *second.PrivateKey, SignerInfoConfig{}); err != nil {
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
	p7.Signers[1].AuthenticatedAttributes =
		removeAttribute(p7.Signers[1].AuthenticatedAttributes, OIDAttributeMessageDigest)
	requireStructureError(t, p7.CheckStructure(), 1, OIDAttributeMessageDigest)
}
