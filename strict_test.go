package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

var strictTestContent = []byte("strict structure test content")

// arbitraryDERParameters is an AlgorithmIdentifier parameters value that is
// neither absent nor NULL: an INTEGER must never be accepted where the
// algorithm only allows absent/NULL parameters.
var arbitraryDERParameters = asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}

func buildStrictTestSignedData(t *testing.T, mutate func(sd *signedData)) []byte {
	t.Helper()
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("cannot create test certificate: %s", err)
	}
	toBeSigned, err := NewSignedData(strictTestContent)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := toBeSigned.AddSigner(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add signer: %s", err)
	}
	if mutate != nil {
		mutate(toBeSigned.GetSignedData())
	}
	der, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signed data: %s", err)
	}
	return der
}

func mustParseStrict(t *testing.T, der []byte) *PKCS7 {
	t.Helper()
	p7, err := Parse(der)
	if err != nil {
		t.Fatalf("cannot parse signed data: %s", err)
	}
	return p7
}

func requireStructuralError(t *testing.T, err error, signerIndex int, oid asn1.ObjectIdentifier) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *StructuralError, got nil")
	}
	var structuralErr *StructuralError
	if !errors.As(err, &structuralErr) {
		t.Fatalf("expected *StructuralError, got %T: %v", err, err)
	}
	if structuralErr.SignerIndex != signerIndex {
		t.Errorf("expected signer index %d, got %d (%v)", signerIndex, structuralErr.SignerIndex, structuralErr)
	}
	if oid != nil && !structuralErr.OID.Equal(oid) {
		t.Errorf("expected OID %s, got %v (%v)", oid, structuralErr.OID, structuralErr)
	}
	if signerIndex >= 0 && !strings.Contains(structuralErr.Error(), "signer 0") {
		t.Errorf("error message should report the signer index: %q", structuralErr.Error())
	}
	if oid != nil && !strings.Contains(structuralErr.Error(), oid.String()) {
		t.Errorf("error message should report the attribute/algorithm OID: %q", structuralErr.Error())
	}
}

func attributeIndex(attrs []attribute, oid asn1.ObjectIdentifier) int {
	for i, attr := range attrs {
		if attr.Type.Equal(oid) {
			return i
		}
	}
	return -1
}

func removeAttribute(attrs []attribute, oid asn1.ObjectIdentifier) []attribute {
	out := make([]attribute, 0, len(attrs))
	for _, attr := range attrs {
		if !attr.Type.Equal(oid) {
			out = append(out, attr)
		}
	}
	return out
}

func duplicateAttributeValue(attrs []attribute, oid asn1.ObjectIdentifier) []attribute {
	i := attributeIndex(attrs, oid)
	if i < 0 {
		return attrs
	}
	duplicated := attrs[i]
	duplicated.Value.Bytes = append(append([]byte{}, attrs[i].Value.Bytes...), attrs[i].Value.Bytes...)
	attrs[i] = duplicated
	return attrs
}

func TestCheckStructureValidSample(t *testing.T) {
	p7 := mustParseStrict(t, buildStrictTestSignedData(t, nil))
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("valid sample rejected by structural policy: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("valid sample rejected by strict verify: %v", err)
	}
}

func TestCheckStructureWithoutSignedAttributes(t *testing.T) {
	// Signatures without signedAttrs follow their own legitimate path
	// (signature computed over the content) and must not be forbidden.
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("cannot create test certificate: %s", err)
	}
	toBeSigned, err := NewSignedData(strictTestContent)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := toBeSigned.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot sign without attributes: %s", err)
	}
	der, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signed data: %s", err)
	}
	p7 := mustParseStrict(t, der)
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("attribute-less signer rejected by structural policy: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("attribute-less signer rejected by strict verify: %v", err)
	}
}

func TestCheckStructureRejectsStructuralMutations(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	tests := []struct {
		name        string
		mutate      func(sd *signedData)
		signerIndex int
		oid         asn1.ObjectIdentifier
	}{
		{
			name:        "signer digest algorithm missing from digestAlgorithms set",
			mutate:      func(sd *signedData) { sd.DigestAlgorithmIdentifiers = nil },
			signerIndex: 0,
			oid:         OIDDigestAlgorithmSHA256,
		},
		{
			name: "digestAlgorithms set entry with arbitrary parameters",
			mutate: func(sd *signedData) {
				sd.DigestAlgorithmIdentifiers[0].Parameters = arbitraryDERParameters
			},
			signerIndex: -1,
			oid:         OIDDigestAlgorithmSHA256,
		},
		{
			name: "signer digest algorithm with arbitrary parameters",
			mutate: func(sd *signedData) {
				sd.SignerInfos[0].DigestAlgorithm.Parameters = arbitraryDERParameters
			},
			signerIndex: 0,
			oid:         OIDDigestAlgorithmSHA256,
		},
		{
			name: "signature algorithm with arbitrary parameters",
			mutate: func(sd *signedData) {
				sd.SignerInfos[0].DigestEncryptionAlgorithm.Parameters = arbitraryDERParameters
			},
			signerIndex: 0,
			oid:         OIDEncryptionAlgorithmRSASHA256,
		},
		{
			name: "duplicated messageDigest attribute",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				i := attributeIndex(attrs, OIDAttributeMessageDigest)
				sd.SignerInfos[0].AuthenticatedAttributes = append(attrs, attrs[i])
			},
			signerIndex: 0,
			oid:         OIDAttributeMessageDigest,
		},
		{
			name: "messageDigest attribute with two values",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				sd.SignerInfos[0].AuthenticatedAttributes = duplicateAttributeValue(attrs, OIDAttributeMessageDigest)
			},
			signerIndex: 0,
			oid:         OIDAttributeMessageDigest,
		},
		{
			name: "messageDigest attribute with wrong length",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				i := attributeIndex(attrs, OIDAttributeMessageDigest)
				shortDigest, _ := asn1.Marshal([]byte{1, 2, 3, 4})
				attrs[i].Value.Bytes = shortDigest
			},
			signerIndex: 0,
			oid:         OIDAttributeMessageDigest,
		},
		{
			name: "contentType attribute mismatching signed content type",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				i := attributeIndex(attrs, OIDAttributeContentType)
				wrong, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
				attrs[i].Value.Bytes = wrong
			},
			signerIndex: 0,
			oid:         OIDAttributeContentType,
		},
		{
			name: "missing contentType attribute",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				sd.SignerInfos[0].AuthenticatedAttributes = removeAttribute(attrs, OIDAttributeContentType)
			},
			signerIndex: 0,
			oid:         OIDAttributeContentType,
		},
		{
			name: "missing messageDigest attribute",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				sd.SignerInfos[0].AuthenticatedAttributes = removeAttribute(attrs, OIDAttributeMessageDigest)
			},
			signerIndex: 0,
			oid:         OIDAttributeMessageDigest,
		},
		{
			name: "duplicated signingTime attribute",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				i := attributeIndex(attrs, OIDAttributeSigningTime)
				sd.SignerInfos[0].AuthenticatedAttributes = append(attrs, attrs[i])
			},
			signerIndex: 0,
			oid:         OIDAttributeSigningTime,
		},
		{
			name: "attribute with empty value set",
			mutate: func(sd *signedData) {
				attrs := sd.SignerInfos[0].AuthenticatedAttributes
				empty := attribute{
					Type:  unknownOID,
					Value: asn1.RawValue{Tag: 17, IsCompound: true},
				}
				sd.SignerInfos[0].AuthenticatedAttributes = append(attrs, empty)
			},
			signerIndex: 0,
			oid:         unknownOID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p7 := mustParseStrict(t, buildStrictTestSignedData(t, test.mutate))
			// The structural layer must report the problem...
			requireStructuralError(t, p7.CheckStructure(), test.signerIndex, test.oid)
			// ...and strict verification must surface it before any
			// cryptographic check (digest/signature) can fail.
			requireStructuralError(t, p7.VerifyStrict(), test.signerIndex, test.oid)
		})
	}
}

func TestCheckStructureAttributeOrderIrrelevant(t *testing.T) {
	// Reordering a legal SET OF attributes (e.g. non-DER ordering on the
	// wire) must not cause a spurious rejection.
	p7 := mustParseStrict(t, buildStrictTestSignedData(t, nil))
	sd := p7.raw.(signedData)
	attrs := sd.SignerInfos[0].AuthenticatedAttributes
	if len(attrs) < 2 {
		t.Fatalf("expected at least two signed attributes, got %d", len(attrs))
	}
	for i, j := 0, len(attrs)-1; i < j; i, j = i+1, j-1 {
		attrs[i], attrs[j] = attrs[j], attrs[i]
	}
	sd.SignerInfos[0].AuthenticatedAttributes = attrs
	p7.raw = sd
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("reordered SET OF attributes rejected: %v", err)
	}
}

func TestCheckStructurePreservesUnknownUnsignedAttributes(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("cannot create test certificate: %s", err)
	}
	toBeSigned, err := NewSignedData(strictTestContent)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	config := SignerInfoConfig{
		ExtraUnsignedAttributes: []Attribute{{Type: unknownOID, Value: "preserve me"}},
	}
	if err := toBeSigned.AddSigner(pair.Certificate, *pair.PrivateKey, config); err != nil {
		t.Fatalf("cannot add signer: %s", err)
	}
	der, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signed data: %s", err)
	}
	p7 := mustParseStrict(t, der)

	// The unknown unsigned attribute survives parsing losslessly.
	found := false
	for _, attr := range p7.Signers[0].UnauthenticatedAttributes {
		if attr.Type.Equal(unknownOID) {
			found = true
			var value string
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &value); err != nil {
				t.Fatalf("cannot unmarshal preserved attribute value: %s", err)
			}
			if value != "preserve me" {
				t.Fatalf("preserved attribute value corrupted: %q", value)
			}
		}
	}
	if !found {
		t.Fatal("unknown unsigned attribute was dropped during parsing")
	}
	if err := p7.CheckStructure(); err != nil {
		t.Fatalf("unknown unsigned attribute rejected by structural policy: %v", err)
	}
	if err := p7.VerifyStrict(); err != nil {
		t.Fatalf("unknown unsigned attribute rejected by strict verify: %v", err)
	}
}

func TestDefaultVerifyAcceptanceScopeUnchanged(t *testing.T) {
	// A structurally inconsistent but cryptographically valid sample must
	// still be accepted by the default compatible entry points; only the
	// strict policy rejects it.
	p7 := mustParseStrict(t, buildStrictTestSignedData(t, func(sd *signedData) {
		sd.DigestAlgorithmIdentifiers = nil
	}))
	if err := p7.Verify(); err != nil {
		t.Fatalf("default Verify acceptance scope changed: %v", err)
	}
	requireStructuralError(t, p7.CheckStructure(), 0, OIDDigestAlgorithmSHA256)
	requireStructuralError(t, p7.VerifyStrict(), 0, OIDDigestAlgorithmSHA256)
}

func TestCheckStructureNonSignedData(t *testing.T) {
	if err := (&PKCS7{}).CheckStructure(); err == nil {
		t.Fatal("expected error for non-signedData payload")
	}
}
