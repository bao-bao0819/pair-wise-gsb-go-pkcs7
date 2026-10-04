package pkcs7

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// StructureError describes a self-contradictory CMS structure detected by
// CheckStructure before any cryptographic verification takes place.
type StructureError struct {
	// Signer is the index of the offending SignerInfo, or -1 when the
	// problem is at the SignedData level.
	Signer int
	// OID is the attribute or algorithm object identifier involved in the
	// problem, or nil when not applicable.
	OID asn1.ObjectIdentifier
	// Detail describes the inconsistency.
	Detail string
}

func (e *StructureError) Error() string {
	msg := "pkcs7: strict structure:"
	if e.Signer >= 0 {
		msg += fmt.Sprintf(" signer %d:", e.Signer)
	}
	if e.OID != nil {
		msg += fmt.Sprintf(" oid %s:", e.OID.String())
	}
	return msg + " " + e.Detail
}

// CheckStructure applies the optional strict structural policy to a parsed
// SignedData message. It verifies, without any cryptographic operation, that
// the message is self-consistent:
//
//   - every digest algorithm identifier carries parameters that are valid
//     for that algorithm (absent or NULL; arbitrary DER is not accepted as
//     equivalent to NULL);
//   - every SignerInfo digest algorithm appears in the SignedData
//     digestAlgorithms set;
//   - every SignerInfo signature algorithm identifier carries valid
//     parameters and, when the algorithm fixes a digest (for example
//     sha256WithRSAEncryption or ecdsa-with-SHA256), that digest matches the
//     SignerInfo digest algorithm;
//   - when signed attributes are present, the single-valued contentType and
//     messageDigest attributes appear exactly once with exactly one value
//     each, the contentType value matches the SignedData content type, and
//     the messageDigest value length matches the digest algorithm;
//   - when signed attributes are absent, the content type is id-data, the
//     only content type that may be signed directly.
//
// Unknown signed or unsigned attribute types are not rejected; unsigned
// attributes in particular are preserved losslessly. The default Verify
// entry points are unaffected by this policy.
func (p7 *PKCS7) CheckStructure() error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: strict structure checks require signed data content")
	}
	for _, alg := range sd.DigestAlgorithmIdentifiers {
		if err := checkStrictDigestAlgorithm(alg); err != nil {
			return &StructureError{Signer: -1, OID: alg.Algorithm, Detail: err.Error()}
		}
	}
	for i := range p7.Signers {
		if err := checkSignerStructure(&p7.Signers[i], &sd, i); err != nil {
			return err
		}
	}
	return nil
}

// VerifyStrict is like Verify but applies the strict structural policy of
// CheckStructure before any cryptographic verification.
func (p7 *PKCS7) VerifyStrict() error {
	if err := p7.CheckStructure(); err != nil {
		return err
	}
	return p7.Verify()
}

// VerifyWithChainStrict is like VerifyWithChain but applies the strict
// structural policy of CheckStructure before any cryptographic verification.
func (p7 *PKCS7) VerifyWithChainStrict(truststore *x509.CertPool) error {
	if err := p7.CheckStructure(); err != nil {
		return err
	}
	return p7.VerifyWithChain(truststore)
}

func checkSignerStructure(signer *signerInfo, sd *signedData, index int) error {
	fail := func(oid asn1.ObjectIdentifier, format string, args ...interface{}) error {
		return &StructureError{Signer: index, OID: oid, Detail: fmt.Sprintf(format, args...)}
	}
	if err := checkStrictDigestAlgorithm(signer.DigestAlgorithm); err != nil {
		return fail(signer.DigestAlgorithm.Algorithm, "%v", err)
	}
	inDigestSet := false
	for _, alg := range sd.DigestAlgorithmIdentifiers {
		if alg.Algorithm.Equal(signer.DigestAlgorithm.Algorithm) {
			inDigestSet = true
			break
		}
	}
	if !inDigestSet {
		return fail(signer.DigestAlgorithm.Algorithm,
			"digest algorithm %q is not present in the SignedData digestAlgorithms set",
			signer.DigestAlgorithm.Algorithm.String())
	}
	if err := checkStrictSignatureParameters(signer.DigestEncryptionAlgorithm); err != nil {
		return fail(signer.DigestEncryptionAlgorithm.Algorithm, "%v", err)
	}
	if required, ok := requiredDigestForSignatureOID(signer.DigestEncryptionAlgorithm.Algorithm); ok {
		hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return fail(signer.DigestAlgorithm.Algorithm, "%v", err)
		}
		if hash != required {
			return fail(signer.DigestEncryptionAlgorithm.Algorithm,
				"signature algorithm %q requires digest %v but SignerInfo declares %q",
				signer.DigestEncryptionAlgorithm.Algorithm.String(), required,
				signer.DigestAlgorithm.Algorithm.String())
		}
	}
	if len(signer.AuthenticatedAttributes) == 0 {
		// Without signedAttrs the signature is computed over the content
		// directly, which is only defined for id-data content.
		if !sd.ContentInfo.ContentType.Equal(OIDData) {
			return fail(sd.ContentInfo.ContentType,
				"signed attributes are absent but the content type %q is not id-data",
				sd.ContentInfo.ContentType.String())
		}
		return nil
	}
	return checkSignedAttributes(signer, sd.ContentInfo.ContentType, fail)
}

func checkSignedAttributes(signer *signerInfo, eContentType asn1.ObjectIdentifier,
	fail func(asn1.ObjectIdentifier, string, ...interface{}) error) error {
	singleValued := []asn1.ObjectIdentifier{
		OIDAttributeContentType,
		OIDAttributeMessageDigest,
		OIDAttributeSigningTime,
	}
	values := make(map[string][]asn1.RawValue, len(singleValued))
	for _, oid := range singleValued {
		count := 0
		for _, attr := range signer.AuthenticatedAttributes {
			if !attr.Type.Equal(oid) {
				continue
			}
			count++
			attrValues, err := attributeValues(attr)
			if err != nil {
				return fail(oid, "cannot decode attribute values: %v", err)
			}
			if len(attrValues) != 1 {
				return fail(oid, "single-valued attribute carries %d values", len(attrValues))
			}
			values[oid.String()] = attrValues
		}
		if count > 1 {
			return fail(oid, "single-valued attribute appears %d times", count)
		}
	}
	contentTypeValues := values[OIDAttributeContentType.String()]
	if len(contentTypeValues) == 0 {
		return fail(OIDAttributeContentType, "mandatory contentType attribute is missing")
	}
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(contentTypeValues[0].FullBytes, &contentType); err != nil {
		return fail(OIDAttributeContentType, "contentType value is not an object identifier: %v", err)
	}
	if !contentType.Equal(eContentType) {
		return fail(OIDAttributeContentType,
			"contentType attribute %q does not match the SignedData content type %q",
			contentType.String(), eContentType.String())
	}
	messageDigestValues := values[OIDAttributeMessageDigest.String()]
	if len(messageDigestValues) == 0 {
		return fail(OIDAttributeMessageDigest, "mandatory messageDigest attribute is missing")
	}
	var digest []byte
	if _, err := asn1.Unmarshal(messageDigestValues[0].FullBytes, &digest); err != nil {
		return fail(OIDAttributeMessageDigest, "messageDigest value is not an octet string: %v", err)
	}
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return fail(signer.DigestAlgorithm.Algorithm, "%v", err)
	}
	if len(digest) != hash.Size() {
		return fail(OIDAttributeMessageDigest,
			"messageDigest value is %d bytes but digest algorithm %q produces %d",
			len(digest), signer.DigestAlgorithm.Algorithm.String(), hash.Size())
	}
	if signingTimeValues := values[OIDAttributeSigningTime.String()]; len(signingTimeValues) == 1 {
		var signingTime time.Time
		if _, err := asn1.Unmarshal(signingTimeValues[0].FullBytes, &signingTime); err != nil {
			return fail(OIDAttributeSigningTime, "signingTime value is not a valid time: %v", err)
		}
	}
	return nil
}

// attributeValues decodes the concatenated DER values held by an attribute
// SET without interpreting them.
func attributeValues(attr attribute) ([]asn1.RawValue, error) {
	var values []asn1.RawValue
	rest := attr.Value.Bytes
	for len(rest) > 0 {
		var value asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &value)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func checkStrictDigestAlgorithm(alg pkix.AlgorithmIdentifier) error {
	if _, err := getHashForOID(alg.Algorithm); err != nil {
		return fmt.Errorf("unsupported digest algorithm %q", alg.Algorithm.String())
	}
	if !algorithmIdentifierParametersAbsentOrNull(alg.Parameters) {
		return fmt.Errorf("digest algorithm %q parameters must be absent or NULL",
			alg.Algorithm.String())
	}
	return nil
}

func checkStrictSignatureParameters(alg pkix.AlgorithmIdentifier) error {
	oid := alg.Algorithm
	if _, ok := mlDSAAlgorithmForOID(oid); ok {
		if algorithmIdentifierParametersPresent(alg.Parameters) {
			return fmt.Errorf("ML-DSA algorithm %q parameters must be absent", oid.String())
		}
		return nil
	}
	switch {
	case oid.Equal(OIDEncryptionAlgorithmRSA),
		oid.Equal(OIDEncryptionAlgorithmRSASHA1),
		oid.Equal(OIDEncryptionAlgorithmRSASHA256),
		oid.Equal(OIDEncryptionAlgorithmRSASHA384),
		oid.Equal(OIDEncryptionAlgorithmRSASHA512),
		oid.Equal(OIDDigestAlgorithmECDSASHA1),
		oid.Equal(OIDDigestAlgorithmECDSASHA256),
		oid.Equal(OIDDigestAlgorithmECDSASHA384),
		oid.Equal(OIDDigestAlgorithmECDSASHA512),
		oid.Equal(OIDPublicKeyAlgorithmEC),
		oid.Equal(OIDEncryptionAlgorithmECDSAP256),
		oid.Equal(OIDEncryptionAlgorithmECDSAP384),
		oid.Equal(OIDEncryptionAlgorithmECDSAP521),
		oid.Equal(OIDEncryptionAlgorithmEDDSA25519):
		if !algorithmIdentifierParametersAbsentOrNull(alg.Parameters) {
			return fmt.Errorf("signature algorithm %q parameters must be absent or NULL",
				oid.String())
		}
	}
	// Unknown or unsupported signature algorithms are left to the
	// cryptographic verification path, which rejects them.
	return nil
}

// requiredDigestForSignatureOID reports the digest fixed by a signature
// algorithm OID, when the algorithm binds one.
func requiredDigestForSignatureOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(OIDEncryptionAlgorithmRSASHA1), oid.Equal(OIDDigestAlgorithmECDSASHA1):
		return crypto.SHA1, true
	case oid.Equal(OIDEncryptionAlgorithmRSASHA256), oid.Equal(OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, true
	case oid.Equal(OIDEncryptionAlgorithmRSASHA384), oid.Equal(OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, true
	case oid.Equal(OIDEncryptionAlgorithmRSASHA512), oid.Equal(OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, true
	}
	return crypto.Hash(0), false
}
