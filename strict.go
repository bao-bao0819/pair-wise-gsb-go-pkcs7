package pkcs7

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// StructuralError describes a self-contradictory CMS structure detected by
// the strict structural policy before any cryptographic verification takes
// place.
type StructuralError struct {
	// SignerIndex identifies the SignerInfo that caused the problem, or -1
	// when the problem is at the SignedData level.
	SignerIndex int
	// OID is the attribute or algorithm object identifier involved in the
	// problem. It is nil when no single OID can be blamed.
	OID asn1.ObjectIdentifier
	// Msg describes the structural problem.
	Msg string
}

func (e *StructuralError) Error() string {
	location := "signedData"
	if e.SignerIndex >= 0 {
		location = fmt.Sprintf("signer %d", e.SignerIndex)
	}
	if e.OID != nil {
		return fmt.Sprintf("pkcs7: invalid CMS structure: %s: %s (oid %s)", location, e.Msg, e.OID)
	}
	return fmt.Sprintf("pkcs7: invalid CMS structure: %s: %s", location, e.Msg)
}

// CheckStructure applies the strict structural policy to a parsed SignedData
// payload. It reports self-contradictory CMS structures as *StructuralError
// without performing any cryptographic operation:
//
//   - every SignerInfo digest algorithm must be advertised in the SignedData
//     digestAlgorithms set;
//   - digest and signature algorithm identifiers must use supported OIDs and
//     carry parameters valid for that algorithm (absent or NULL where the
//     algorithm allows it, never arbitrary DER);
//   - single-valued signed attributes (contentType, messageDigest,
//     signingTime) must appear at most once and hold exactly one value;
//   - the contentType signed attribute must match the SignedData content
//     type, and the messageDigest length must match the digest algorithm
//     output size.
//
// Signers without signed attributes are checked through their legitimate
// direct-signature path and are not rejected. Unknown unauthenticated
// (unsigned) attributes are ignored and preserved. The relative order of
// attributes inside a SET OF is irrelevant.
func (p7 *PKCS7) CheckStructure() error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if err := checkDigestAlgorithmSet(sd); err != nil {
		return err
	}
	for i := range sd.SignerInfos {
		if err := checkSignerInfoStructure(sd, i); err != nil {
			return err
		}
	}
	return nil
}

// VerifyStrict is a wrapper around VerifyWithChainStrict() that initializes
// an empty trust store, effectively disabling certificate verification when
// validating a signature.
func (p7 *PKCS7) VerifyStrict() (err error) {
	return p7.VerifyWithChainStrict(nil)
}

// VerifyWithChainStrict behaves like VerifyWithChain but applies the strict
// structural policy (see CheckStructure) before any cryptographic
// verification.
func (p7 *PKCS7) VerifyWithChainStrict(truststore *x509.CertPool) (err error) {
	intermediates := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
	}

	return p7.VerifyWithOptsStrict(opts)
}

// VerifyWithOptsStrict behaves like VerifyWithOpts but applies the strict
// structural policy (see CheckStructure) before any cryptographic
// verification.
func (p7 *PKCS7) VerifyWithOptsStrict(opts x509.VerifyOptions) (err error) {
	if err := p7.CheckStructure(); err != nil {
		return err
	}
	return p7.VerifyWithOpts(opts)
}

// checkDigestAlgorithmSet validates the SignedData digestAlgorithms set and
// its relationship with the signer infos.
func checkDigestAlgorithmSet(sd signedData) error {
	for _, ai := range sd.DigestAlgorithmIdentifiers {
		if _, err := getHashForOID(ai.Algorithm); err != nil {
			// The set may advertise algorithms this implementation does
			// not support; only entries for known algorithms have their
			// parameters shape enforced.
			continue
		}
		if !algorithmIdentifierParametersAbsentOrNull(ai.Parameters) {
			return &StructuralError{
				SignerIndex: -1,
				OID:         ai.Algorithm,
				Msg:         "digest algorithm identifier parameters must be absent or NULL",
			}
		}
	}
	for i := range sd.SignerInfos {
		digestOID := sd.SignerInfos[i].DigestAlgorithm.Algorithm
		advertised := false
		for _, ai := range sd.DigestAlgorithmIdentifiers {
			if ai.Algorithm.Equal(digestOID) {
				advertised = true
				break
			}
		}
		if !advertised {
			return &StructuralError{
				SignerIndex: i,
				OID:         digestOID,
				Msg:         "signer digest algorithm is not present in the SignedData digestAlgorithms set",
			}
		}
	}
	return nil
}

// checkSignerInfoStructure validates the algorithm identifiers and the
// authenticated attributes of a single signer info.
func checkSignerInfoStructure(sd signedData, index int) error {
	signer := sd.SignerInfos[index]

	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return &StructuralError{
			SignerIndex: index,
			OID:         signer.DigestAlgorithm.Algorithm,
			Msg:         "unsupported digest algorithm",
		}
	}
	if !algorithmIdentifierParametersAbsentOrNull(signer.DigestAlgorithm.Parameters) {
		return &StructuralError{
			SignerIndex: index,
			OID:         signer.DigestAlgorithm.Algorithm,
			Msg:         "digest algorithm identifier parameters must be absent or NULL",
		}
	}
	if err := checkSignatureAlgorithmIdentifier(signer, index); err != nil {
		return err
	}

	if len(signer.AuthenticatedAttributes) == 0 {
		// Legitimate direct-signature path: the signature is computed
		// over the content itself and no signed attributes are involved.
		return nil
	}
	return checkSignedAttributes(sd, signer, index, hash)
}

// checkSignatureAlgorithmIdentifier validates the SignerInfo
// signatureAlgorithm (digestEncryptionAlgorithm) identifier, including the
// shape of its parameters for every supported algorithm.
func checkSignatureAlgorithmIdentifier(signer signerInfo, index int) error {
	oid := signer.DigestEncryptionAlgorithm.Algorithm
	params := signer.DigestEncryptionAlgorithm.Parameters
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
		oid.Equal(OIDEncryptionAlgorithmECDSAP521):
		if !algorithmIdentifierParametersAbsentOrNull(params) {
			return &StructuralError{
				SignerIndex: index,
				OID:         oid,
				Msg:         "signature algorithm identifier parameters must be absent or NULL",
			}
		}
	case oid.Equal(OIDEncryptionAlgorithmEDDSA25519),
		oid.Equal(OIDSignatureAlgorithmMLDSA44),
		oid.Equal(OIDSignatureAlgorithmMLDSA65),
		oid.Equal(OIDSignatureAlgorithmMLDSA87):
		if algorithmIdentifierParametersPresent(params) {
			return &StructuralError{
				SignerIndex: index,
				OID:         oid,
				Msg:         "signature algorithm identifier parameters must be absent",
			}
		}
	}
	// The digest/signature combination must be one this implementation can
	// actually verify; getSignatureAlgorithm performs the remaining
	// algorithm-specific parameter checks (ML-DSA, id-ecPublicKey).
	if _, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm); err != nil {
		return &StructuralError{
			SignerIndex: index,
			OID:         oid,
			Msg:         err.Error(),
		}
	}
	return nil
}

// singleValuedSignedAttributeOIDs are the signed attributes that RFC 5652
// defines as single-valued: they must appear at most once and their
// attribute SET must hold exactly one value.
var singleValuedSignedAttributeOIDs = []asn1.ObjectIdentifier{
	OIDAttributeContentType,
	OIDAttributeMessageDigest,
	OIDAttributeSigningTime,
}

func isSingleValuedSignedAttribute(oid asn1.ObjectIdentifier) bool {
	for _, single := range singleValuedSignedAttributeOIDs {
		if oid.Equal(single) {
			return true
		}
	}
	return false
}

// countAttributeValues counts the values inside an attribute's SET OF
// AttributeValue, which is stored as concatenated DER encodings.
func countAttributeValues(attr attribute) (int, error) {
	count := 0
	rest := attr.Value.Bytes
	for len(rest) > 0 {
		var value asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &value)
		if err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

// checkSignedAttributes validates the authenticated attributes of a signer
// info against each other and against the SignedData content info.
func checkSignedAttributes(sd signedData, signer signerInfo, index int, hash crypto.Hash) error {
	seen := make(map[string]bool)
	var hasContentType, hasMessageDigest bool
	for _, attr := range signer.AuthenticatedAttributes {
		count, err := countAttributeValues(attr)
		if err != nil {
			return &StructuralError{
				SignerIndex: index,
				OID:         attr.Type,
				Msg:         "attribute values are not well-formed DER",
			}
		}
		if count == 0 {
			return &StructuralError{
				SignerIndex: index,
				OID:         attr.Type,
				Msg:         "attribute has an empty value set",
			}
		}
		if isSingleValuedSignedAttribute(attr.Type) {
			if seen[attr.Type.String()] {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg:         "single-valued attribute appears more than once",
				}
			}
			if count != 1 {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg:         fmt.Sprintf("single-valued attribute must hold exactly one value, found %d", count),
				}
			}
		}
		seen[attr.Type.String()] = true

		switch {
		case attr.Type.Equal(OIDAttributeContentType):
			hasContentType = true
			var contentType asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &contentType); err != nil {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg:         "contentType value is not an object identifier",
				}
			}
			if !contentType.Equal(sd.ContentInfo.ContentType) {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg: fmt.Sprintf("contentType %s does not match the signed content type %s",
						contentType.String(), sd.ContentInfo.ContentType.String()),
				}
			}
		case attr.Type.Equal(OIDAttributeMessageDigest):
			hasMessageDigest = true
			var digest []byte
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &digest); err != nil {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg:         "messageDigest value is not an octet string",
				}
			}
			if len(digest) != hash.Size() {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg: fmt.Sprintf("messageDigest is %d bytes, expected %d for the digest algorithm",
						len(digest), hash.Size()),
				}
			}
		case attr.Type.Equal(OIDAttributeSigningTime):
			var signingTime time.Time
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &signingTime); err != nil {
				return &StructuralError{
					SignerIndex: index,
					OID:         attr.Type,
					Msg:         "signingTime value is not a valid time",
				}
			}
		}
	}
	if !hasContentType {
		return &StructuralError{
			SignerIndex: index,
			OID:         OIDAttributeContentType,
			Msg:         "mandatory contentType signed attribute is missing",
		}
	}
	if !hasMessageDigest {
		return &StructuralError{
			SignerIndex: index,
			OID:         OIDAttributeMessageDigest,
			Msg:         "mandatory messageDigest signed attribute is missing",
		}
	}
	return nil
}
