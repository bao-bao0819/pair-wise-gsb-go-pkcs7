package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// OIDAttributeCountersignature is the countersignature unsigned attribute
// defined in RFC 5652 section 11.4
// (1.2.840.113549.1.9.6). Countersignatures are SignerInfo values carried
// in the unauthenticatedAttributes of the signer they counter-sign.
var OIDAttributeCountersignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}

var (
	// ErrUnsupportedCountersignatureType is returned when an operation that
	// only supports SignedData is used with another content type.
	ErrUnsupportedCountersignatureType = errors.New("pkcs7: countersignatures are only supported on signedData")

	// ErrCountersignatureContentTypeForbidden is returned when a
	// countersignature is created with a contentType authenticated attribute
	// or when a countersignature being verified carries one. RFC 5652
	// section 11.4 restricts the authenticated attributes of a
	// countersignature; in particular contentType is not permitted because
	// the countersignature signs a signatureValue rather than content.
	ErrCountersignatureContentTypeForbidden = errors.New("pkcs7: countersignature must not include a contentType authenticated attribute")

	// ErrUnsupportedRecursiveCountersignature is returned when an attempt is
	// made to verify a countersignature nested inside another countersignature.
	// This package only handles countersignatures attached to top-level
	// SignerInfo values.
	ErrUnsupportedRecursiveCountersignature = errors.New("pkcs7: recursive countersignatures are not supported")
)

// AddCountersignature is a wrapper around AddCountersignatureChain that adds
// a countersignature whose signer certificate has no parents in the message.
// See AddCountersignatureChain for details.
func (p7 *PKCS7) AddCountersignature(signerIndex int, ee *x509.Certificate, keyOrSigner interface{}, config SignerInfoConfig) error {
	return p7.AddCountersignatureChain(signerIndex, ee, keyOrSigner, nil, config)
}

// AddCountersignatureChain adds a CMS countersignature (RFC 5652 section 11.4)
// for the existing SignerInfo at signerIndex. The countersignature signs the
// target signer's signatureValue, not the encapsulated content, and is stored
// in the target's unauthenticatedAttributes under the countersignature OID.
//
// The target SignerInfo, its authenticatedAttributes, and its signatureValue
// are never modified. The countersigner certificate (and any parents) is
// appended to the message certificates unless SkipCertificates is set.
//
// A countersignature carries a messageDigest authenticated attribute computed
// over the target signatureValue. A contentType authenticated attribute is
// forbidden and signingTime is added unless SkipSigningTime is set.
// Countersignatures nested inside another countersignature are not supported.
func (p7 *PKCS7) AddCountersignatureChain(signerIndex int, ee *x509.Certificate, keyOrSigner interface{}, parents []*x509.Certificate, config SignerInfoConfig) error {
	if _, ok := p7.raw.(signedData); !ok {
		return ErrUnsupportedCountersignatureType
	}
	if signerIndex < 0 || signerIndex >= len(p7.Signers) {
		return fmt.Errorf("pkcs7: signerInfo index %d out of range, message has %d signer(s)", signerIndex, len(p7.Signers))
	}
	if slices.ContainsFunc(config.ExtraSignedAttributes, func(attr Attribute) bool {
		return attr.Type.Equal(OIDAttributeContentType)
	}) {
		return ErrCountersignatureContentTypeForbidden
	}
	if slices.ContainsFunc(config.ExtraUnsignedAttributes, func(attr Attribute) bool {
		return attr.Type.Equal(OIDAttributeCountersignature)
	}) {
		return ErrUnsupportedRecursiveCountersignature
	}

	digestOID, err := GetDigestOIDForSignatureAlgorithm(ee.SignatureAlgorithm)
	if err != nil {
		return err
	}
	algorithm, err := getCMSSignerAlgorithm(keyOrSigner, digestOID, nil)
	if err != nil {
		return err
	}
	if err := ensureDigestAlgorithm(p7, algorithm.digestOID); err != nil {
		return err
	}

	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		if err := verifyPartialChain(ee, parents); err != nil {
			return err
		}
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}

	hash, err := getHashForOID(algorithm.digestOID)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(p7.Signers[signerIndex].EncryptedDigest)
	targetDigest := h.Sum(nil)

	attrs := &attributes{}
	attrs.Add(OIDAttributeMessageDigest, targetDigest)
	hasExplicitSigningTime := slices.ContainsFunc(
		config.ExtraSignedAttributes,
		func(attr Attribute) bool { return attr.Type.Equal(OIDAttributeSigningTime) },
	)
	if !config.SkipSigningTime && !hasExplicitSigningTime {
		attrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	}
	addedExplicitSigningTime := false
	for _, attr := range config.ExtraSignedAttributes {
		if attr.Type.Equal(OIDAttributeSigningTime) {
			if config.SkipSigningTime || addedExplicitSigningTime {
				continue
			}
			addedExplicitSigningTime = true
		}
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}
	unsignedAttrs := &attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}
	attrBytes, err := marshalAttributes(finalAttrs)
	if err != nil {
		return err
	}
	signature, err := algorithm.sign(keyOrSigner, attrBytes, hash)
	if err != nil {
		return err
	}

	counterSignerInfo := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		UnauthenticatedAttributes: finalUnsignedAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: algorithm.digestOID},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm.signatureOID},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	if err := appendCountersignature(&p7.Signers[signerIndex], counterSignerInfo); err != nil {
		return err
	}

	if !config.SkipCertificates {
		if getCertFromCertsByIssuerAndSerial(p7.Certificates, ias) == nil {
			p7.Certificates = append(p7.Certificates, ee)
		}
		for _, parent := range parents {
			if getCertFromCertsByIssuerAndSerial(p7.Certificates, cert2issuerAndSerial(parent)) == nil {
				p7.Certificates = append(p7.Certificates, parent)
			}
		}
	}
	return p7.syncRawSignedData()
}

// RawCountersignatures returns the raw DER-encoded countersignature
// SignerInfo values attached to the top-level SignerInfo at signerIndex.
// Nested countersignatures are not decoded by this package.
func (p7 *PKCS7) RawCountersignatures(signerIndex int) ([][]byte, error) {
	if _, ok := p7.raw.(signedData); !ok {
		return nil, ErrUnsupportedCountersignatureType
	}
	if signerIndex < 0 || signerIndex >= len(p7.Signers) {
		return nil, fmt.Errorf("pkcs7: signerInfo index %d out of range, message has %d signer(s)", signerIndex, len(p7.Signers))
	}
	return countersignatureValues(p7.Signers[signerIndex].UnauthenticatedAttributes)
}

// Marshal re-serializes a parsed SignedData message, including any
// countersignatures added to its SignerInfo values.
func (p7 *PKCS7) Marshal() ([]byte, error) {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return nil, ErrUnsupportedCountersignatureType
	}
	sd.SignerInfos = p7.Signers
	sd.Certificates = marshalCertificates(p7.Certificates)
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// syncRawSignedData writes the mutable signer list back into the parsed
// signedData envelope so that a later re-marshal observes unsigned
// attributes added in place.
func (p7 *PKCS7) syncRawSignedData() error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return ErrUnsupportedCountersignatureType
	}
	sd.SignerInfos = p7.Signers
	p7.raw = sd
	return nil
}

// appendCountersignature appends a countersignature SignerInfo to the target
// signer's countersignature unsigned attribute. Multiple countersignatures
// are grouped in a single attribute SET, as produced by common CMS toolkits;
// any pre-existing countersignature attributes are preserved and extended.
func appendCountersignature(target *signerInfo, counter signerInfo) error {
	encoded, err := asn1.Marshal(counter)
	if err != nil {
		return err
	}
	for i := range target.UnauthenticatedAttributes {
		if target.UnauthenticatedAttributes[i].Type.Equal(OIDAttributeCountersignature) {
			target.UnauthenticatedAttributes[i].Value.Bytes = append(
				target.UnauthenticatedAttributes[i].Value.Bytes, encoded...)
			// The attribute was decoded and carries cached FullBytes; drop
			// them so the appended SignerInfo is not lost on re-marshal.
			target.UnauthenticatedAttributes[i].Value.FullBytes = nil
			return nil
		}
	}
	target.UnauthenticatedAttributes = append(target.UnauthenticatedAttributes, attribute{
		Type:  OIDAttributeCountersignature,
		Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: encoded},
	})
	return nil
}

// countersignatureValues extracts the individual DER-encoded SignerInfo
// values from the countersignature unsigned attribute(s).
func countersignatureValues(attrs []attribute) ([][]byte, error) {
	var values [][]byte
	for _, attr := range attrs {
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		rest := attr.Value.Bytes
		for len(rest) > 0 {
			var raw asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
				return nil, fmt.Errorf("pkcs7: failed to parse countersignature SignerInfo: %w", err)
			}
			values = append(values, raw.FullBytes)
		}
	}
	return values, nil
}

// ensureDigestAlgorithm adds the digest algorithm identifier to the
// SignedData digestAlgorithms set when it is not already present.
func ensureDigestAlgorithm(p7 *PKCS7, digestOID asn1.ObjectIdentifier) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return ErrUnsupportedCountersignatureType
	}
	for _, alg := range sd.DigestAlgorithmIdentifiers {
		if alg.Algorithm.Equal(digestOID) {
			return nil
		}
	}
	sd.DigestAlgorithmIdentifiers = append(sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: digestOID})
	p7.raw = sd
	return nil
}
