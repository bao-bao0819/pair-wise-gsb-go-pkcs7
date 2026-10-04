package pkcs7

import (
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// CountersignerConfig are optional values to include when adding a
// countersigner. Unlike SignerInfoConfig, countersignatures never get a
// contentType authenticated attribute: RFC 5652 section 11.4 forbids it, and
// their messageDigest always covers the target SignerInfo signatureValue.
type CountersignerConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
	SkipCertificates        bool
	// SkipSigningTime omits the signing-time signed attribute.
	SkipSigningTime bool
}

// AddCountersigner adds a CMS countersignature as an unsigned attribute of the
// SignerInfo selected by targetSignerInfo, which indexes SignerInfos in
// insertion order. Per RFC 5652 section 11.4 the countersigner computes its
// messageDigest over the DER encoding of the target signer's signatureValue
// (never over the encapsulated content), signs its authenticated attributes,
// and stores the resulting SignerInfo in an id-countersignature
// (1.2.840.113549.1.9.6) unsigned attribute. Several countersignatures can be
// attached to the same SignerInfo; the countersigner certificate is added to
// SignedData certificates unless SkipCertificates is set.
//
// Countersignatures of an existing countersignature (nested countersignatures)
// cannot be produced with this interface.
func (sd *SignedData) AddCountersigner(targetSignerInfo int, ee *x509.Certificate, keyOrSigner interface{}, config CountersignerConfig) error {
	if targetSignerInfo < 0 || targetSignerInfo >= len(sd.sd.SignerInfos) {
		return fmt.Errorf("pkcs7: target signer info index %d out of range (have %d signer infos)",
			targetSignerInfo, len(sd.sd.SignerInfos))
	}
	target := &sd.sd.SignerInfos[targetSignerInfo]
	if len(target.EncryptedDigest) == 0 {
		return errors.New("pkcs7: target signer info has no signatureValue to countersign")
	}
	for _, attr := range config.ExtraSignedAttributes {
		if attr.Type.Equal(OIDAttributeContentType) {
			return ErrCountersignatureForbiddenContentType
		}
		if attr.Type.Equal(OIDAttributeMessageDigest) {
			return errors.New("pkcs7: messageDigest is computed over the target signatureValue and cannot be supplied as an extra signed attribute")
		}
	}
	for _, attr := range config.ExtraUnsignedAttributes {
		if attr.Type.Equal(OIDAttributeCountersignature) {
			return ErrNestedCountersignature
		}
	}

	algorithm, err := getCMSSignerAlgorithm(keyOrSigner, sd.digestOid, nil)
	if err != nil {
		return err
	}
	signHash, err := getHashForOID(algorithm.digestOID)
	if err != nil {
		return err
	}
	// The countersigned messageDigest uses the caller-selected digest, except
	// ML-DSA for which RFC 9882 mandates SHA-512 (while still signing in pure
	// mode).
	counterDigestOID := sd.digestOid
	if algorithm.mode == cmsSigningModeMLDSA {
		counterDigestOID = OIDDigestAlgorithmSHA512
	}
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: counterDigestOID})
	digestHash, err := getHashForOID(counterDigestOID)
	if err != nil {
		return err
	}
	h := digestHash.New()
	h.Write(target.EncryptedDigest)
	messageDigest := h.Sum(nil)

	attrs := &attributes{}
	attrs.Add(OIDAttributeMessageDigest, messageDigest)
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
	signature, err := algorithm.sign(keyOrSigner, attrBytes, signHash)
	if err != nil {
		return err
	}

	countersigner := signerInfo{
		Version:                   1,
		IssuerAndSerialNumber:     cert2issuerAndSerial(ee),
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: counterDigestOID},
		AuthenticatedAttributes:   finalAttrs,
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm.signatureOID},
		EncryptedDigest:           signature,
		UnauthenticatedAttributes: finalUnsignedAttrs,
	}
	if err := appendCountersignatureAttribute(target, countersigner); err != nil {
		return err
	}
	if !config.SkipCertificates {
		sd.certs = append(sd.certs, ee)
	}
	return nil
}

// appendCountersignatureAttribute appends a countersigner SignerInfo to the
// target's id-countersignature unsigned attribute, creating the attribute
// when the target has none yet. Multiple countersignatures are carried as a
// SET OF SignerInfo in a single attribute value.
func appendCountersignatureAttribute(target *signerInfo, countersigner signerInfo) error {
	encoded, err := asn1.Marshal(countersigner)
	if err != nil {
		return err
	}
	for i := range target.UnauthenticatedAttributes {
		attr := &target.UnauthenticatedAttributes[i]
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		// attr.Value.Bytes carries the full SET TLV. Strip its header to
		// validate the members, then append the new SignerInfo and rewrap.
		var set asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Value.Bytes, &set); err != nil {
			return fmt.Errorf("pkcs7: malformed existing countersignature attribute: %v", err)
		}
		if set.Tag != asn1.TagSet {
			return errors.New("pkcs7: countersignature attribute value is not a SET")
		}
		members := set.Bytes
		for len(members) > 0 {
			var raw asn1.RawValue
			rest, err := asn1.Unmarshal(members, &raw)
			if err != nil {
				return fmt.Errorf("pkcs7: malformed existing countersignature attribute: %v", err)
			}
			members = rest
		}
		memberBytes := append(append([]byte(nil), set.Bytes...), encoded...)
		setValue := asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: memberBytes}
		setTLV, err := asn1.Marshal(setValue)
		if err != nil {
			return err
		}
		attr.Value.Bytes = setTLV
		attr.Value.FullBytes = nil
		return nil
	}

	setTLV, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: encoded})
	if err != nil {
		return err
	}
	target.UnauthenticatedAttributes = append(target.UnauthenticatedAttributes, attribute{
		Type:  OIDAttributeCountersignature,
		Value: asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: setTLV},
	})
	return nil
}

// SignatureReport describes verification of one primary SignerInfo and all
// countersignatures attached to it. OriginalError is the failure of the
// original signature over the content (or its authenticated attributes);
// Countersignatures reports each id-countersignature entry independently so a
// bad countersignature never masks or invalidates the original signature.
type SignatureReport struct {
	Signer            *x509.Certificate
	OriginalError     error
	Countersignatures []CountersignatureReport
}

// CountersignatureReport describes verification of a single countersignature
// SignerInfo. Nested countersignatures attached to the countersigner are not
// evaluated: their raw DER encodings are returned in NestedRaw and Error is
// ErrNestedCountersignature when the countersignature itself otherwise
// verifies.
type CountersignatureReport struct {
	Countersigner *x509.Certificate
	Error         error
	NestedRaw     [][]byte
}

var (
	// ErrCountersignatureForbiddenContentType is returned when a
	// countersignature SignerInfo carries a contentType authenticated
	// attribute, which RFC 5652 section 11.4 forbids.
	ErrCountersignatureForbiddenContentType = errors.New("pkcs7: countersignature must not include a contentType authenticated attribute")
	// ErrNestedCountersignature is returned when a countersignature itself
	// carries id-countersignature unsigned attributes; recursively
	// countersigning a countersignature is outside the supported interface.
	ErrNestedCountersignature = errors.New("pkcs7: nested countersignatures are not supported")
)

// CountersignatureDigestMismatchError is returned when a countersignature
// messageDigest does not match the digest computed over the target
// SignerInfo signatureValue. It is distinct from MessageDigestMismatchError,
// which concerns the encapsulated content of a primary signature.
type CountersignatureDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *CountersignatureDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: countersignature message digest over target signatureValue mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

// VerifySignatures checks every primary SignerInfo and every countersignature
// attached to it, reporting each layer independently. Certificate chain
// handling follows VerifyWithChain: certificates embedded in the SignedData
// are used as intermediates, and when opts.Roots is nil the certificates are
// not chain-validated. The returned error is non-nil only for structural
// problems (for example no signers); per-layer failures are reported in the
// SignatureReport slice. Call ReportsError for an aggregate error.
func (p7 *PKCS7) VerifySignatures(opts x509.VerifyOptions) ([]SignatureReport, error) {
	if opts.KeyUsages == nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("pkcs7: Message has no signers")
	}
	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	}
	for _, cert := range p7.Certificates {
		opts.Intermediates.AddCert(cert)
	}
	reports := make([]SignatureReport, len(p7.Signers))
	for i, signer := range p7.Signers {
		report := SignatureReport{
			Signer: getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber),
		}
		if opts.CurrentTime.IsZero() {
			report.OriginalError = verifySignature(p7, signer, opts)
		} else {
			report.OriginalError = verifySignatureAtTime(p7, signer, opts)
		}
		report.Countersignatures = verifyCountersignatures(p7, signer, opts)
		reports[i] = report
	}
	return reports, nil
}

// ReportsError returns nil when every primary signature and every
// countersignature verified successfully, otherwise an error listing all
// failing layers by signer position.
func ReportsError(reports []SignatureReport) error {
	var failures []string
	for i, report := range reports {
		if report.OriginalError != nil {
			failures = append(failures, fmt.Sprintf("signer %d: %v", i, report.OriginalError))
		}
		for j, counter := range report.Countersignatures {
			if counter.Error != nil {
				failures = append(failures, fmt.Sprintf("signer %d countersignature %d: %v", i, j, counter.Error))
			}
		}
	}
	if len(failures) == 0 {
		return nil
	}
	joined := "pkcs7: signature verification failed:"
	for _, failure := range failures {
		joined += "\n\t" + failure
	}
	return errors.New(joined)
}

func verifyCountersignatures(p7 *PKCS7, signer signerInfo, opts x509.VerifyOptions) []CountersignatureReport {
	var reports []CountersignatureReport
	for _, attr := range signer.UnauthenticatedAttributes {
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		members, err := countersignatureSetMembers(attr.Value.Bytes)
		if err != nil {
			reports = append(reports, CountersignatureReport{Error: err})
			continue
		}
		rest := members
		for len(rest) > 0 {
			var counter signerInfo
			if rest, err = asn1.Unmarshal(rest, &counter); err != nil {
				reports = append(reports, CountersignatureReport{Error: fmt.Errorf("pkcs7: malformed countersignature SignerInfo: %v", err)})
				break
			}
			reports = append(reports, verifyCountersignature(p7, counter, signer.EncryptedDigest, opts))
		}
	}
	return reports
}

// countersignatureSetMembers returns the raw SignerInfo encodings inside an
// id-countersignature attribute SET. The parsed attribute value may carry
// either the SET content alone (strict DER produced by this package's
// builder) or the complete SET TLV, so both forms are accepted.
func countersignatureSetMembers(value []byte) ([]byte, error) {
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(value, &set); err != nil {
		return nil, fmt.Errorf("pkcs7: malformed countersignature attribute: %v", err)
	}
	if set.Tag == asn1.TagSet && set.IsCompound {
		return set.Bytes, nil
	}
	return value, nil
}

func verifyCountersignature(p7 *PKCS7, counter signerInfo, targetSignature []byte, opts x509.VerifyOptions) CountersignatureReport {
	report := CountersignatureReport{
		Countersigner: getCertFromCertsByIssuerAndSerial(p7.Certificates, counter.IssuerAndSerialNumber),
	}
	countersignerCert := report.Countersigner
	if countersignerCert == nil {
		report.Error = errors.New("pkcs7: No certificate for countersigner")
		return report
	}

	// RFC 5652 11.4: a countersignature must not carry contentType.
	if _, err := unmarshalRawAttribute(counter.AuthenticatedAttributes, OIDAttributeContentType); err == nil {
		report.Error = ErrCountersignatureForbiddenContentType
		return report
	}

	var digest []byte
	if err := unmarshalAttribute(counter.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
		report.Error = errors.New("pkcs7: countersignature is missing the messageDigest authenticated attribute")
		return report
	}
	hash, err := getHashForOID(counter.DigestAlgorithm.Algorithm)
	if err != nil {
		report.Error = err
		return report
	}
	h := hash.New()
	h.Write(targetSignature)
	computed := h.Sum(nil)
	if subtle.ConstantTimeCompare(digest, computed) != 1 {
		report.Error = &CountersignatureDigestMismatchError{
			ExpectedDigest: digest,
			ActualDigest:   computed,
		}
		return report
	}

	if opts.Roots != nil {
		chainOpts := opts
		if chainOpts.CurrentTime.IsZero() {
			signingTime := time.Now().UTC()
			if err := unmarshalAttribute(counter.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime); err == nil {
				if signingTime.After(countersignerCert.NotAfter) || signingTime.Before(countersignerCert.NotBefore) {
					report.Error = fmt.Errorf("pkcs7: signing time %q is outside of countersigner certificate validity %q to %q",
						signingTime.Format(time.RFC3339),
						countersignerCert.NotBefore.Format(time.RFC3339),
						countersignerCert.NotAfter.Format(time.RFC3339))
					return report
				}
			}
			chainOpts.CurrentTime = signingTime
		}
		if _, err := countersignerCert.Verify(chainOpts); err != nil {
			report.Error = fmt.Errorf("pkcs7: failed to verify countersigner certificate chain: %v", err)
			return report
		}
	}
	sigalg, err := getSignatureAlgorithm(counter.DigestEncryptionAlgorithm, counter.DigestAlgorithm)
	if err != nil {
		report.Error = err
		return report
	}
	attrBytes, err := marshalAttributes(counter.AuthenticatedAttributes)
	if err != nil {
		report.Error = err
		return report
	}
	if err := countersignerCert.CheckSignature(sigalg, attrBytes, counter.EncryptedDigest); err != nil {
		report.Error = fmt.Errorf("pkcs7: countersignature verification failed: %v", err)
		return report
	}

	if nested := unsignedCountersignatureAttributes(counter.UnauthenticatedAttributes); len(nested) > 0 {
		report.NestedRaw = nested
		report.Error = ErrNestedCountersignature
	}
	return report
}

func unsignedCountersignatureAttributes(attrs []attribute) [][]byte {
	var nested [][]byte
	for _, attr := range attrs {
		if attr.Type.Equal(OIDAttributeCountersignature) {
			nested = append(nested, attr.Value.FullBytes)
		}
	}
	return nested
}

func unmarshalRawAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier) (asn1.RawValue, error) {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			var raw asn1.RawValue
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &raw); err != nil {
				return asn1.RawValue{}, err
			}
			return raw, nil
		}
	}
	return asn1.RawValue{}, errors.New("pkcs7: attribute type not in attributes")
}
