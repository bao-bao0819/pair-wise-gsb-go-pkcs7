package pkcs7

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// SignerLayerResult reports verification of one top-level SignerInfo and
// all countersignatures attached to it. Primary and countersignature
// results are reported independently: a broken original signature does not
// prevent countersignature checks and vice versa.
type SignerLayerResult struct {
	// Index is the position of the SignerInfo in SignedData.signerInfos.
	Index int
	// Certificate is the message certificate identified by the SignerInfo,
	// or nil when no matching certificate is present.
	Certificate *x509.Certificate
	// PrimaryError is nil when the original signature verifies.
	PrimaryError error
	// Countersignatures reports each countersignature individually, in the
	// order in which they appear in the unsigned attributes.
	Countersignatures []CountersignatureResult
}

// CountersignatureResult reports verification of one countersignature
// SignerInfo nested in a top-level signer's unsigned attributes.
type CountersignatureResult struct {
	// AttributeOrder identifies the countersignature attribute occurrence
	// (RFC 5652 permits more than one); 0 is the first one.
	AttributeOrder int
	// Index is the position of the SignerInfo within that attribute.
	Index int
	// Certificate is the countersigner certificate, or nil when absent.
	Certificate *x509.Certificate
	// Error is nil when the countersignature verifies.
	Error error
}

// VerifyLayers verifies every original signature and every countersignature
// in the SignedData without chaining to a trust store.
// See VerifyLayersWithOpts.
func (p7 *PKCS7) VerifyLayers() ([]SignerLayerResult, error) {
	return p7.VerifyLayersWithOpts(x509.VerifyOptions{})
}

// VerifyLayersWithChain verifies every original signature and every
// countersignature, additionally checking certificate chains against
// truststore (a nil truststore disables chain checking).
func (p7 *PKCS7) VerifyLayersWithChain(truststore *x509.CertPool) ([]SignerLayerResult, error) {
	intermediates := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		intermediates.AddCert(cert)
	}
	return p7.VerifyLayersWithOpts(x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
	})
}

// VerifyLayersWithOpts verifies the original signatures of all top-level
// SignerInfo values together with their countersignatures.
//
// Each top-level SignerInfo is reported as one SignerLayerResult, and each
// countersignature is reported separately so that independent failures can
// be distinguished. Structural problems (for example a message without
// signers) are returned as the aggregated error; cryptographic failures are
// attached to the relevant result entry.
//
// Countersignatures are checked against the signatureValue of the signer
// they are attached to, as required by RFC 5652 section 11.4: their
// messageDigest authenticated attribute must equal the digest of that
// signatureValue, and they must not carry a contentType authenticated
// attribute. Nested countersignatures (countersignatures of
// countersignatures) are not processed: the corresponding SignerInfo is
// reported with ErrUnsupportedRecursiveCountersignature.
func (p7 *PKCS7) VerifyLayersWithOpts(opts x509.VerifyOptions) ([]SignerLayerResult, error) {
	if opts.KeyUsages == nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("pkcs7: Message has no signers")
	}

	results := make([]SignerLayerResult, len(p7.Signers))
	for i := range p7.Signers {
		results[i] = p7.verifySignerLayer(i, opts)
	}
	return results, nil
}

func (p7 *PKCS7) verifySignerLayer(index int, opts x509.VerifyOptions) SignerLayerResult {
	signer := p7.Signers[index]
	result := SignerLayerResult{
		Index:             index,
		Certificate:       getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber),
		Countersignatures: p7.verifyCountersignatures(signer, opts),
	}

	// Reuse the existing single-signer path for the original signature so
	// the primary result is byte-identical to VerifyWithOpts output.
	result.PrimaryError = verifySignature(p7, signer, opts)
	return result
}

func (p7 *PKCS7) verifyCountersignatures(target signerInfo, opts x509.VerifyOptions) []CountersignatureResult {
	var results []CountersignatureResult
	attributeOrder := 0
	for _, attr := range target.UnauthenticatedAttributes {
		if !attr.Type.Equal(OIDAttributeCountersignature) {
			continue
		}
		rest := attr.Value.Bytes
		counterIndex := 0
		for len(rest) > 0 {
			var rawValue asn1.RawValue
			remaining, err := asn1.Unmarshal(rest, &rawValue)
			if err != nil {
				results = append(results, CountersignatureResult{
					AttributeOrder: attributeOrder,
					Index:          counterIndex,
					Error:          fmt.Errorf("pkcs7: failed to parse countersignature SignerInfo: %w", err),
				})
				return results
			}
			rest = remaining

			var counter signerInfo
			_, parseErr := asn1.Unmarshal(rawValue.FullBytes, &counter)
			result := CountersignatureResult{
				AttributeOrder: attributeOrder,
				Index:          counterIndex,
			}
			if parseErr == nil {
				result.Certificate = getCertFromCertsByIssuerAndSerial(p7.Certificates, counter.IssuerAndSerialNumber)
				result.Error = p7.verifyCountersignature(target, counter, opts)
			} else {
				result.Error = fmt.Errorf("pkcs7: failed to parse countersignature SignerInfo: %w", parseErr)
			}
			results = append(results, result)
			counterIndex++
		}
		attributeOrder++
	}
	return results
}

func (p7 *PKCS7) verifyCountersignature(target, counter signerInfo, opts x509.VerifyOptions) error {
	// RFC 5652 11.4: a countersignature is itself a SignerInfo, but this
	// package does not support countersigning countersignatures. When a
	// nested one is present, report it and leave the raw value untouched.
	for _, attr := range counter.UnauthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeCountersignature) {
			return ErrUnsupportedRecursiveCountersignature
		}
	}

	if len(counter.AuthenticatedAttributes) == 0 {
		return errors.New("pkcs7: countersignature is missing authenticated attributes")
	}
	// The contentType attribute is forbidden: the countersignature signs the
	// target signatureValue, not the encapsulated content.
	for _, attr := range counter.AuthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeContentType) {
			return ErrCountersignatureContentTypeForbidden
		}
	}

	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, counter.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for countersigner")
	}

	var digest []byte
	if err := unmarshalAttribute(counter.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
		return err
	}
	hash, err := getHashForOID(counter.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(target.EncryptedDigest)
	if subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
		return &MessageDigestMismatchError{
			ExpectedDigest: digest,
			ActualDigest:   sumHash(hash, target.EncryptedDigest),
		}
	}

	var signingTime time.Time
	if err := unmarshalAttribute(counter.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime); err == nil {
		if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
			return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
				signingTime.Format(time.RFC3339),
				ee.NotBefore.Format(time.RFC3339),
				ee.NotAfter.Format(time.RFC3339))
		}
	}

	if opts.Roots != nil {
		chainOpts := opts
		if chainOpts.CurrentTime.IsZero() && !signingTime.IsZero() {
			chainOpts.CurrentTime = signingTime
		}
		if _, err := ee.Verify(chainOpts); err != nil {
			return fmt.Errorf("pkcs7: failed to verify countersigner certificate chain: %v", err)
		}
	}

	signedAttributes, err := marshalAttributes(counter.AuthenticatedAttributes)
	if err != nil {
		return err
	}
	sigalg, err := getSignatureAlgorithm(counter.DigestEncryptionAlgorithm, counter.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedAttributes, counter.EncryptedDigest)
}

func sumHash(hash crypto.Hash, data []byte) []byte {
	h := hash.New()
	h.Write(data)
	return h.Sum(nil)
}
