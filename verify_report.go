package pkcs7

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// VerifyPolicy selects how the per-SignerInfo results of a detailed
// verification are combined into an overall decision.
type VerifyPolicy int

const (
	// PolicyAll accepts the SignedData only when every SignerInfo is valid.
	PolicyAll VerifyPolicy = iota
	// PolicyAny accepts the SignedData when at least one SignerInfo is valid.
	PolicyAny
	// PolicyAtLeastKDistinct accepts the SignedData when at least K valid
	// SignerInfos originate from distinct identities, where an identity is
	// derived from IdentityBasis. A repeated SignerInfo from the same
	// certificate or public key never counts more than once.
	PolicyAtLeastKDistinct
)

// IdentityBasis selects how callers identify a signer when counting distinct
// identities for PolicyAtLeastKDistinct.
type IdentityBasis int

const (
	// IdentityCertificateFingerprint identifies signers by the SHA-256
	// fingerprint of the DER-encoded signer certificate.
	IdentityCertificateFingerprint IdentityBasis = iota
	// IdentityPublicKeyFingerprint identifies signers by the SHA-256
	// fingerprint of the DER-encoded signer public key (SPKI).
	IdentityPublicKeyFingerprint
)

// CheckStatus is the outcome of a single verification check performed on a
// SignerInfo.
type CheckStatus int

const (
	// CheckPassed means the check succeeded.
	CheckPassed CheckStatus = iota
	// CheckFailed means the check ran and failed.
	CheckFailed
	// CheckSkipped means the check does not apply to this SignerInfo.
	CheckSkipped
)

// Detailed errors reported per SignerInfo. They can be used with errors.Is
// against SignerVerificationReport.Err and the individual CheckResult.Err
// values.
var (
	// ErrCertificateNotFound is reported when no embedded certificate matches
	// the SignerInfo issuerAndSerialNumber.
	ErrCertificateNotFound = errors.New("pkcs7: no certificate for signer")
	// ErrCertificateAmbiguous is reported when more than one distinct embedded
	// certificate shares the SignerInfo issuerAndSerialNumber.
	ErrCertificateAmbiguous = errors.New("pkcs7: multiple certificates match signer issuer and serial number")
	// ErrDigestMismatch is reported when the signed message-digest attribute
	// does not match the digest computed over the encapsulated content.
	ErrDigestMismatch = errors.New("pkcs7: message digest mismatch")
	// ErrInvalidSignature is reported when the cryptographic signature over
	// the content (or authenticated attributes) does not verify.
	ErrInvalidSignature = errors.New("pkcs7: invalid signature")
)

// VerifyReportOptions configures a detailed, per-SignerInfo verification.
type VerifyReportOptions struct {
	// Roots and Intermediates configure certificate chain verification. When
	// Roots is nil, chain verification is skipped and the TrustChain check is
	// reported as CheckSkipped. When Intermediates is nil, the certificates
	// embedded in the SignedData are used, mirroring VerifyWithChain.
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// KeyUsages defaults to x509.ExtKeyUsageAny when empty, mirroring
	// VerifyWithOpts.
	KeyUsages []x509.ExtKeyUsage
	// CurrentTime is the only time used for certificate chain validation. The
	// signed signingTime attribute is never substituted for it; it is reported
	// only as an untrusted claim carried by the signature.
	CurrentTime time.Time

	// Policy combines the individual results into an overall decision.
	Policy VerifyPolicy
	// K is the number of distinct valid identities required by
	// PolicyAtLeastKDistinct and is ignored by the other policies.
	K int
	// IdentityBasis selects certificate or public-key fingerprinting for the
	// distinct-identity count.
	IdentityBasis IdentityBasis
}

// CheckResult reports the outcome of a single verification check.
type CheckResult struct {
	Status CheckStatus
	// Err is nil for CheckPassed and CheckSkipped, otherwise it describes the
	// failure and wraps one of the exported sentinel errors.
	Err error
}

func checkSkipped() CheckResult { return CheckResult{Status: CheckSkipped} }

func checkPass() CheckResult { return CheckResult{Status: CheckPassed} }

func checkFailed(err error) CheckResult { return CheckResult{Status: CheckFailed, Err: err} }

// SignerVerificationReport records the detailed verification evidence for a
// single SignerInfo, in the same order as PKCS7.Signers.
type SignerVerificationReport struct {
	Index int

	DigestAlgorithm    asn1.ObjectIdentifier
	SignatureAlgorithm asn1.ObjectIdentifier
	IssuerAndSerial    issuerAndSerial
	Certificate        *x509.Certificate

	// SigningTime is the signed signingTime attribute when present. It is a
	// claim carried by the signature and is never used as the chain
	// validation time.
	SigningTime    time.Time
	HasSigningTime bool

	CertificateFingerprint []byte
	PublicKeyFingerprint   []byte

	// CertificateMatch covers finding a unique embedded certificate for the
	// SignerInfo issuerAndSerialNumber.
	CertificateMatch CheckResult
	// ContentDigest covers the message-digest attribute against the content.
	// It is skipped for SignerInfos without authenticated attributes, where
	// the signature is computed directly over the content.
	ContentDigest CheckResult
	// Signature covers the cryptographic signature verification.
	Signature CheckResult
	// TrustChain covers certificate chain validation against Roots. It is
	// skipped when no Roots pool is provided.
	TrustChain CheckResult

	// Valid is true only when every applicable check passed.
	Valid bool
	// Err wraps the first failure that makes this SignerInfo invalid.
	Err error
}

func (report *SignerVerificationReport) identityFingerprint(basis IdentityBasis) []byte {
	if basis == IdentityPublicKeyFingerprint {
		return report.PublicKeyFingerprint
	}
	return report.CertificateFingerprint
}

// VerificationReport is the result of a detailed verification.
type VerificationReport struct {
	Signers []SignerVerificationReport
	// ValidSigners indexes the reports whose checks all passed.
	ValidSigners []int
	// DistinctValidIdentities holds the identity fingerprints that valid
	// SignerInfos reduced to, each counted once.
	DistinctValidIdentities [][]byte
	// Accepted is the final policy decision.
	Accepted bool
	// Err is nil when Accepted is true and otherwise a *PolicyError.
	Err error
}

// PolicyError explains why the configured VerifyPolicy was not satisfied.
type PolicyError struct {
	Policy                  VerifyPolicy
	Required                int
	Total                   int
	ValidSigners            int
	DistinctValidIdentities int
}

func (err *PolicyError) Error() string {
	switch err.Policy {
	case PolicyAll:
		return fmt.Sprintf("pkcs7: policy requires all %d signer(s) to verify, but only %d did",
			err.Total, err.ValidSigners)
	case PolicyAny:
		return fmt.Sprintf("pkcs7: policy requires at least one valid signer out of %d, but none verified",
			err.Total)
	case PolicyAtLeastKDistinct:
		return fmt.Sprintf("pkcs7: policy requires %d distinct valid identit(ies), but found %d among %d signer(s)",
			err.Required, err.DistinctValidIdentities, err.Total)
	default:
		return fmt.Sprintf("pkcs7: unknown verification policy %d", err.Policy)
	}
}

// VerifyWithReport verifies every SignerInfo independently and returns the
// full evidence for each of them together with an explicit, caller-controlled
// policy decision.
//
// Unlike VerifyWithOpts, it never returns on the first failing signer: the
// other signers are still examined so genuine evidence about them is not lost.
// Certificate chain validation uses only opts.CurrentTime; the signed
// signingTime attribute is surfaced in the report as a claim and never
// replaces the caller's trust time.
func (p7 *PKCS7) VerifyWithReport(opts VerifyReportOptions) (*VerificationReport, error) {
	if len(p7.Signers) == 0 {
		return nil, errors.New("pkcs7: message has no signers")
	}
	if opts.Policy == PolicyAtLeastKDistinct && opts.K <= 0 {
		return nil, fmt.Errorf("pkcs7: policy threshold K must be positive, got %d", opts.K)
	}

	intermediates := opts.Intermediates
	if intermediates == nil {
		intermediates = x509.NewCertPool()
		for _, cert := range p7.Certificates {
			intermediates.AddCert(cert)
		}
	}
	chainOpts := x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   opts.CurrentTime,
	}
	if opts.KeyUsages == nil {
		chainOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	} else {
		chainOpts.KeyUsages = opts.KeyUsages
	}

	report := &VerificationReport{Signers: make([]SignerVerificationReport, len(p7.Signers))}
	seenIdentities := map[string]struct{}{}
	for index, signer := range p7.Signers {
		signerReport := p7.verifySignerReport(index, signer, chainOpts)
		report.Signers[index] = signerReport
		if signerReport.Valid {
			report.ValidSigners = append(report.ValidSigners, index)
			fingerprint := signerReport.identityFingerprint(opts.IdentityBasis)
			key := string(fingerprint)
			if _, ok := seenIdentities[key]; !ok {
				seenIdentities[key] = struct{}{}
				report.DistinctValidIdentities = append(report.DistinctValidIdentities, fingerprint)
			}
		}
	}

	if !report.evaluatePolicy(opts) {
		report.Err = &PolicyError{
			Policy:                  opts.Policy,
			Required:                opts.K,
			Total:                   len(report.Signers),
			ValidSigners:            len(report.ValidSigners),
			DistinctValidIdentities: len(report.DistinctValidIdentities),
		}
	}
	report.Accepted = report.Err == nil
	return report, nil
}

func (report *VerificationReport) evaluatePolicy(opts VerifyReportOptions) bool {
	switch opts.Policy {
	case PolicyAll:
		return len(report.ValidSigners) == len(report.Signers)
	case PolicyAny:
		return len(report.ValidSigners) > 0
	case PolicyAtLeastKDistinct:
		return len(report.DistinctValidIdentities) >= opts.K
	default:
		return false
	}
}

func (p7 *PKCS7) verifySignerReport(index int, signer signerInfo, chainOpts x509.VerifyOptions) SignerVerificationReport {
	report := SignerVerificationReport{
		Index:              index,
		DigestAlgorithm:    signer.DigestAlgorithm.Algorithm,
		SignatureAlgorithm: signer.DigestEncryptionAlgorithm.Algorithm,
		IssuerAndSerial:    signer.IssuerAndSerialNumber,
	}

	// Certificate identification: zero and multiple distinct candidates are
	// kept as separate, distinguishable failure modes.
	cert, certResult := matchSignerCertificate(p7.Certificates, signer.IssuerAndSerialNumber)
	report.CertificateMatch = certResult
	report.Certificate = cert
	if cert != nil {
		certSum := sha256.Sum256(cert.Raw)
		report.CertificateFingerprint = certSum[:]
		keySum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		report.PublicKeyFingerprint = keySum[:]
	}

	signedData := p7.Content
	signatureRecorded := false
	if len(signer.AuthenticatedAttributes) == 0 {
		report.ContentDigest = checkSkipped()
	} else {
		var digest []byte
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
			report.ContentDigest = checkFailed(err)
		} else if hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm); err != nil {
			report.ContentDigest = checkFailed(fmt.Errorf("%w: digest algorithm %s: %v",
				ErrUnsupportedAlgorithm, signer.DigestAlgorithm.Algorithm, err))
		} else {
			h := hash.New()
			h.Write(p7.Content)
			computed := h.Sum(nil)
			if subtle.ConstantTimeCompare(digest, computed) != 1 {
				report.ContentDigest = checkFailed(fmt.Errorf("%w: expected %X, computed %X",
					ErrDigestMismatch, digest, computed))
			} else {
				report.ContentDigest = checkPass()
			}
		}

		if signingTime, err := getSigningTimeAttribute(signer.AuthenticatedAttributes); err == nil {
			report.HasSigningTime = true
			report.SigningTime = signingTime
		}

		// With authenticated attributes the signature covers the DER-encoded
		// attribute SET rather than the encapsulated content.
		marshaled, err := marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			report.Signature = checkFailed(err)
			signatureRecorded = true
		} else {
			signedData = marshaled
		}
	}

	switch {
	case signatureRecorded:
		// Signature failure already recorded above.
	case cert == nil:
		report.Signature = checkSkipped()
	default:
		algorithm, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
		if err != nil {
			report.Signature = checkFailed(fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err))
		} else if err := cert.CheckSignature(algorithm, signedData, signer.EncryptedDigest); err != nil {
			report.Signature = checkFailed(fmt.Errorf("%w: %v", ErrInvalidSignature, err))
		} else {
			report.Signature = checkPass()
		}
	}

	switch {
	case cert == nil, chainOpts.Roots == nil:
		report.TrustChain = checkSkipped()
	default:
		if _, err := cert.Verify(chainOpts); err != nil {
			report.TrustChain = checkFailed(fmt.Errorf("pkcs7: failed to verify certificate chain: %w", err))
		} else {
			report.TrustChain = checkPass()
		}
	}

	report.Valid = true
	for _, result := range []CheckResult{
		report.CertificateMatch,
		report.ContentDigest,
		report.Signature,
		report.TrustChain,
	} {
		if result.Status == CheckFailed {
			report.Valid = false
			report.Err = result.Err
			return report
		}
	}
	return report
}

// matchSignerCertificate resolves the unique embedded certificate referenced
// by a SignerInfo. Byte-identical duplicates collapse to one candidate;
// distinct certificates sharing the issuer/serial are ambiguous.
func matchSignerCertificate(certs []*x509.Certificate, ias issuerAndSerial) (*x509.Certificate, CheckResult) {
	var unique []*x509.Certificate
	for _, cert := range certs {
		if !isCertMatchForIssuerAndSerial(cert, ias) {
			continue
		}
		duplicate := false
		for _, seen := range unique {
			if bytes.Equal(seen.Raw, cert.Raw) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, cert)
		}
	}
	switch len(unique) {
	case 0:
		return nil, checkFailed(fmt.Errorf("%w: serial %s", ErrCertificateNotFound, ias.SerialNumber))
	case 1:
		return unique[0], checkPass()
	default:
		return nil, checkFailed(fmt.Errorf("%w: %d distinct certificates share serial %s",
			ErrCertificateAmbiguous, len(unique), ias.SerialNumber))
	}
}

func getSigningTimeAttribute(attrs []attribute) (time.Time, error) {
	var signingTime time.Time
	err := unmarshalAttribute(attrs, OIDAttributeSigningTime, &signingTime)
	return signingTime, err
}
