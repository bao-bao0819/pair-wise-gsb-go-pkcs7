package pkcs7

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// IdentityKind selects how the identity of a signer is derived from its
// certificate when de-duplicating signers for threshold policies.
type IdentityKind int

const (
	// IdentityByCertificateFingerprint identifies a signer by the SHA-256
	// fingerprint of the whole signer certificate.
	IdentityByCertificateFingerprint IdentityKind = iota
	// IdentityByPublicKeyFingerprint identifies a signer by the SHA-256
	// fingerprint of the certificate's subject public key info, so that
	// re-issued certificates for the same key count as one identity.
	IdentityByPublicKeyFingerprint
)

// VerifyMode enumerates the overall acceptance policies that can be applied
// to the per-signer results of a detailed verification.
type VerifyMode int

const (
	// RequireAll accepts only when every SignerInfo verifies.
	RequireAll VerifyMode = iota
	// RequireAny accepts when at least one SignerInfo verifies.
	RequireAny
	// RequireAtLeastK accepts when at least Threshold distinct identities
	// verify. Identities are de-duplicated according to
	// VerifyPolicy.Identity, so the same signer cannot satisfy the
	// threshold by attaching multiple SignerInfos.
	RequireAtLeastK
)

// VerifyPolicy describes how the per-signer verification results are
// combined into an overall accept/reject decision.
type VerifyPolicy struct {
	Mode VerifyMode
	// Threshold is the number of distinct identities required by
	// RequireAtLeastK. It is ignored by the other modes.
	Threshold int
	// Identity selects the fingerprint used to de-duplicate signers.
	Identity IdentityKind
}

// Errors reported in SignerVerification.CertificateErr. They are wrapped so
// that callers can distinguish a missing signer certificate from an
// ambiguous issuer/serial lookup with errors.Is.
var (
	ErrSignerCertificateNotFound  = errors.New("pkcs7: no certificate for signer")
	ErrSignerCertificateAmbiguous = errors.New("pkcs7: multiple certificates match signer issuer and serial number")
)

// SignerVerification reports the verification evidence collected for a
// single SignerInfo. Each check is recorded independently so that one
// failure does not hide the outcome of the other checks.
type SignerVerification struct {
	// Index is the position of the SignerInfo in PKCS7.Signers.
	Index int
	// Certificate is the certificate matched by issuer and serial number,
	// or nil when the lookup failed.
	Certificate *x509.Certificate
	// Identity is the signer fingerprint derived according to
	// VerifyPolicy.Identity. It is nil when no certificate was matched.
	Identity []byte
	// SigningTime is the signing-time signed attribute when present. It is
	// only a claim carried by the signature and is never used in place of
	// the caller supplied verification time.
	SigningTime *time.Time
	// CertificateErr reports a missing or ambiguous signer certificate.
	CertificateErr error
	// DigestErr reports a content message-digest mismatch.
	DigestErr error
	// AlgorithmErr reports an unsupported digest or signature algorithm.
	AlgorithmErr error
	// SignatureErr reports a signature that does not verify.
	SignatureErr error
	// ChainErr reports a trust chain failure. It is only set when a root
	// pool was supplied in the verify options.
	ChainErr error
}

// OK reports whether every check performed for this signer succeeded.
func (s *SignerVerification) OK() bool {
	return s.CertificateErr == nil && s.DigestErr == nil && s.AlgorithmErr == nil &&
		s.SignatureErr == nil && s.ChainErr == nil
}

// DetailedVerification is the result of VerifyDetailed: one report per
// SignerInfo plus the policy evaluation.
type DetailedVerification struct {
	// Signers holds one report per SignerInfo, in order.
	Signers []SignerVerification
	// ValidSignatures counts the signers for which every check passed.
	ValidSignatures int
	// DistinctIdentities counts the de-duplicated identities among the
	// fully valid signers.
	DistinctIdentities int
	// Accepted is the overall decision for the policy passed to
	// VerifyDetailed.
	Accepted bool
}

// Accept evaluates a policy against the collected per-signer results.
func (d *DetailedVerification) Accept(policy VerifyPolicy) bool {
	switch policy.Mode {
	case RequireAll:
		return d.ValidSignatures == len(d.Signers)
	case RequireAny:
		return d.ValidSignatures > 0
	case RequireAtLeastK:
		return d.DistinctIdentities >= policy.Threshold
	}
	return false
}

// VerifyDetailed verifies every SignerInfo independently and reports the
// per-signer evidence instead of stopping at the first error.
//
// For each signer it records the content digest check, the signature check,
// the signer certificate lookup and, when opts.Roots is not nil, the trust
// chain validation. The verification time comes from opts.CurrentTime (the
// zero value means now, as in crypto/x509); a signing-time signed attribute
// is only reported as a claim and never replaces the caller's trust policy.
//
// The overall acceptance is decided by policy: RequireAll, RequireAny, or
// RequireAtLeastK with identities de-duplicated by the fingerprint kind
// selected in policy.Identity.
func (p7 *PKCS7) VerifyDetailed(opts x509.VerifyOptions, policy VerifyPolicy) (*DetailedVerification, error) {
	if len(p7.Signers) == 0 {
		return nil, errors.New("pkcs7: Message has no signers")
	}
	if policy.Mode == RequireAtLeastK && policy.Threshold < 1 {
		return nil, fmt.Errorf("pkcs7: invalid threshold %d for RequireAtLeastK policy", policy.Threshold)
	}
	if policy.Mode != RequireAll && policy.Mode != RequireAny && policy.Mode != RequireAtLeastK {
		return nil, fmt.Errorf("pkcs7: unknown verification policy mode %d", policy.Mode)
	}
	if opts.KeyUsages == nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if opts.Roots != nil && opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range p7.Certificates {
			opts.Intermediates.AddCert(cert)
		}
	}
	result := &DetailedVerification{}
	identities := make(map[string]struct{})
	for i := range p7.Signers {
		report := p7.verifySignerDetailed(&p7.Signers[i], i, opts, policy.Identity)
		if report.OK() {
			result.ValidSignatures++
			identities[string(report.Identity)] = struct{}{}
		}
		result.Signers = append(result.Signers, report)
	}
	result.DistinctIdentities = len(identities)
	result.Accepted = result.Accept(policy)
	return result, nil
}

func (p7 *PKCS7) verifySignerDetailed(signer *signerInfo, index int, opts x509.VerifyOptions, identity IdentityKind) SignerVerification {
	report := SignerVerification{Index: index}

	ee, err := findSignerCertificate(p7.Certificates, signer.IssuerAndSerialNumber)
	if err != nil {
		report.CertificateErr = err
	} else {
		report.Certificate = ee
		report.Identity = signerIdentity(ee, identity)
	}

	signedData := p7.Content
	if len(signer.AuthenticatedAttributes) > 0 {
		var digest []byte
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
			report.DigestErr = err
		} else if hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm); err != nil {
			report.AlgorithmErr = err
		} else {
			h := hash.New()
			h.Write(p7.Content)
			computed := h.Sum(nil)
			if subtle.ConstantTimeCompare(digest, computed) != 1 {
				report.DigestErr = &MessageDigestMismatchError{
					ExpectedDigest: digest,
					ActualDigest:   computed,
				}
			}
		}
		marshaled, err := marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			report.DigestErr = err
		} else {
			signedData = marshaled
		}
		var signingTime time.Time
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime); err == nil {
			claim := signingTime
			report.SigningTime = &claim
		}
	}

	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		if report.AlgorithmErr == nil {
			report.AlgorithmErr = err
		}
	} else if ee != nil {
		if err := ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest); err != nil {
			report.SignatureErr = err
		}
	}

	if ee != nil && opts.Roots != nil {
		if _, err := ee.Verify(opts); err != nil {
			report.ChainErr = fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
		}
	}

	return report
}

// findSignerCertificate returns the unique certificate matching the signer
// issuer and serial number, or a distinct error when there is no candidate
// or more than one.
func findSignerCertificate(certs []*x509.Certificate, ias issuerAndSerial) (*x509.Certificate, error) {
	var match *x509.Certificate
	count := 0
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			if match == nil {
				match = cert
			}
			count++
		}
	}
	switch count {
	case 0:
		return nil, ErrSignerCertificateNotFound
	case 1:
		return match, nil
	default:
		return nil, fmt.Errorf("%w: %d candidates", ErrSignerCertificateAmbiguous, count)
	}
}

func signerIdentity(cert *x509.Certificate, kind IdentityKind) []byte {
	var sum [sha256.Size]byte
	if kind == IdentityByPublicKeyFingerprint {
		sum = sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	} else {
		sum = sha256.Sum256(cert.Raw)
	}
	identity := make([]byte, len(sum))
	copy(identity, sum[:])
	return identity
}
