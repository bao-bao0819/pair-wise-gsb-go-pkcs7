package pkcs7

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"
)

// DetachedVerifyOptions controls detached signature verification performed
// directly from an io.Reader. VerifyOptions carries the standard x509 chain
// verification parameters, while MaxContentSize bounds the number of content
// bytes that are hashed.
type DetachedVerifyOptions struct {
	x509.VerifyOptions

	// MaxContentSize limits the number of bytes read from the content reader.
	// Zero means no limit. If the content is longer than the limit, verification
	// fails with ErrContentTooLarge.
	MaxContentSize int64
}

var (
	// ErrContentTooLarge is returned when the detached content read for
	// verification exceeds DetachedVerifyOptions.MaxContentSize.
	ErrContentTooLarge = errors.New("pkcs7: detached content exceeds maximum allowed size")

	// ErrStreamingNotSupported is returned when a SignerInfo cannot be verified
	// without buffering the full content.
	ErrStreamingNotSupported = errors.New("pkcs7: streaming verification not supported for this SignerInfo")
)

// VerifyDetachedWithChain verifies a detached signature using the content read
// from content. The signature structure is validated before any content is
// read, and the content is scanned exactly once regardless of how many
// signers it has.
//
// If truststore is not nil, the signer certificate chain is verified against
// it at the signing-time authenticated attribute, or at the current time when
// the attribute is absent.
//
// The PKCS7 object is not modified; in particular p7.Content is left
// untouched, so embedded content (if any) is never used and subsequent calls
// are unaffected.
func (p7 *PKCS7) VerifyDetachedWithChain(truststore *x509.CertPool, content io.Reader) error {
	opts := DetachedVerifyOptions{}
	opts.Roots = truststore
	return p7.verifyDetached(context.Background(), opts, content, time.Time{})
}

// VerifyDetachedWithChainAtTime is like VerifyDetachedWithChain but verifies
// certificate validity at currentTime and never uses the signing-time
// authenticated attribute.
func (p7 *PKCS7) VerifyDetachedWithChainAtTime(truststore *x509.CertPool, currentTime time.Time, content io.Reader) error {
	opts := DetachedVerifyOptions{}
	opts.Roots = truststore
	return p7.verifyDetached(context.Background(), opts, content, currentTime)
}

// VerifyDetachedWithOpts verifies a detached signature using the content read
// from content and the supplied options. The signature structure is validated
// before any content is read, and the content is scanned exactly once.
//
// The following signature modes are supported:
//
//   - SignerInfos with authenticated (signed) attributes, where the signature
//     is verified over the DER-encoded authenticated attributes (never over the
//     bare content digest). This covers RSA (PKCS#1 v1.5, SHA-1/256/384/512),
//     ECDSA (SHA-1/256/384/512), Ed25519, and ML-DSA-44/65/87 signers.
//   - SignerInfos without authenticated attributes for pre-hashed algorithms,
//     where the content digest is passed directly to the key verification
//     primitive. This covers RSA (PKCS#1 v1.5, SHA-1/256/384/512) and ECDSA
//     (SHA-1/256/384/512).
//
// SignerInfos without authenticated attributes for pure algorithms (Ed25519
// and ML-DSA) cannot be verified without buffering the entire content, so
// they fail with ErrStreamingNotSupported, as does DSA which this library
// cannot verify at all.
//
// The PKCS7 object is not modified; in particular p7.Content is left
// untouched, so embedded content (if any) is never used and subsequent calls
// are unaffected.
func (p7 *PKCS7) VerifyDetachedWithOpts(ctx context.Context, opts DetachedVerifyOptions, content io.Reader) error {
	return p7.verifyDetached(ctx, opts, content, time.Time{})
}

func (p7 *PKCS7) verifyDetached(ctx context.Context, opts DetachedVerifyOptions, content io.Reader, currentTime time.Time) error {
	if opts.KeyUsages == nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if opts.Intermediates == nil {
		opts.Intermediates = intermediatesFromCerts(p7.Certificates)
	}

	signers, hashes, err := prepareDetachedSigners(p7)
	if err != nil {
		return err
	}

	digests, err := hashDetachedContent(ctx, content, hashes, opts.MaxContentSize)
	if err != nil {
		return err
	}

	for _, prepared := range signers {
		if err := verifyDetachedSigner(prepared, digests, opts, currentTime); err != nil {
			return err
		}
	}
	return nil
}

func intermediatesFromCerts(certs []*x509.Certificate) *x509.CertPool {
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		intermediates.AddCert(cert)
	}
	return intermediates
}

type preparedDetachedSigner struct {
	signerInfo     signerInfo
	cert           *x509.Certificate
	hash           crypto.Hash
	signatureAlg   x509.SignatureAlgorithm
	hasAttributes  bool
	expectedDigest []byte
	signedData     []byte
	signingTime    time.Time
	hasSigningTime bool
}

// prepareDetachedSigners validates the SignerInfo structure and certificate
// availability before the content reader is touched. It returns one prepared
// signer per SignerInfo and the set of distinct content hashes required.
func prepareDetachedSigners(p7 *PKCS7) ([]preparedDetachedSigner, map[crypto.Hash]struct{}, error) {
	if len(p7.Signers) == 0 {
		return nil, nil, errors.New("pkcs7: Message has no signers")
	}
	signers := make([]preparedDetachedSigner, 0, len(p7.Signers))
	hashes := make(map[crypto.Hash]struct{})
	for _, signer := range p7.Signers {
		ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
		if ee == nil {
			return nil, nil, errors.New("pkcs7: No certificate for signer")
		}
		hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return nil, nil, err
		}
		signatureAlg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
		if err != nil {
			return nil, nil, err
		}

		prepared := preparedDetachedSigner{
			signerInfo:   signer,
			cert:         ee,
			hash:         hash,
			signatureAlg: signatureAlg,
		}
		if len(signer.AuthenticatedAttributes) > 0 {
			var digest []byte
			if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
				return nil, nil, err
			}
			signedData, err := marshalAttributes(signer.AuthenticatedAttributes)
			if err != nil {
				return nil, nil, err
			}
			var signingTime time.Time
			if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime); err == nil {
				prepared.hasSigningTime = true
				prepared.signingTime = signingTime
			}
			prepared.hasAttributes = true
			prepared.expectedDigest = digest
			prepared.signedData = signedData
		} else if isPureSignatureAlgorithm(signatureAlg) {
			return nil, nil, fmt.Errorf("%w: %s requires authenticated attributes",
				ErrStreamingNotSupported, signatureAlg)
		}
		hashes[hash] = struct{}{}
		signers = append(signers, prepared)
	}
	return signers, hashes, nil
}

// hashDetachedContent reads content a single time and updates one hash per
// distinct algorithm, so multiple signers sharing a digest algorithm reuse a
// single accumulation. A read that returns n > 0 together with an error still
// hashes the returned bytes before the read error is surfaced.
func hashDetachedContent(ctx context.Context, content io.Reader, hashes map[crypto.Hash]struct{}, maxSize int64) (map[crypto.Hash][]byte, error) {
	hashers := make(map[crypto.Hash]hashWriter, len(hashes))
	for hash := range hashes {
		if !hash.Available() {
			return nil, fmt.Errorf("pkcs7: requested hash function #%d is not available", hash)
		}
		hashers[hash] = hashWriter{h: hash.New()}
	}

	buf := make([]byte, 32*1024)
	var total int64
readLoop:
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("pkcs7: detached content verification canceled: %w", err)
		}
		n, readErr := content.Read(buf)
		if n > 0 {
			total += int64(n)
			if maxSize > 0 && total > maxSize {
				return nil, ErrContentTooLarge
			}
			for hash := range hashers {
				if _, err := hashers[hash].h.Write(buf[:n]); err != nil {
					return nil, err
				}
			}
		}
		switch {
		case readErr == io.EOF:
			break readLoop
		case readErr != nil:
			// Preserve the reader error (including a terminal failure that
			// accompanies the final bytes); the bytes above were hashed.
			return nil, fmt.Errorf("pkcs7: failed to read detached content: %w", readErr)
		case n == 0:
			// A zero read with a nil error is permitted by the io.Reader
			// contract and simply means nothing happened.
			continue
		}
	}

	digests := make(map[crypto.Hash][]byte, len(hashers))
	for hash, hasher := range hashers {
		digests[hash] = hasher.h.Sum(nil)
	}
	return digests, nil
}

type hashWriter struct {
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
}

func verifyDetachedSigner(prepared preparedDetachedSigner, digests map[crypto.Hash][]byte, opts DetachedVerifyOptions, currentTime time.Time) error {
	signer := prepared.signerInfo
	ee := prepared.cert
	computed := digests[prepared.hash]

	var signedData []byte
	if prepared.hasAttributes {
		if subtle.ConstantTimeCompare(prepared.expectedDigest, computed) != 1 {
			return &MessageDigestMismatchError{
				ExpectedDigest: prepared.expectedDigest,
				ActualDigest:   computed,
			}
		}
		signedData = prepared.signedData

		// Mirror the in-memory verifier: the signing-time window is only
		// enforced when the caller did not request a fixed verification time.
		if currentTime.IsZero() && prepared.hasSigningTime {
			signingTime := prepared.signingTime
			if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
				return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
					signingTime.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339),
					ee.NotAfter.Format(time.RFC3339))
			}
		}
	}

	signingTime := time.Now().UTC()
	if !currentTime.IsZero() {
		signingTime = currentTime
	} else if prepared.hasAttributes && prepared.hasSigningTime {
		signingTime = prepared.signingTime
	}
	if opts.Roots != nil {
		chainOpts := opts.VerifyOptions
		chainOpts.CurrentTime = signingTime
		if _, err := ee.Verify(chainOpts); err != nil {
			return fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
		}
	}

	if prepared.hasAttributes {
		return ee.CheckSignature(prepared.signatureAlg, signedData, signer.EncryptedDigest)
	}
	return verifyPrehashedSignature(ee, prepared.signatureAlg, computed, signer.EncryptedDigest)
}

// isPureSignatureAlgorithm reports whether the signature algorithm signs the
// full message rather than a pre-computed digest, so it cannot be verified
// from the streamed content digest when no authenticated attributes are
// present.
func isPureSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.PureEd25519, x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return true
	}
	return false
}

// verifyPrehashedSignature checks a signature directly over the content
// digest, the exact operation performed by certificate.CheckSignature for
// SignerInfos that have no authenticated attributes.
func verifyPrehashedSignature(cert *x509.Certificate, alg x509.SignatureAlgorithm, digest, signature []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		hash, ok := hashForSignatureAlgorithm(alg)
		if !ok {
			return fmt.Errorf("%w: %s for RSA", ErrStreamingNotSupported, alg)
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, signature)
	case *ecdsa.PublicKey:
		if _, ok := hashForSignatureAlgorithm(alg); !ok {
			return fmt.Errorf("%w: %s for ECDSA", ErrStreamingNotSupported, alg)
		}
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return errors.New("pkcs7: invalid ECDSA signature")
		}
		return nil
	default:
		return fmt.Errorf("%w: %s key type %T", ErrStreamingNotSupported, alg, cert.PublicKey)
	}
}

func hashForSignatureAlgorithm(alg x509.SignatureAlgorithm) (crypto.Hash, bool) {
	switch alg {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return crypto.SHA1, true
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return crypto.SHA256, true
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return crypto.SHA384, true
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return crypto.SHA512, true
	}
	return crypto.Hash(0), false
}
