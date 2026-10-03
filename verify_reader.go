package pkcs7

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
)

// ErrDetachedContentTooLarge is returned by VerifyDetachedReader when the
// detached content read from the reader exceeds the caller-provided limit.
var ErrDetachedContentTooLarge = errors.New("pkcs7: detached content exceeds the maximum allowed length")

// ErrDetachedUnsignedAttributes is returned by VerifyDetachedReader when a
// signer carries no signed (authenticated) attributes. Streaming
// verification requires the message-digest signed attribute; signatures
// over the raw content (e.g. created by SignWithoutAttr) are not supported.
var ErrDetachedUnsignedAttributes = errors.New("pkcs7: streaming verification of detached content requires signed attributes")

// detachedSigner holds the per-signer state needed to verify a detached
// signature after the content has been streamed.
type detachedSigner struct {
	signer     signerInfo
	ee         *x509.Certificate
	sigAlg     x509.SignatureAlgorithm
	signedData []byte
	digest     []byte
	hash       crypto.Hash
}

// VerifyDetachedReader verifies the signatures of a detached CMS SignedData
// against content streamed from r, so large payloads never need to be held
// in PKCS7.Content. Like Verify, it does not perform certificate chain
// verification.
//
// The signature structure is fully validated before any content is read:
// every signer must have a matching certificate, carry signed
// (authenticated) attributes containing a message-digest attribute, and use
// digest and signature algorithms among the ones the library supports for
// in-memory verification: RSA with SHA-1/256/384/512, ECDSA with
// SHA-1/256/384/512 (including the legacy id-ecPublicKey and named-curve
// SignerInfo forms), Ed25519, and ML-DSA-44/65/87. Signers without signed
// attributes and DSA signers are rejected with ErrDetachedUnsignedAttributes
// or the corresponding algorithm error, because their signature input is
// the raw content rather than the DER-encoded signed attributes.
//
// The content is read exactly once: signers sharing a digest algorithm
// accumulate into a single running hash. After the read completes, each
// signer's message-digest attribute is compared against the computed digest
// and the signature is checked over the original signed attributes, exactly
// as in-memory verification does.
//
// maxBytes caps the number of content bytes accepted; a negative value
// disables the limit. Exceeding the limit returns
// ErrDetachedContentTooLarge. Context cancellation aborts the read and
// returns the context error. If the reader returns n > 0 bytes together
// with an error, the final bytes are processed and the read error is still
// returned: verification never reports success unless the content was read
// all the way to io.EOF. p7.Content is never modified.
func (p7 *PKCS7) VerifyDetachedReader(ctx context.Context, r io.Reader, maxBytes int64) error {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}

	// Validate the whole signature structure before touching the content.
	signers := make([]detachedSigner, len(p7.Signers))
	hashers := make(map[crypto.Hash]hash.Hash)
	for i, signer := range p7.Signers {
		ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
		if ee == nil {
			return errors.New("pkcs7: No certificate for signer")
		}
		if len(signer.AuthenticatedAttributes) == 0 {
			return ErrDetachedUnsignedAttributes
		}
		var digest []byte
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
			return err
		}
		hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return err
		}
		if !hash.Available() {
			return fmt.Errorf("pkcs7: hash function %v is not linked into the binary", hash)
		}
		sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
		if err != nil {
			return err
		}
		signedData, err := marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		signers[i] = detachedSigner{
			signer:     signer,
			ee:         ee,
			sigAlg:     sigalg,
			signedData: signedData,
			digest:     digest,
			hash:       hash,
		}
		if _, ok := hashers[hash]; !ok {
			hashers[hash] = hash.New()
		}
	}

	writers := make([]io.Writer, 0, len(hashers))
	for _, h := range hashers {
		writers = append(writers, h)
	}
	w := io.MultiWriter(writers...)

	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("pkcs7: reading detached content: %w", err)
		}
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if maxBytes >= 0 && total > maxBytes {
				return ErrDetachedContentTooLarge
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return fmt.Errorf("pkcs7: hashing detached content: %w", werr)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("pkcs7: reading detached content: %w", err)
		}
	}

	for _, s := range signers {
		computed := hashers[s.hash].Sum(nil)
		if subtle.ConstantTimeCompare(s.digest, computed) != 1 {
			return &MessageDigestMismatchError{
				ExpectedDigest: s.digest,
				ActualDigest:   computed,
			}
		}
		if err := s.ee.CheckSignature(s.sigAlg, s.signedData, s.signer.EncryptedDigest); err != nil {
			return err
		}
	}
	return nil
}
