package pkcs7

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"testing"
)

// --- test readers -----------------------------------------------------------

// chunkReader returns at most maxChunk bytes per Read, exercising the
// streaming loop with arbitrarily small reads.
type chunkReader struct {
	data      []byte
	pos       int
	maxChunk  int
	readCount int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	r.readCount++
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := min(len(p), r.maxChunk, len(r.data)-r.pos)
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// countingReader counts Read calls: a single multi-signer verification must
// issue one continuous pass over the body, not one pass per signer.
type countingReader struct {
	r     io.Reader
	calls int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	return r.r.Read(p)
}

// failingTailReader hands out every byte of the body but returns a non-EOF
// error together with the final bytes, modelling a reader that reports
// n > 0 and err simultaneously.
type failingTailReader struct {
	data     []byte
	pos      int
	maxChunk int
	err      error
}

func (r *failingTailReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := min(len(p), r.maxChunk, len(r.data)-r.pos)
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

// truncatingReader stops after limit bytes and returns an error instead of
// io.EOF, simulating an incomplete body.
type truncatingReader struct {
	data  []byte
	pos   int
	limit int
}

func (r *truncatingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) || r.pos >= r.limit {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(p), len(r.data)-r.pos, r.limit-r.pos)
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

// blockReader blocks until its channel is closed, then reports the context
// cancellation error. Used to prove cancellation is honored mid-read.
type blockReader struct {
	ready chan struct{}
}

func (r *blockReader) Read(p []byte) (int, error) {
	<-r.ready
	return 0, context.Canceled
}

// zeroThenBodyReader first returns a legal (0, nil) read, then serves the
// body, to verify the loop tolerates zero-length reads.
type zeroThenBodyReader struct {
	data   []byte
	zeroed bool
}

func (r *zeroThenBodyReader) Read(p []byte) (int, error) {
	if !r.zeroed {
		r.zeroed = true
		return 0, nil
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// --- builders --------------------------------------------------------------

type detachedCase struct {
	name       string
	sigAlg     x509.SignatureAlgorithm
	withAttrs  bool
	extraAttrs []Attribute
	skipChain  bool
}

func detachedSignatureCases() []detachedCase {
	return []detachedCase{
		{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true},
		{name: "RSA-SHA512/noattrs", sigAlg: x509.SHA512WithRSA, withAttrs: false},
		{name: "ECDSA-SHA256/attrs", sigAlg: x509.ECDSAWithSHA256, withAttrs: true},
		{name: "ECDSA-SHA384/noattrs", sigAlg: x509.ECDSAWithSHA384, withAttrs: false},
		{name: "ECDSA-SHA512/attrs", sigAlg: x509.ECDSAWithSHA512, withAttrs: true},
		{name: "Ed25519/attrs", sigAlg: x509.PureEd25519, withAttrs: true},
		{name: "RSA-SHA256/attrs/custom-attr", sigAlg: x509.SHA256WithRSA, withAttrs: true,
			extraAttrs: []Attribute{{Type: asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}, Value: "detached-stream"}}},
		{name: "RSA-SHA256/noattrs", sigAlg: x509.SHA256WithRSA, withAttrs: false},
	}
}

// buildDetachedP7 creates a detached CMS over content for the given case.
func buildDetachedP7(t *testing.T, tc detachedCase, content []byte) (*PKCS7, *x509.CertPool) {
	t.Helper()
	pair, err := createTestCertificate(tc.sigAlg)
	if err != nil {
		t.Fatalf("create %s certificate: %v", tc.name, err)
	}
	digestOID, err := GetDigestOIDForSignatureAlgorithm(tc.sigAlg)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(digestOID)
	key := (*pair.PrivateKey).(crypto.Signer)
	if tc.withAttrs {
		if err := signedData.AddSigner(pair.Certificate, key, SignerInfoConfig{ExtraSignedAttributes: tc.extraAttrs}); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := signedData.SignWithoutAttr(pair.Certificate, key, SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	signedData.Detach()
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Content) != 0 {
		t.Fatalf("detached CMS unexpectedly contains %d content bytes", len(p7.Content))
	}
	var trust *x509.CertPool
	if !tc.skipChain {
		trust = x509.NewCertPool()
		trust.AddCert(pair.Certificate)
	}
	return p7, trust
}

// buildMultiSignerDetachedP7 builds one detached CMS carrying three signers
// that use only two distinct digest algorithms (SHA-256 twice, SHA-512 once),
// so a single body pass must feed exactly two hashes.
func buildMultiSignerDetachedP7(t *testing.T, content []byte) (*PKCS7, *x509.CertPool, map[crypto.Hash]struct{}) {
	t.Helper()
	sigAlgs := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.ECDSAWithSHA512,
		x509.ECDSAWithSHA256,
	}

	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	wantHashes := map[crypto.Hash]struct{}{}
	for _, sigAlg := range sigAlgs {
		pair, err := createTestCertificate(sigAlg)
		if err != nil {
			t.Fatal(err)
		}
		digestOID, err := GetDigestOIDForSignatureAlgorithm(sigAlg)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := getHashForOID(digestOID)
		if err != nil {
			t.Fatal(err)
		}
		wantHashes[hash] = struct{}{}
		trust.AddCert(pair.Certificate)
		signedData.SetDigestAlgorithm(digestOID)
		key := (*pair.PrivateKey).(crypto.Signer)
		if err := signedData.AddSigner(pair.Certificate, key, SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	signedData.Detach()
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p7.Signers); got != 3 {
		t.Fatalf("signer count = %d, want 3", got)
	}
	return p7, trust, wantHashes
}
