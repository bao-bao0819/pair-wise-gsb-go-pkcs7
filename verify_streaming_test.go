package pkcs7

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestVerifyDetachedParity cross-checks streaming detached verification
// against in-memory verification across every supported signature mode.
func TestVerifyDetachedParity(t *testing.T) {
	content := bytes.Repeat([]byte("Detached CMS streaming parity. "), 500)
	chunks := []int{1, 2, 3, 7, 64, 4096}

	for _, tc := range detachedSignatureCases() {
		t.Run(tc.name, func(t *testing.T) {
			p7, trust := buildDetachedP7(t, tc, content)

			// Baseline: load the body into p7.Content and verify in memory.
			embedded := *p7
			embedded.Content = content
			if err := embedded.VerifyWithChain(trust); err != nil {
				t.Fatalf("in-memory verification failed: %v", err)
			}

			// Full-buffer reader.
			if err := p7.VerifyDetachedWithChain(trust, bytes.NewReader(content)); err != nil {
				t.Fatalf("full-reader verification failed: %v", err)
			}

			// Short readers that fragment the body and may return data with
			// io.EOF on the final read.
			for _, chunk := range chunks {
				cr := &chunkReader{data: content, maxChunk: chunk}
				if err := p7.VerifyDetachedWithChain(trust, cr); err != nil {
					t.Fatalf("chunk=%d verification failed: %v", chunk, err)
				}
				if cr.pos != len(content) {
					t.Fatalf("chunk=%d consumed %d of %d bytes", chunk, cr.pos, len(content))
				}
			}

			// Fixed-time variant exercises the AtTime path and skips
			// signing-time entirely.
			if err := p7.VerifyDetachedWithChainAtTime(trust, time.Now().UTC(), bytes.NewReader(content)); err != nil {
				t.Fatalf("AtTime verification failed: %v", err)
			}

			// Tampered body must be rejected, never reported as a success.
			bad := bytes.Clone(content)
			bad[len(bad)/2] ^= 0xFF
			if err := p7.VerifyDetachedWithChain(trust, bytes.NewReader(bad)); err == nil {
				t.Fatal("verification succeeded for tampered content")
			} else if tc.withAttrs && !errors.Is(err, &MessageDigestMismatchError{}) &&
				!strings.Contains(err.Error(), "Message digest mismatch") {
				t.Fatalf("expected digest mismatch for tampered attrs case, got: %v", err)
			}
		})
	}
}

// TestVerifyDetachedDoesNotMutateContent proves streaming verification leaves
// p7.Content alone and does not rely on any embedded content.
func TestVerifyDetachedDoesNotMutateContent(t *testing.T) {
	content := []byte("must remain detached")
	p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)

	if err := p7.VerifyDetachedWithChain(trust, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if len(p7.Content) != 0 {
		t.Fatalf("p7.Content mutated to %d bytes, want untouched empty", len(p7.Content))
	}

	// Even with junk embedded content, the reader is the source of truth.
	p7.Content = []byte("embedded junk that must be ignored")
	if err := p7.VerifyDetachedWithOpts(context.Background(), DetachedVerifyOptions{}, bytes.NewReader(content)); err != nil {
		t.Fatalf("embedded content should be ignored: %v", err)
	}
	if !bytes.Equal(p7.Content, []byte("embedded junk that must be ignored")) {
		t.Fatal("caller-provided p7.Content should not be modified")
	}

	// Repeated calls against independent readers all succeed.
	for i := 0; i < 3; i++ {
		if err := p7.VerifyDetachedWithChain(trust, bytes.NewReader(content)); err != nil {
			t.Fatalf("repeated verification %d failed: %v", i, err)
		}
	}
}

// TestVerifyDetachedMLDSA covers ML-DSA-44/65/87, which are pure algorithms
// and therefore require authenticated attributes for streaming verification.
func TestVerifyDetachedMLDSA(t *testing.T) {
	content := bytes.Repeat([]byte("ML-DSA detached streaming body. "), 100)

	for _, tc := range mlDSATestCases {
		t.Run(tc.name+"/attrs", func(t *testing.T) {
			cert, key := createMLDSATestCertificate(t, tc)
			signedData, err := NewSignedData(content)
			if err != nil {
				t.Fatal(err)
			}
			if err := signedData.AddSigner(cert, key, SignerInfoConfig{}); err != nil {
				t.Fatal(err)
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
			roots := x509.NewCertPool()
			roots.AddCert(cert)

			if err := p7.VerifyDetachedWithChain(roots, &chunkReader{data: content, maxChunk: 5}); err != nil {
				t.Fatalf("ML-DSA streaming verify: %v", err)
			}
		})

		t.Run(tc.name+"/noattrs-unsupported", func(t *testing.T) {
			cert, key := createMLDSATestCertificate(t, tc)
			signedData, err := NewSignedData(content)
			if err != nil {
				t.Fatal(err)
			}
			if err := signedData.SignWithoutAttr(cert, key, SignerInfoConfig{}); err != nil {
				t.Fatal(err)
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
			counter := &countingReader{r: bytes.NewReader(content)}
			err = p7.VerifyDetachedWithOpts(context.Background(), DetachedVerifyOptions{}, counter)
			if !errors.Is(err, ErrStreamingNotSupported) {
				t.Fatalf("err = %v, want ErrStreamingNotSupported", err)
			}
			if counter.calls != 0 {
				t.Fatalf("content read %d times before structure was rejected", counter.calls)
			}
		})
	}
}

// TestVerifyDetachedMultipleSignersSinglePass proves several signers are
// satisfied with one continuous scan and one hash per distinct algorithm.
func TestVerifyDetachedMultipleSignersSinglePass(t *testing.T) {
	content := bytes.Repeat([]byte("multi-signer body "), 300)
	p7, trust, wantHashes := buildMultiSignerDetachedP7(t, content)

	signers, hashes, err := prepareDetachedSigners(p7)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 3 {
		t.Fatalf("prepared %d signers, want 3", len(signers))
	}
	if len(hashes) != len(wantHashes) {
		t.Fatalf("distinct hashes = %d, want %d", len(hashes), len(wantHashes))
	}
	for hash := range wantHashes {
		if _, ok := hashes[hash]; !ok {
			t.Errorf("missing expected hash %v", hash)
		}
	}

	// bytes.Reader returns one (n,nil) read then one (0,EOF) read; a single
	// pass therefore drives exactly two Read calls regardless of signer count.
	reader := &countingReader{r: bytes.NewReader(content)}
	if err := p7.VerifyDetachedWithChain(trust, reader); err != nil {
		t.Fatalf("multi-signer streaming verify: %v", err)
	}
	if reader.calls != 2 {
		t.Fatalf("body scanned with %d Read calls, want 2 (one data pass + EOF)", reader.calls)
	}

	// In-memory verification of the same detached object must agree.
	p7.Content = content
	if err := p7.VerifyWithChain(trust); err != nil {
		t.Fatalf("in-memory multi-signer verify: %v", err)
	}
}

// TestVerifyDetachedDigestReuse verifies the dedup path directly: two signers
// on the same digest share one hash, a distinct digest adds exactly one more.
func TestVerifyDetachedDigestReuse(t *testing.T) {
	content := []byte("reuse")
	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	pair256, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	pair256Other, err := createTestCertificate(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	pair512, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []certKeyPair{pair256, pair256Other, pair512} {
		digestOID, err := GetDigestOIDForSignatureAlgorithm(pair.Certificate.SignatureAlgorithm)
		if err != nil {
			t.Fatal(err)
		}
		sd.SetDigestAlgorithm(digestOID)
		if err := sd.AddSigner(pair.Certificate, (*pair.PrivateKey).(crypto.Signer), SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	_, hashes, err := prepareDetachedSigners(p7)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Signers) != 3 {
		t.Fatalf("signer count = %d, want 3", len(p7.Signers))
	}
	if len(hashes) != 2 {
		t.Fatalf("distinct hashes = %d, want 2 (SHA-256 shared, SHA-512 once)", len(hashes))
	}
	if err := p7.VerifyDetachedWithChain(nil, bytes.NewReader(content)); err != nil {
		t.Fatalf("streaming verify: %v", err)
	}
}

// TestVerifyDetachedMaxSize covers the size limit, including when the
// overflow arrives in a final chunk that also returns data.
func TestVerifyDetachedMaxSize(t *testing.T) {
	content := []byte("0123456789")

	for _, limit := range []int64{0, int64(len(content))} {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		if err := p7.VerifyDetachedWithOpts(context.Background(),
			DetachedVerifyOptions{VerifyOptions: x509.VerifyOptions{Roots: trust}, MaxContentSize: limit},
			bytes.NewReader(content)); err != nil {
			t.Fatalf("limit=%d should accept %d bytes: %v", limit, len(content), err)
		}
	}

	for _, maxChunk := range []int{1, 3, len(content)} {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		// One byte too small, delivered through a short reader so the over-read
		// may coincide with the final chunk.
		rd := &chunkReader{data: content, maxChunk: maxChunk}
		err := p7.VerifyDetachedWithOpts(context.Background(),
			DetachedVerifyOptions{VerifyOptions: x509.VerifyOptions{Roots: trust}, MaxContentSize: int64(len(content) - 1)},
			rd)
		if !errors.Is(err, ErrContentTooLarge) {
			t.Fatalf("maxChunk=%d: err = %v, want ErrContentTooLarge", maxChunk, err)
		}
	}
}

// TestVerifyDetachedContextCanceled ensures cancellation is reported and no
// signature success is returned when the body cannot be completed.
func TestVerifyDetachedContextCanceled(t *testing.T) {
	content := []byte("cancellation body")
	p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)

	ctx, cancel := context.WithCancel(context.Background())
	block := &blockReader{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- p7.VerifyDetachedWithOpts(ctx, DetachedVerifyOptions{VerifyOptions: x509.VerifyOptions{Roots: trust}}, block)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	close(block.ready)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verification did not return after cancellation")
	}

	// A pre-cancelled context must fail before the reader is consumed.
	counter := &countingReader{r: bytes.NewReader(content)}
	cancelledCtx, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := p7.VerifyDetachedWithOpts(cancelledCtx,
		DetachedVerifyOptions{VerifyOptions: x509.VerifyOptions{Roots: trust}}, counter); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled err = %v, want context.Canceled", err)
	}
	if counter.calls != 0 {
		t.Fatalf("pre-cancelled context read content %d times", counter.calls)
	}
}

// TestVerifyDetachedReadErrors proves terminal (n>0, err) reads still process
// the final bytes but retain the read error, and that truncated/zero-error
// streams never yield a successful verification.
func TestVerifyDetachedReadErrors(t *testing.T) {
	content := []byte("tail-failure-and-truncation content here")
	sentinel := errors.New("synthetic terminal failure")

	t.Run("terminal-error-with-final-bytes", func(t *testing.T) {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		for _, chunk := range []int{1, 5, len(content)} {
			rd := &failingTailReader{data: content, maxChunk: chunk, err: sentinel}
			err := p7.VerifyDetachedWithChain(trust, rd)
			if !errors.Is(err, sentinel) {
				t.Fatalf("chunk=%d err = %v, want wrapped sentinel", chunk, err)
			}
		}
	})

	t.Run("truncated-body", func(t *testing.T) {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		for _, limit := range []int{0, 1, len(content) - 1} {
			rd := &truncatingReader{data: content, limit: limit}
			err := p7.VerifyDetachedWithChain(trust, rd)
			if err == nil {
				t.Fatalf("limit=%d verification unexpectedly succeeded", limit)
			}
			if errors.Is(err, ErrContentTooLarge) {
				t.Fatalf("limit=%d returned size-limit error for an incomplete read", limit)
			}
		}
	})

	t.Run("empty-body-without-eof", func(t *testing.T) {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		rd := &truncatingReader{data: content, limit: 0}
		if err := p7.VerifyDetachedWithChain(trust, rd); err == nil {
			t.Fatal("reader that never reaches EOF reported success")
		}
	})

	t.Run("zero-nil-read-tolerated", func(t *testing.T) {
		p7, trust := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		rd := &zeroThenBodyReader{data: content}
		if err := p7.VerifyDetachedWithChain(trust, rd); err != nil {
			t.Fatalf("legal (0,nil) read broke verification: %v", err)
		}
	})
}

// TestVerifyDetachedSignedAttributesAreTheSignatureInput proves the signature
// is checked over the authenticated attributes rather than the bare digest.
func TestVerifyDetachedSignedAttributesAreTheSignatureInput(t *testing.T) {
	content := []byte("signed attributes carry the signature")
	tc := detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}
	p7, trust := buildDetachedP7(t, tc, content)

	// Sanity: valid attributes verify.
	if err := p7.VerifyDetachedWithChain(trust, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}

	// Tamper with an authenticated attribute while leaving the embedded
	// message-digest attribute intact. If the implementation incorrectly
	// verified over the content digest, this could still pass; verifying over
	// the re-marshalled attributes must fail instead.
	corrupt := *p7
	corrupt.Signers = make([]signerInfo, len(p7.Signers))
	copy(corrupt.Signers, p7.Signers)
	attrs := corrupt.Signers[0].AuthenticatedAttributes
	flipped := make([]attribute, len(attrs))
	copy(flipped, attrs)
	for i, attr := range flipped {
		if attr.Type.Equal(OIDAttributeSigningTime) {
			// Replace the value with a freshly encoded, different signing
			// time. Content-type and message-digest attributes stay intact,
			// so only the signature over the authenticated attributes can
			// detect the change.
			encoded, err := asn1.Marshal(time.Now().Add(24 * time.Hour).UTC())
			if err != nil {
				t.Fatal(err)
			}
			flipped[i] = attribute{
				Type:  OIDAttributeSigningTime,
				Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: encoded},
			}
			break
		}
	}
	corrupt.Signers[0].AuthenticatedAttributes = flipped

	err := corrupt.VerifyDetachedWithChain(trust, bytes.NewReader(content))
	if err == nil {
		t.Fatal("verification succeeded after authenticated attributes were corrupted")
	}
}

// TestVerifyDetachedStructureCheckedBeforeRead ensures malformed structure
// (no signers, missing certificate, unsupported algorithm) fails before a
// single content byte is read.
func TestVerifyDetachedStructureCheckedBeforeRead(t *testing.T) {
	content := []byte("structure first")

	t.Run("no-signers", func(t *testing.T) {
		p7, _ := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}, content)
		p7.Signers = nil
		counter := &countingReader{r: bytes.NewReader(content)}
		if err := p7.VerifyDetachedWithChain(nil, counter); err == nil {
			t.Fatal("expected error for CMS without signers")
		}
		if counter.calls != 0 {
			t.Fatalf("content read %d times before no-signers rejection", counter.calls)
		}
	})

	t.Run("missing-certificate", func(t *testing.T) {
		p7, _ := buildDetachedP7(t, detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true, skipChain: true}, content)
		p7.Certificates = nil
		counter := &countingReader{r: bytes.NewReader(content)}
		if err := p7.VerifyDetachedWithChain(nil, counter); err == nil {
			t.Fatal("expected error for signer without certificate")
		}
		if counter.calls != 0 {
			t.Fatalf("content read %d times before missing-cert rejection", counter.calls)
		}
	})

	t.Run("dsa-unsupported", func(t *testing.T) {
		fixture := UnmarshalDSATestFixture(EC2IdentityDocumentFixture)
		p7, err := Parse(fixture.Input)
		if err != nil {
			t.Fatal(err)
		}
		p7.Certificates = []*x509.Certificate{fixture.Certificate}
		dsaContent := p7.Content
		if len(dsaContent) == 0 {
			t.Fatal("fixture expected to carry embedded content for reference")
		}
		p7.Content = nil
		counter := &countingReader{r: bytes.NewReader(dsaContent)}
		err = p7.VerifyDetachedWithChain(nil, counter)
		if err == nil || !strings.Contains(err.Error(), "DSA signature verification is not supported") {
			t.Fatalf("err = %v, want DSA unsupported", err)
		}
		if counter.calls != 0 {
			t.Fatalf("DSA content read %d times before rejection", counter.calls)
		}
	})
}

// TestVerifyDetachedAtTimeWindow exercises the fixed-time verification path.
func TestVerifyDetachedAtTimeWindow(t *testing.T) {
	content := []byte("fixed verification time")
	tc := detachedCase{name: "RSA-SHA256/attrs", sigAlg: x509.SHA256WithRSA, withAttrs: true}
	p7, trust := buildDetachedP7(t, tc, content)

	if err := p7.VerifyDetachedWithChainAtTime(trust, time.Now().UTC(), bytes.NewReader(content)); err != nil {
		t.Fatalf("current time verify: %v", err)
	}

	// A time before the certificate was issued must fail the chain check.
	before := time.Now().AddDate(-10, 0, 0)
	if err := p7.VerifyDetachedWithChainAtTime(trust, before, bytes.NewReader(content)); err == nil {
		t.Fatal("verification at a time before certificate validity succeeded")
	}
}
