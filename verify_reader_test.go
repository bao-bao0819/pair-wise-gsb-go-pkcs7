package pkcs7

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// chunkedReader returns at most chunkSize bytes per Read.
type chunkedReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(r.chunkSize, len(r.data), len(p))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// tailErrorReader delivers all of its data, returning the final chunk
// together with a non-EOF error.
type tailErrorReader struct {
	data []byte
	err  error
}

func (r *tailErrorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

// countingReader counts the bytes and Read calls passing through it.
type countingReader struct {
	r     io.Reader
	bytes int64
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.bytes += int64(n)
	r.reads++
	return n, err
}

type detachedSignerSpec struct {
	sigAlg    x509.SignatureAlgorithm
	digestOID asn1.ObjectIdentifier
}

// createDetachedSignature signs content with one signer per spec, detaches
// the content, and returns the parsed PKCS7 together with a reference
// in-memory copy whose Content is populated for Verify().
func createDetachedSignature(t *testing.T, content []byte, specs ...detachedSignerSpec) (detached *PKCS7, inMemory *PKCS7) {
	t.Helper()
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		pair, err := createTestCertificate(spec.sigAlg)
		if err != nil {
			t.Fatal(err)
		}
		signedData.SetDigestAlgorithm(spec.digestOID)
		if err := signedData.AddSigner(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	signedData.Detach()
	der, err := signedData.Finish()
	if err != nil {
		t.Fatal(err)
	}
	detached, err = Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	inMemory, err = Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	inMemory.Content = content
	return detached, inMemory
}

func TestVerifyDetachedReader(t *testing.T) {
	content := []byte(strings.Repeat("We the People ", 500))
	detached, inMemory := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
	)

	if err := inMemory.Verify(); err != nil {
		t.Fatalf("in-memory Verify failed: %v", err)
	}

	for _, chunkSize := range []int{1, 7, 4096, len(content)} {
		t.Run(fmt.Sprintf("chunk size %d", chunkSize), func(t *testing.T) {
			reader := &chunkedReader{data: content, chunkSize: chunkSize}
			if err := detached.VerifyDetachedReader(context.Background(), reader, -1); err != nil {
				t.Fatalf("VerifyDetachedReader failed: %v", err)
			}
		})
	}

	// Tampered content must fail the same way as in-memory verification.
	tampered := bytes.Clone(content)
	tampered[0] ^= 0xff
	inMemoryTampered := *inMemory
	inMemoryTampered.Content = tampered
	if err := inMemoryTampered.Verify(); err == nil {
		t.Fatal("in-memory Verify succeeded on tampered content")
	}
	err := detached.VerifyDetachedReader(context.Background(), bytes.NewReader(tampered), -1)
	var mismatch *MessageDigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("tampered content: got %v, want MessageDigestMismatchError", err)
	}

	// The detached content must not leak into p7.Content.
	if len(detached.Content) != 0 {
		t.Fatalf("p7.Content was modified: %d bytes", len(detached.Content))
	}
}

func TestVerifyDetachedReaderMultipleSignersSinglePass(t *testing.T) {
	content := []byte(strings.Repeat("multi-signer content ", 300))
	detached, inMemory := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
		detachedSignerSpec{x509.SHA512WithRSA, OIDDigestAlgorithmSHA512},
		detachedSignerSpec{x509.ECDSAWithSHA256, OIDDigestAlgorithmSHA256},
	)

	if err := inMemory.Verify(); err != nil {
		t.Fatalf("in-memory Verify failed: %v", err)
	}

	// Two signers share SHA-256, one uses SHA-512: the content must still
	// be scanned exactly once.
	counting := &countingReader{r: &chunkedReader{data: content, chunkSize: 113}}
	if err := detached.VerifyDetachedReader(context.Background(), counting, -1); err != nil {
		t.Fatalf("VerifyDetachedReader failed: %v", err)
	}
	if counting.bytes != int64(len(content)) {
		t.Fatalf("content scanned %d bytes, want exactly %d (one pass)", counting.bytes, len(content))
	}
}

func TestVerifyDetachedReaderTailError(t *testing.T) {
	content := []byte(strings.Repeat("tail failure ", 100))
	detached, _ := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
	)

	errBoom := errors.New("boom")
	reader := &tailErrorReader{data: content, err: errBoom}
	err := detached.VerifyDetachedReader(context.Background(), reader, -1)
	if !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want the reader error to be preserved", err)
	}
}

func TestVerifyDetachedReaderTruncated(t *testing.T) {
	content := []byte(strings.Repeat("truncated content ", 100))
	detached, _ := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
	)

	truncated := content[:len(content)/2]
	err := detached.VerifyDetachedReader(context.Background(), bytes.NewReader(truncated), -1)
	var mismatch *MessageDigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("truncated content: got %v, want MessageDigestMismatchError", err)
	}
}

func TestVerifyDetachedReaderLimit(t *testing.T) {
	content := []byte(strings.Repeat("limited content ", 100))
	detached, _ := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
	)

	err := detached.VerifyDetachedReader(context.Background(), bytes.NewReader(content), int64(len(content)-1))
	if !errors.Is(err, ErrDetachedContentTooLarge) {
		t.Fatalf("got %v, want ErrDetachedContentTooLarge", err)
	}

	if err := detached.VerifyDetachedReader(context.Background(), bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("limit equal to content length: got %v, want nil", err)
	}
}

func TestVerifyDetachedReaderContextCanceled(t *testing.T) {
	content := []byte(strings.Repeat("canceled content ", 100))
	detached, _ := createDetachedSignature(t, content,
		detachedSignerSpec{x509.SHA256WithRSA, OIDDigestAlgorithmSHA256},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := detached.VerifyDetachedReader(ctx, bytes.NewReader(content), -1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestVerifyDetachedReaderRejectsUnsignedAttributes(t *testing.T) {
	content := []byte("no signed attributes")
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	signedData.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := signedData.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
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

	err = p7.VerifyDetachedReader(context.Background(), bytes.NewReader(content), -1)
	if !errors.Is(err, ErrDetachedUnsignedAttributes) {
		t.Fatalf("got %v, want ErrDetachedUnsignedAttributes", err)
	}
}

func TestVerifyDetachedReaderNoSigners(t *testing.T) {
	p7 := &PKCS7{}
	if err := p7.VerifyDetachedReader(context.Background(), bytes.NewReader(nil), -1); err == nil {
		t.Fatal("expected an error for a message without signers")
	}
}
