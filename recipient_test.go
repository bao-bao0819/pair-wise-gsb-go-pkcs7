package pkcs7

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestRecipientsListsEnvelopedData(t *testing.T) {
	pairA, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	pairB, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128GCM)
	encrypted, err := Encrypt([]byte("inspect me"), []*x509.Certificate{pairA.Certificate, pairB.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 {
		t.Fatalf("Recipients length = %d, want 2", len(recipients))
	}
	bySerial := map[string]Recipient{}
	for _, recipient := range recipients {
		if recipient.Type != RecipientTypeKeyTrans {
			t.Errorf("recipient %d type = %d, want RecipientTypeKeyTrans", recipient.Index, recipient.Type)
		}
		if !recipient.Supported {
			t.Errorf("recipient %d is not supported: %s", recipient.Index, recipient.UnsupportedReason)
		}
		if !recipient.KeyEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmRSA) {
			t.Errorf("recipient %d algorithm = %s, want %s", recipient.Index, recipient.KeyEncryptionAlgorithm, OIDEncryptionAlgorithmRSA)
		}
		if recipient.IssuerAndSerial == nil {
			t.Fatalf("recipient %d has no issuerAndSerialNumber", recipient.Index)
		}
		if len(recipient.SubjectKeyID) != 0 {
			t.Errorf("recipient %d unexpectedly has a subject key identifier", recipient.Index)
		}
		bySerial[recipient.IssuerAndSerial.SerialNumber.String()] = recipient
	}
	for _, pair := range []certKeyPair{pairA, pairB} {
		recipient, ok := bySerial[pair.Certificate.SerialNumber.String()]
		if !ok {
			t.Fatalf("no recipient listed for serial %s", pair.Certificate.SerialNumber)
		}
		if !bytes.Equal(recipient.IssuerAndSerial.Issuer, pair.Certificate.RawIssuer) {
			t.Errorf("recipient issuer does not match certificate issuer")
		}
	}
}

func TestRecipientsRejectsNonEnvelopedData(t *testing.T) {
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128GCM)
	encrypted, err := EncryptUsingPSK([]byte("psk content"), []byte("128BitKey4AESGCM"))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Recipients(); !errors.Is(err, ErrNotEncryptedContent) {
		t.Fatalf("Recipients error = %v, want ErrNotEncryptedContent", err)
	}
	if _, err := p7.DecryptRecipient(nil, SelectRecipientIndex(0)); !errors.Is(err, ErrNotEncryptedContent) {
		t.Fatalf("DecryptRecipient error = %v, want ErrNotEncryptedContent", err)
	}
}

func TestDecryptRecipientByIdentifierIgnoresOrder(t *testing.T) {
	pairA, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	pairB, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("same plaintext for both recipient orders")
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)

	orders := [][]*x509.Certificate{
		{pairA.Certificate, pairB.Certificate},
		{pairB.Certificate, pairA.Certificate},
	}
	selector := SelectRecipientByIssuerAndSerial(pairB.Certificate.RawIssuer, pairB.Certificate.SerialNumber)
	for i, recipients := range orders {
		encrypted, err := Encrypt(plaintext, recipients)
		if err != nil {
			t.Fatal(err)
		}
		p7, err := Parse(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := p7.DecryptRecipient(*pairB.PrivateKey, selector)
		if err != nil {
			t.Fatalf("order %d: DecryptRecipient by identifier: %v", i, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("order %d: decrypted = %q, want %q", i, decrypted, plaintext)
		}

		// Selecting the same recipient through its listed stable index must
		// recover the same plaintext.
		listed, err := p7.Recipients()
		if err != nil {
			t.Fatal(err)
		}
		index := -1
		for _, recipient := range listed {
			if recipient.IssuerAndSerial != nil && recipient.IssuerAndSerial.SerialNumber.Cmp(pairB.Certificate.SerialNumber) == 0 {
				index = recipient.Index
			}
		}
		if index < 0 {
			t.Fatalf("order %d: recipient B not listed", i)
		}
		byIndex, err := p7.DecryptRecipient(*pairB.PrivateKey, SelectRecipientIndex(index))
		if err != nil {
			t.Fatalf("order %d: DecryptRecipient by index: %v", i, err)
		}
		if !bytes.Equal(byIndex, plaintext) {
			t.Fatalf("order %d: decrypted by index = %q, want %q", i, byIndex, plaintext)
		}
	}
}

func TestDecryptRecipientMissingTarget(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)
	encrypted, err := Encrypt([]byte("content"), []*x509.Certificate{pair.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	missing := SelectRecipientByIssuerAndSerial(pair.Certificate.RawIssuer, big.NewInt(-1))
	if _, err := p7.DecryptRecipient(*pair.PrivateKey, missing); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("DecryptRecipient error = %v, want ErrNoMatchingRecipient", err)
	}
	if _, err := p7.DecryptRecipient(*pair.PrivateKey, SelectRecipientBySubjectKeyID([]byte("no-such-key-id"))); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("DecryptRecipient error = %v, want ErrNoMatchingRecipient", err)
	}
	if _, err := p7.DecryptRecipient(*pair.PrivateKey, SelectRecipientIndex(1)); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("DecryptRecipient error = %v, want out-of-range index error", err)
	}
	if _, err := p7.DecryptRecipient(*pair.PrivateKey, RecipientSelector{}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("DecryptRecipient error = %v, want empty selector error", err)
	}
}

func TestDecryptRecipientAmbiguousIdentifierRequiresIndex(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("two recipients, one certificate")
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)
	encrypted, err := Encrypt(plaintext, []*x509.Certificate{pair.Certificate, pair.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 {
		t.Fatalf("Recipients length = %d, want 2", len(recipients))
	}

	selector := SelectRecipientByIssuerAndSerial(pair.Certificate.RawIssuer, pair.Certificate.SerialNumber)
	if _, err := p7.DecryptRecipient(*pair.PrivateKey, selector); !errors.Is(err, ErrAmbiguousRecipient) {
		t.Fatalf("DecryptRecipient error = %v, want ErrAmbiguousRecipient", err)
	}
	for _, recipient := range recipients {
		decrypted, err := p7.DecryptRecipient(*pair.PrivateKey, SelectRecipientIndex(recipient.Index))
		if err != nil {
			t.Fatalf("DecryptRecipient index %d: %v", recipient.Index, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("index %d: decrypted = %q, want %q", recipient.Index, decrypted, plaintext)
		}
	}
}

func TestDecryptRecipientWrongPrivateKey(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	// createTestCertificate reuses fixed RSA keys per signature algorithm, so
	// generate a fresh key to have one that does not match the recipient.
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)
	encrypted, err := Encrypt([]byte("for one recipient only"), []*x509.Certificate{pair.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p7.DecryptRecipient(wrongKey, SelectRecipientIndex(0))
	if err == nil || !strings.Contains(err.Error(), "recipient 0") {
		t.Fatalf("DecryptRecipient with wrong RSA key = %v, want error naming recipient 0", err)
	}

	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	wrongKEMKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	kemCert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, kemKey.EncapsulationKey().Bytes())
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
	encrypted, err = Encrypt([]byte("post-quantum content"), []*x509.Certificate{kemCert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err = Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p7.DecryptRecipient(wrongKEMKey, SelectRecipientIndex(0))
	if err == nil || !strings.Contains(err.Error(), "recipient 0") {
		t.Fatalf("DecryptRecipient with wrong ML-KEM key = %v, want error naming recipient 0", err)
	}
}

func TestDecryptRecipientUnsupportedTarget(t *testing.T) {
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)
	encrypted, err := Encrypt([]byte("unsupported key transport"), []*x509.Certificate{pair.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	envelope := p7.raw.(envelopedData)
	var info recipientInfo
	if _, err := asn1.Unmarshal(envelope.RecipientInfos[0].FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	info.KeyEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
	raw, err := marshalRecipientInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	envelope.RecipientInfos[0] = raw
	p7.raw = envelope

	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Recipients length = %d, want 1", len(recipients))
	}
	if recipients[0].Supported {
		t.Fatal("unsupported key transport algorithm listed as supported")
	}
	if recipients[0].UnsupportedReason == "" {
		t.Fatal("unsupported recipient has no reason")
	}
	_, err = p7.DecryptRecipient(*pair.PrivateKey, SelectRecipientIndex(0))
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Fatalf("DecryptRecipient error = %v, want unsupported recipient error", err)
	}
}

func TestDecryptRecipientBySubjectKeyID(t *testing.T) {
	privateKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, privateKey.EncapsulationKey().Bytes())
	plaintext := []byte("identified by subject key identifier")
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)
	encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	envelope := p7.raw.(envelopedData)
	info := decodeKEMRecipientInfo(t, envelope.RecipientInfos[0])
	info.RecipientID = asn1.RawValue{Class: 2, Tag: 0, Bytes: cert.SubjectKeyId}
	envelope.RecipientInfos[0] = encodeKEMRecipientInfo(t, info)
	p7.raw = envelope

	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Recipients length = %d, want 1", len(recipients))
	}
	recipient := recipients[0]
	if recipient.Type != RecipientTypeKEM {
		t.Fatalf("recipient type = %d, want RecipientTypeKEM", recipient.Type)
	}
	if !recipient.Supported {
		t.Fatalf("KEM recipient not supported: %s", recipient.UnsupportedReason)
	}
	if !recipient.KeyEncryptionAlgorithm.Equal(OIDKeyAlgorithmMLKEM768) {
		t.Errorf("recipient algorithm = %s, want %s", recipient.KeyEncryptionAlgorithm, OIDKeyAlgorithmMLKEM768)
	}
	if recipient.IssuerAndSerial != nil {
		t.Error("recipient unexpectedly has issuerAndSerialNumber")
	}
	if !bytes.Equal(recipient.SubjectKeyID, cert.SubjectKeyId) {
		t.Errorf("recipient subject key identifier = %X, want %X", recipient.SubjectKeyID, cert.SubjectKeyId)
	}

	decrypted, err := p7.DecryptRecipient(privateKey, SelectRecipientBySubjectKeyID(cert.SubjectKeyId))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}
