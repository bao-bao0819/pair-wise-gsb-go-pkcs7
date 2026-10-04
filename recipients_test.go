package pkcs7

import (
	"bytes"
	"crypto/mlkem"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
)

func TestRecipientsListAndSelectByIdentifier(t *testing.T) {
	certA, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	certB, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("multi-recipient secret")
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128CBC)

	orders := [][]*x509.Certificate{
		{certA.Certificate, certB.Certificate},
		{certB.Certificate, certA.Certificate},
	}
	for i, order := range orders {
		encrypted, err := Encrypt(plaintext, order)
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
			t.Fatalf("order %d: Recipients length = %d, want 2", i, len(recipients))
		}
		for _, recipient := range recipients {
			if recipient.Type != RecipientTypeKeyTrans {
				t.Errorf("order %d: recipient %d type = %s, want KeyTrans", i, recipient.Index, recipient.Type)
			}
			if !recipient.Supported {
				t.Errorf("order %d: recipient %d is not supported", i, recipient.Index)
			}
			if !recipient.Algorithm.Equal(OIDEncryptionAlgorithmRSA) {
				t.Errorf("order %d: recipient %d algorithm = %s, want RSA", i, recipient.Index, recipient.Algorithm)
			}
			if recipient.SerialNumber == nil || len(recipient.Issuer) == 0 {
				t.Errorf("order %d: recipient %d missing issuer/serial identifier", i, recipient.Index)
			}
		}

		// Selecting by identifier must find certA's recipient and produce the
		// same plaintext regardless of the recipient order.
		got, err := p7.DecryptRecipient(SelectRecipientForCertificate(certA.Certificate), certA.Certificate, *certA.PrivateKey)
		if err != nil {
			t.Fatalf("order %d: DecryptRecipient by identifier: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("order %d: decrypted content = %q, want %q", i, got, plaintext)
		}

		// Selecting certB by index must agree with its listed position.
		index := -1
		for _, recipient := range recipients {
			if recipient.SerialNumber.Cmp(certB.Certificate.SerialNumber) == 0 {
				index = recipient.Index
			}
		}
		if index < 0 {
			t.Fatalf("order %d: certB recipient not listed", i)
		}
		got, err = p7.DecryptRecipient(SelectRecipientByIndex(index), certB.Certificate, *certB.PrivateKey)
		if err != nil {
			t.Fatalf("order %d: DecryptRecipient by index: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("order %d: decrypted content = %q, want %q", i, got, plaintext)
		}
	}
}

func TestDecryptRecipientMissingTarget(t *testing.T) {
	certA, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	certC, err := createTestCertificate(x509.SHA384WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt([]byte("secret"), []*x509.Certificate{certA.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p7.DecryptRecipient(SelectRecipientForCertificate(certC.Certificate), certC.Certificate, *certC.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "no recipient matches") {
		t.Errorf("missing identifier error = %v, want 'no recipient matches'", err)
	}
	if _, err := p7.DecryptRecipient(SelectRecipientBySubjectKeyID([]byte("no-such-key-id")), nil, *certA.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "no recipient matches") {
		t.Errorf("missing subject key identifier error = %v, want 'no recipient matches'", err)
	}
	if _, err := p7.DecryptRecipient(SelectRecipientByIndex(1), certA.Certificate, *certA.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "out of range") {
		t.Errorf("out of range index error = %v, want 'out of range'", err)
	}
	if _, err := p7.DecryptRecipient(RecipientSelector{Index: -1}, certA.Certificate, *certA.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "selector is empty") {
		t.Errorf("empty selector error = %v, want 'selector is empty'", err)
	}
}

func TestDecryptRecipientAmbiguousTarget(t *testing.T) {
	certA, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("duplicated recipient")
	encrypted, err := Encrypt(plaintext, []*x509.Certificate{certA.Certificate, certA.Certificate})
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

	if _, err := p7.DecryptRecipient(SelectRecipientForCertificate(certA.Certificate), certA.Certificate, *certA.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate identifier error = %v, want 'ambiguous'", err)
	}

	// A specific index resolves the ambiguity.
	for _, index := range []int{0, 1} {
		got, err := p7.DecryptRecipient(SelectRecipientByIndex(index), certA.Certificate, *certA.PrivateKey)
		if err != nil {
			t.Fatalf("DecryptRecipient by index %d: %v", index, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("index %d: decrypted content = %q, want %q", index, got, plaintext)
		}
	}
}

func TestDecryptRecipientWrongKey(t *testing.T) {
	certA, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	certB, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("only for cert A")
	encrypted, err := Encrypt(plaintext, []*x509.Certificate{certA.Certificate, certB.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	// The wrong private key must fail without falling back to certB's
	// recipient, even though certB's key could decrypt the content.
	if _, err := p7.DecryptRecipient(SelectRecipientForCertificate(certA.Certificate), certA.Certificate, *certB.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "cannot decrypt key for recipient") {
		t.Errorf("wrong private key error = %v, want 'cannot decrypt key for recipient'", err)
	}

	// A certificate that does not match the selected recipient is rejected.
	if _, err := p7.DecryptRecipient(SelectRecipientForCertificate(certA.Certificate), certB.Certificate, *certB.PrivateKey); err == nil ||
		!strings.Contains(err.Error(), "certificate does not match recipient") {
		t.Errorf("mismatched certificate error = %v, want 'certificate does not match recipient'", err)
	}

	// The correct key still works.
	got, err := p7.DecryptRecipient(SelectRecipientForCertificate(certA.Certificate), certA.Certificate, *certA.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptRecipient with correct key: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted content = %q, want %q", got, plaintext)
	}
}

func TestDecryptRecipientMLKEM(t *testing.T) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	cert := newMLKEMTestCertificate(t, OIDKeyAlgorithmMLKEM768, key.EncapsulationKey().Bytes())
	plaintext := []byte("post-quantum recipient selection")
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES256CBC)

	encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert})
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
	if len(recipients) != 1 {
		t.Fatalf("Recipients length = %d, want 1", len(recipients))
	}
	recipient := recipients[0]
	if recipient.Type != RecipientTypeKEM {
		t.Errorf("recipient type = %s, want KEM", recipient.Type)
	}
	if !recipient.Supported {
		t.Error("ML-KEM recipient is not supported")
	}
	if !recipient.Algorithm.Equal(OIDKeyAlgorithmMLKEM768) {
		t.Errorf("recipient algorithm = %s, want ML-KEM-768", recipient.Algorithm)
	}

	for name, selector := range map[string]RecipientSelector{
		"index":      SelectRecipientByIndex(0),
		"identifier": SelectRecipientForCertificate(cert),
	} {
		got, err := p7.DecryptRecipient(selector, cert, key)
		if err != nil {
			t.Fatalf("%s: DecryptRecipient: %v", name, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("%s: decrypted content = %q, want %q", name, got, plaintext)
		}
	}

	// A decapsulation key for a different recipient must fail without
	// trying anything else.
	otherKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.DecryptRecipient(SelectRecipientByIndex(0), cert, otherKey); err == nil {
		t.Error("DecryptRecipient with wrong ML-KEM key succeeded")
	}
}

func TestRecipientsUnsupported(t *testing.T) {
	info := recipientInfo{
		Version: 0,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
			SerialNumber: big.NewInt(7),
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmDESCBC},
		EncryptedKey:           []byte("not-a-real-key"),
	}
	raw, err := marshalRecipientInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	envelope := envelopedData{
		Version:        0,
		RecipientInfos: []asn1.RawValue{raw},
		EncryptedContentInfo: encryptedContentInfo{
			ContentType: OIDData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  OIDEncryptionAlgorithmDESCBC,
				Parameters: asn1.RawValue{Tag: 4, Bytes: make([]byte, 8)},
			},
			EncryptedContent: marshalEncryptedContent([]byte("0123456789abcdef")),
		},
	}
	inner, err := asn1.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner},
	})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}

	// Unsupported recipients are listed but flagged as unsupported.
	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Recipients length = %d, want 1", len(recipients))
	}
	recipient := recipients[0]
	if recipient.Type != RecipientTypeKeyTrans {
		t.Errorf("recipient type = %s, want KeyTrans", recipient.Type)
	}
	if recipient.Supported {
		t.Error("recipient with DES key-encryption algorithm is marked supported")
	}
	if recipient.SerialNumber.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("recipient serial = %s, want 7", recipient.SerialNumber)
	}

	// An unsupported recipient cannot be selected for decryption.
	if _, err := p7.DecryptRecipient(SelectRecipientByIndex(0), nil, nil); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Errorf("unsupported recipient error = %v, want 'not supported'", err)
	}
}

func TestRecipientsNotEnvelopedData(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Recipients length = %d, want 1", len(recipients))
	}

	// EncryptedData is not EnvelopedData.
	withContentEncryptionAlgorithm(t, EncryptionAlgorithmAES128GCM)
	encrypted, err := EncryptUsingPSK([]byte("content"), []byte("128BitKey4AESGCM"))
	if err != nil {
		t.Fatal(err)
	}
	p7, err = Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Recipients(); err != ErrNotEncryptedContent {
		t.Errorf("Recipients on EncryptedData error = %v, want ErrNotEncryptedContent", err)
	}
	if _, err := p7.DecryptRecipient(SelectRecipientByIndex(0), nil, nil); err != ErrNotEncryptedContent {
		t.Errorf("DecryptRecipient on EncryptedData error = %v, want ErrNotEncryptedContent", err)
	}
}
