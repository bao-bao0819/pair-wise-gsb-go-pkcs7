package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// RecipientType identifies the CMS RecipientInfo CHOICE alternative used by a
// recipient of an EnvelopedData.
type RecipientType int

const (
	// RecipientTypeKeyTrans is a CMS KeyTransRecipientInfo, for example RSA
	// key transport.
	RecipientTypeKeyTrans RecipientType = iota

	// RecipientTypeKEM is an RFC 9629 KEMRecipientInfo carried inside an
	// OtherRecipientInfo.
	RecipientTypeKEM

	// RecipientTypeOther is any other RecipientInfo alternative. These
	// recipients can be listed but not decrypted.
	RecipientTypeOther
)

func (t RecipientType) String() string {
	switch t {
	case RecipientTypeKeyTrans:
		return "KeyTrans"
	case RecipientTypeKEM:
		return "KEM"
	default:
		return "Other"
	}
}

// RecipientInfo describes a single recipient of an EnvelopedData. It is
// derived from the RecipientInfo structure alone and never touches private
// keys or decrypted key material.
type RecipientInfo struct {
	// Index is the stable position of the recipient within the result of
	// Recipients and can be used to select it for decryption.
	Index int

	// Type is the RecipientInfo CHOICE alternative.
	Type RecipientType

	// Issuer is the DER-encoded issuer Name for recipients identified by
	// issuerAndSerialNumber, nil otherwise.
	Issuer []byte

	// SerialNumber is the certificate serial number for recipients
	// identified by issuerAndSerialNumber, nil otherwise.
	SerialNumber *big.Int

	// SubjectKeyID is the key identifier for recipients identified by
	// subjectKeyIdentifier, nil otherwise.
	SubjectKeyID []byte

	// Algorithm is the key-encryption or KEM algorithm OID of the
	// recipient. For RecipientTypeOther it is the OtherRecipientInfo type
	// OID when one is present.
	Algorithm asn1.ObjectIdentifier

	// Supported reports whether this package can decrypt the recipient.
	// Unsupported recipients are listed for inspection but cannot be
	// selected for decryption.
	Supported bool
}

// Recipients lists the recipients of an EnvelopedData without requiring any
// private key. The result never contains decrypted content or key material.
func (p7 *PKCS7) Recipients() ([]RecipientInfo, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return describeRecipients(data.RecipientInfos)
}

func describeRecipients(raws []asn1.RawValue) ([]RecipientInfo, error) {
	recipients := make([]RecipientInfo, 0, len(raws))
	for i, raw := range raws {
		recipient, err := describeRecipient(i, raw)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func describeRecipient(index int, raw asn1.RawValue) (RecipientInfo, error) {
	recipient := RecipientInfo{Index: index, Type: RecipientTypeOther}
	switch {
	case raw.Class == 0 && raw.Tag == asn1.TagSequence:
		info, err := parseKeyTransRecipientInfo(raw)
		if err != nil {
			return RecipientInfo{}, err
		}
		recipient.Type = RecipientTypeKeyTrans
		recipient.Issuer = info.IssuerAndSerialNumber.IssuerName.FullBytes
		recipient.SerialNumber = info.IssuerAndSerialNumber.SerialNumber
		recipient.Algorithm = info.KeyEncryptionAlgorithm.Algorithm
		recipient.Supported = info.KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSA)
	case raw.Class == 2 && raw.Tag == 4:
		other, err := parseOtherRecipientInfo(raw)
		if err != nil {
			return RecipientInfo{}, err
		}
		recipient.Algorithm = other.Type
		if !other.Type.Equal(OIDOtherRecipientInfoKEM) {
			return recipient, nil
		}
		var info kemRecipientInfo
		rest, err := asn1.Unmarshal(other.Value.FullBytes, &info)
		if err != nil {
			return RecipientInfo{}, fmt.Errorf("pkcs7: malformed KEMRecipientInfo: %w", err)
		}
		if len(rest) != 0 {
			return RecipientInfo{}, errors.New("pkcs7: trailing data in KEMRecipientInfo")
		}
		recipient.Type = RecipientTypeKEM
		recipient.Algorithm = info.KEM.Algorithm
		switch {
		case info.RecipientID.Class == 0 && info.RecipientID.Tag == asn1.TagSequence:
			var issuerAndSerial issuerAndSerial
			rest, err := asn1.Unmarshal(info.RecipientID.FullBytes, &issuerAndSerial)
			if err != nil {
				return RecipientInfo{}, fmt.Errorf("pkcs7: malformed issuerAndSerialNumber: %w", err)
			}
			if len(rest) != 0 {
				return RecipientInfo{}, errors.New("pkcs7: trailing data in issuerAndSerialNumber")
			}
			recipient.Issuer = issuerAndSerial.IssuerName.FullBytes
			recipient.SerialNumber = issuerAndSerial.SerialNumber
		case info.RecipientID.Class == 2 && info.RecipientID.Tag == 0:
			recipient.SubjectKeyID = info.RecipientID.Bytes
		default:
			return RecipientInfo{}, errors.New("pkcs7: unsupported RecipientIdentifier")
		}
		recipient.Supported = kemRecipientInfoSupported(info)
	}
	return recipient, nil
}

func kemRecipientInfoSupported(info kemRecipientInfo) bool {
	if info.Version != 0 {
		return false
	}
	if !info.KEM.Algorithm.Equal(OIDKeyAlgorithmMLKEM768) &&
		!info.KEM.Algorithm.Equal(OIDKeyAlgorithmMLKEM1024) {
		return false
	}
	if algorithmIdentifierHasParameters(info.KEM) {
		return false
	}
	if !info.KDF.Algorithm.Equal(OIDKDFHKDFSHA256) || algorithmIdentifierHasParameters(info.KDF) {
		return false
	}
	if !info.Wrap.Algorithm.Equal(OIDKeyWrapAES256) || algorithmIdentifierHasParameters(info.Wrap) {
		return false
	}
	return info.KEKLength == mlKEMKEKLength
}

// RecipientSelector selects a single recipient of an EnvelopedData for
// decryption. A recipient is selected either by its stable Index within
// Recipients, or by an identifier (issuer/serial number or subject key
// identifier) that must match exactly one recipient.
type RecipientSelector struct {
	// Index selects a recipient by position. A negative value disables
	// index selection and selects by identifier instead.
	Index int

	// Issuer is the DER-encoded issuer Name matched together with
	// SerialNumber.
	Issuer []byte

	// SerialNumber is the certificate serial number matched together with
	// Issuer.
	SerialNumber *big.Int

	// SubjectKeyID matches a recipient identified by subject key
	// identifier.
	SubjectKeyID []byte
}

// SelectRecipientByIndex returns a RecipientSelector that selects the
// recipient at the given position within Recipients.
func SelectRecipientByIndex(index int) RecipientSelector {
	return RecipientSelector{Index: index}
}

// SelectRecipientByIssuerAndSerial returns a RecipientSelector that selects
// the recipient identified by the DER-encoded issuer Name and certificate
// serial number.
func SelectRecipientByIssuerAndSerial(issuer []byte, serialNumber *big.Int) RecipientSelector {
	return RecipientSelector{Index: -1, Issuer: issuer, SerialNumber: serialNumber}
}

// SelectRecipientBySubjectKeyID returns a RecipientSelector that selects the
// recipient identified by the given subject key identifier.
func SelectRecipientBySubjectKeyID(subjectKeyID []byte) RecipientSelector {
	return RecipientSelector{Index: -1, SubjectKeyID: subjectKeyID}
}

// SelectRecipientForCertificate returns a RecipientSelector that selects the
// recipient identified by the certificate's issuer and serial number.
func SelectRecipientForCertificate(cert *x509.Certificate) RecipientSelector {
	return SelectRecipientByIssuerAndSerial(cert.RawIssuer, cert.SerialNumber)
}

func (s RecipientSelector) resolve(recipients []RecipientInfo) (int, error) {
	if s.Index >= 0 {
		if s.Index >= len(recipients) {
			return -1, fmt.Errorf("pkcs7: recipient index %d out of range: EnvelopedData has %d recipients", s.Index, len(recipients))
		}
		return s.Index, nil
	}
	var matches func(RecipientInfo) bool
	switch {
	case len(s.SubjectKeyID) > 0:
		matches = func(r RecipientInfo) bool {
			return len(r.SubjectKeyID) > 0 && bytes.Equal(r.SubjectKeyID, s.SubjectKeyID)
		}
	case s.Issuer != nil && s.SerialNumber != nil:
		matches = func(r RecipientInfo) bool {
			return r.SerialNumber != nil && r.SerialNumber.Cmp(s.SerialNumber) == 0 &&
				bytes.Equal(r.Issuer, s.Issuer)
		}
	default:
		return -1, errors.New("pkcs7: recipient selector is empty: provide an index, issuer/serial number, or subject key identifier")
	}
	index := -1
	count := 0
	for _, recipient := range recipients {
		if matches(recipient) {
			index = recipient.Index
			count++
		}
	}
	switch count {
	case 0:
		return -1, errors.New("pkcs7: no recipient matches the provided identifier")
	case 1:
		return index, nil
	default:
		return -1, fmt.Errorf("pkcs7: recipient identifier is ambiguous: matches %d recipients, select by index", count)
	}
}

// DecryptRecipient decrypts the EnvelopedData content for the single
// recipient chosen by selector, using the certificate and private key of
// that recipient. The certificate is optional: when provided it must match
// the selected recipient's identifier.
//
// Unlike Decrypt, only the selected recipient is tried. If selection or
// decryption fails, the error is returned as is and no other recipient or
// algorithm is attempted.
func (p7 *PKCS7) DecryptRecipient(selector RecipientSelector, cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipients, err := describeRecipients(data.RecipientInfos)
	if err != nil {
		return nil, err
	}
	index, err := selector.resolve(recipients)
	if err != nil {
		return nil, err
	}
	recipient := recipients[index]
	if !recipient.Supported {
		return nil, fmt.Errorf("pkcs7: recipient %d (%s, algorithm %s) is not supported", index, recipient.Type, recipient.Algorithm)
	}

	var contentKey []byte
	switch recipient.Type {
	case RecipientTypeKeyTrans:
		rsaKey, ok := pkey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pkcs7: recipient %d requires an RSA private key, got %T", index, pkey)
		}
		info, err := parseKeyTransRecipientInfo(data.RecipientInfos[index])
		if err != nil {
			return nil, err
		}
		if cert != nil && !isCertMatchForIssuerAndSerial(cert, info.IssuerAndSerialNumber) {
			return nil, fmt.Errorf("pkcs7: certificate does not match recipient %d", index)
		}
		//nolint:staticcheck // PKCS #1 v1.5 is required by the existing CMS RSA key-transport format.
		contentKey, err = rsa.DecryptPKCS1v15(rand.Reader, rsaKey, info.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: cannot decrypt key for recipient %d: %w", index, err)
		}
	case RecipientTypeKEM:
		if data.Version != 3 {
			return nil, errors.New("pkcs7: EnvelopedData containing OtherRecipientInfo must use version 3")
		}
		contentEncryptionAlgorithm := data.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm
		if !contentEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmAES128CBC) &&
			!contentEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmAES256CBC) {
			return nil, errors.New("pkcs7: ML-KEM EnvelopedData requires AES-CBC; AES-GCM requires AuthEnvelopedData")
		}
		other, err := parseOtherRecipientInfo(data.RecipientInfos[index])
		if err != nil {
			return nil, err
		}
		var info kemRecipientInfo
		rest, err := asn1.Unmarshal(other.Value.FullBytes, &info)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: malformed KEMRecipientInfo: %w", err)
		}
		if len(rest) != 0 {
			return nil, errors.New("pkcs7: trailing data in KEMRecipientInfo")
		}
		if cert != nil {
			matches, err := recipientIdentifierMatchesCertificate(info.RecipientID, cert)
			if err != nil {
				return nil, err
			}
			if !matches {
				return nil, fmt.Errorf("pkcs7: certificate does not match recipient %d", index)
			}
		}
		contentKey, err = decryptKEMRecipient(info, pkey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("pkcs7: recipient %d (%s) is not decryptable", index, recipient.Type)
	}
	defer clear(contentKey)
	return data.EncryptedContentInfo.decrypt(contentKey)
}
