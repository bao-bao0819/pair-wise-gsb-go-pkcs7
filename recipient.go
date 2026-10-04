package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// RecipientType classifies the RecipientInfo alternative used by one recipient
// of an EnvelopedData.
type RecipientType int

const (
	// RecipientTypeUnknown is a RecipientInfo this library cannot classify.
	RecipientTypeUnknown RecipientType = iota

	// RecipientTypeKeyTrans is a CMS KeyTransRecipientInfo, used for RSA key
	// transport.
	RecipientTypeKeyTrans

	// RecipientTypeKEM is an OtherRecipientInfo carrying a KEMRecipientInfo
	// as defined by RFC 9629.
	RecipientTypeKEM

	// RecipientTypeOther is an OtherRecipientInfo of an unrecognized type.
	RecipientTypeOther
)

// IssuerAndSerial identifies a recipient certificate by the DER encoding of
// its issuer name and its serial number.
type IssuerAndSerial struct {
	Issuer       []byte
	SerialNumber *big.Int
}

// Recipient describes a single recipient of an EnvelopedData. It is derived
// from the RecipientInfo structure alone and never contains keying material,
// so listing recipients does not require or expose any private key.
type Recipient struct {
	// Index is the recipient's position in the EnvelopedData RecipientInfos
	// set. It is stable for a given parsed document and can be used with
	// SelectRecipientIndex.
	Index int

	// Type classifies the RecipientInfo alternative.
	Type RecipientType

	// IssuerAndSerial is set when the recipient is identified by
	// issuerAndSerialNumber. It is nil when SubjectKeyID is used.
	IssuerAndSerial *IssuerAndSerial

	// SubjectKeyID is set when the recipient is identified by a subject key
	// identifier. It is nil when IssuerAndSerial is used.
	SubjectKeyID []byte

	// KeyEncryptionAlgorithm is the algorithm protecting the
	// content-encryption key for this recipient: the key transport algorithm
	// for RecipientTypeKeyTrans, the KEM algorithm for RecipientTypeKEM, and
	// the OtherRecipientInfo type for RecipientTypeOther.
	KeyEncryptionAlgorithm asn1.ObjectIdentifier

	// Supported reports whether this library can decrypt the recipient.
	// Unsupported recipients are listed for inspection but cannot be
	// selected for decryption.
	Supported bool

	// UnsupportedReason explains why Supported is false.
	UnsupportedReason string
}

// Recipients lists the recipients of an EnvelopedData without performing any
// decryption. It returns ErrNotEncryptedContent when the PKCS7 structure is
// not EnvelopedData.
func (p7 *PKCS7) Recipients() ([]Recipient, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	listed := listRecipients(data.RecipientInfos)
	recipients := make([]Recipient, len(listed))
	for i, recipient := range listed {
		recipients[i] = recipient.Recipient
	}
	return recipients, nil
}

// ErrNoMatchingRecipient is returned when a RecipientSelector matches no
// recipient of an EnvelopedData.
var ErrNoMatchingRecipient = errors.New("pkcs7: no recipient matches the selector")

// ErrAmbiguousRecipient is returned when a RecipientSelector matches more
// than one recipient. Select the target by index instead.
var ErrAmbiguousRecipient = errors.New("pkcs7: recipient selector is ambiguous; select a recipient by index")

// RecipientSelector identifies a single recipient of an EnvelopedData,
// either by its stable index or by the identifier reported by Recipients.
// Construct it with SelectRecipientIndex, SelectRecipientByIssuerAndSerial,
// or SelectRecipientBySubjectKeyID.
type RecipientSelector struct {
	index        *int
	issuer       []byte
	serialNumber *big.Int
	subjectKeyID []byte
}

// SelectRecipientIndex selects the recipient at the given position in the
// EnvelopedData RecipientInfos set, as reported by Recipient.Index.
func SelectRecipientIndex(index int) RecipientSelector {
	return RecipientSelector{index: &index}
}

// SelectRecipientByIssuerAndSerial selects the recipient identified by the
// DER-encoded issuer name and serial number of its certificate.
func SelectRecipientByIssuerAndSerial(issuer []byte, serialNumber *big.Int) RecipientSelector {
	return RecipientSelector{issuer: issuer, serialNumber: serialNumber}
}

// SelectRecipientBySubjectKeyID selects the recipient identified by a
// subject key identifier.
func SelectRecipientBySubjectKeyID(subjectKeyID []byte) RecipientSelector {
	return RecipientSelector{subjectKeyID: subjectKeyID}
}

// DecryptRecipient decrypts the content of an EnvelopedData for the single
// recipient identified by selector. Identifier-based selectors must match
// exactly one recipient; when several recipients share an identifier,
// ErrAmbiguousRecipient is returned and a stable index from Recipients must
// be used instead. Only the selected recipient is attempted: if it is
// unsupported or decryption fails, the error reports the reason and no other
// recipient or algorithm is tried.
func (p7 *PKCS7) DecryptRecipient(privateKey crypto.PrivateKey, selector RecipientSelector) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipients := listRecipients(data.RecipientInfos)
	index, err := selector.selectIndex(recipients)
	if err != nil {
		return nil, err
	}
	recipient := recipients[index]
	if !recipient.Supported {
		return nil, fmt.Errorf("pkcs7: recipient %d cannot be decrypted: %s", index, recipient.UnsupportedReason)
	}

	var contentKey []byte
	switch recipient.Type {
	case RecipientTypeKeyTrans:
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pkcs7: recipient %d uses RSA key transport and requires an RSA private key", index)
		}
		//nolint:staticcheck // PKCS #1 v1.5 is required by the existing CMS RSA key-transport format.
		contentKey, err = rsa.DecryptPKCS1v15(rand.Reader, key, recipient.keyTrans.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: cannot decrypt key for recipient %d: %w", index, err)
		}
	case RecipientTypeKEM:
		expectedKEM, decapsulate, ok := mlKEMDecapsulator(privateKey)
		if !ok {
			return nil, ErrUnsupportedAlgorithm
		}
		if data.Version != 3 {
			return nil, errors.New("pkcs7: EnvelopedData containing OtherRecipientInfo must use version 3")
		}
		contentEncryptionAlgorithm := data.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm
		if !contentEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmAES128CBC) &&
			!contentEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmAES256CBC) {
			return nil, errors.New("pkcs7: ML-KEM EnvelopedData requires AES-CBC; AES-GCM requires AuthEnvelopedData")
		}
		contentKey, err = decryptKEMRecipientInfo(*recipient.kem, expectedKEM, decapsulate)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: cannot decrypt key for recipient %d: %w", index, err)
		}
	default:
		return nil, fmt.Errorf("pkcs7: recipient %d cannot be decrypted: unsupported recipient type", index)
	}
	defer clear(contentKey)
	return data.EncryptedContentInfo.decrypt(contentKey)
}

// selectIndex resolves the selector to a single recipient index. An
// identifier-based selector must match exactly one recipient.
func (s RecipientSelector) selectIndex(recipients []listedRecipient) (int, error) {
	if s.index != nil {
		if *s.index < 0 || *s.index >= len(recipients) {
			return -1, fmt.Errorf("pkcs7: recipient index %d out of range [0, %d)", *s.index, len(recipients))
		}
		return *s.index, nil
	}
	if s.serialNumber == nil && s.subjectKeyID == nil {
		return -1, errors.New("pkcs7: recipient selector is empty")
	}
	matches := make([]int, 0, 1)
	for i, recipient := range recipients {
		if s.matches(recipient.Recipient) {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		return -1, ErrNoMatchingRecipient
	case 1:
		return matches[0], nil
	default:
		return -1, fmt.Errorf("%w: %d recipients share the identifier", ErrAmbiguousRecipient, len(matches))
	}
}

func (s RecipientSelector) matches(recipient Recipient) bool {
	switch {
	case s.serialNumber != nil:
		return recipient.IssuerAndSerial != nil &&
			recipient.IssuerAndSerial.SerialNumber.Cmp(s.serialNumber) == 0 &&
			bytes.Equal(recipient.IssuerAndSerial.Issuer, s.issuer)
	case s.subjectKeyID != nil:
		return len(recipient.SubjectKeyID) != 0 && bytes.Equal(recipient.SubjectKeyID, s.subjectKeyID)
	}
	return false
}

// listedRecipient pairs the public Recipient description with the parsed
// RecipientInfo needed to decrypt it.
type listedRecipient struct {
	Recipient
	keyTrans *recipientInfo
	kem      *kemRecipientInfo
}

// listRecipients inspects each RecipientInfo without decrypting anything.
// Recipients that cannot be parsed or use unsupported algorithms are listed
// with Supported set to false.
func listRecipients(raws []asn1.RawValue) []listedRecipient {
	recipients := make([]listedRecipient, 0, len(raws))
	for i, raw := range raws {
		recipient := listedRecipient{Recipient: Recipient{Index: i}}
		switch {
		case raw.Class == 0 && raw.Tag == asn1.TagSequence:
			recipient.Recipient.Type = RecipientTypeKeyTrans
			info, reason, err := parseKeyTransRecipient(raw)
			if err != nil {
				recipient.UnsupportedReason = reason
				break
			}
			recipient.keyTrans = info
			recipient.IssuerAndSerial = &IssuerAndSerial{
				Issuer:       info.IssuerAndSerialNumber.IssuerName.FullBytes,
				SerialNumber: info.IssuerAndSerialNumber.SerialNumber,
			}
			recipient.KeyEncryptionAlgorithm = info.KeyEncryptionAlgorithm.Algorithm
			if !info.KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSA) {
				recipient.UnsupportedReason = fmt.Sprintf("unsupported key transport algorithm %s", info.KeyEncryptionAlgorithm.Algorithm)
				break
			}
			recipient.Supported = true
		case raw.Class == 2 && raw.Tag == 4:
			other, err := parseOtherRecipientInfo(raw)
			if err != nil {
				recipient.UnsupportedReason = err.Error()
				break
			}
			recipient.KeyEncryptionAlgorithm = other.Type
			if !other.Type.Equal(OIDOtherRecipientInfoKEM) {
				recipient.Recipient.Type = RecipientTypeOther
				recipient.UnsupportedReason = fmt.Sprintf("unsupported OtherRecipientInfo type %s", other.Type)
				break
			}
			recipient.Recipient.Type = RecipientTypeKEM
			var info kemRecipientInfo
			rest, err := asn1.Unmarshal(other.Value.FullBytes, &info)
			if err != nil || len(rest) != 0 {
				recipient.UnsupportedReason = "malformed KEMRecipientInfo"
				break
			}
			recipient.kem = &info
			recipient.KeyEncryptionAlgorithm = info.KEM.Algorithm
			recipient.setIdentifier(info.RecipientID)
			if err := checkKEMRecipientInfo(info); err != nil {
				recipient.UnsupportedReason = err.Error()
				break
			}
			recipient.Supported = true
		default:
			recipient.UnsupportedReason = "unrecognized RecipientInfo alternative"
		}
		recipients = append(recipients, recipient)
	}
	return recipients
}

// setIdentifier fills the recipient identifier fields from a
// RecipientIdentifier CHOICE.
func (r *listedRecipient) setIdentifier(identifier asn1.RawValue) {
	switch {
	case identifier.Class == 0 && identifier.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		rest, err := asn1.Unmarshal(identifier.FullBytes, &ias)
		if err != nil || len(rest) != 0 {
			return
		}
		r.IssuerAndSerial = &IssuerAndSerial{
			Issuer:       ias.IssuerName.FullBytes,
			SerialNumber: ias.SerialNumber,
		}
	case identifier.Class == 2 && identifier.Tag == 0:
		r.SubjectKeyID = identifier.Bytes
	}
}

func parseKeyTransRecipient(raw asn1.RawValue) (*recipientInfo, string, error) {
	var info recipientInfo
	rest, err := asn1.Unmarshal(raw.FullBytes, &info)
	if err != nil {
		return nil, fmt.Sprintf("malformed KeyTransRecipientInfo: %s", err), err
	}
	if len(rest) != 0 {
		return nil, "trailing data in KeyTransRecipientInfo", errors.New("pkcs7: trailing data in KeyTransRecipientInfo")
	}
	return &info, "", nil
}
