package api

import (
	"bytes"
	"encoding/json"
	"time"
)

// The nested parts of a cipher keep every field the server sends, known or
// not, in Extra, and send it back unchanged on save. A field GoVault does
// not model, such as login.autofillOnPageLoad or a field a newer server
// adds, therefore survives edits.

type EncryptedLogin struct {
	Username             *string                    `json:"username"`
	Password             *string                    `json:"password"`
	TOTP                 *string                    `json:"totp"`
	URIs                 []EncryptedLoginURI        `json:"uris,omitempty"`
	PasswordRevisionDate *time.Time                 `json:"passwordRevisionDate,omitempty"`
	Fido2Credentials     []EncryptedFido2Credential `json:"fido2Credentials,omitempty"`
	Extra                map[string]json.RawMessage `json:"-"`
}

func (l *EncryptedLogin) UnmarshalJSON(data []byte) error {
	type alias EncryptedLogin
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*l = EncryptedLogin(v)
	return nil
}

func (l EncryptedLogin) MarshalJSON() ([]byte, error) {
	type alias EncryptedLogin
	return marshalWithExtra(alias(l), l.Extra)
}

type EncryptedLoginURI struct {
	URI         *string                    `json:"uri"`
	Match       *int                       `json:"match"`
	URIChecksum *string                    `json:"uriChecksum,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

func (u *EncryptedLoginURI) UnmarshalJSON(data []byte) error {
	type alias EncryptedLoginURI
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*u = EncryptedLoginURI(v)
	return nil
}

func (u EncryptedLoginURI) MarshalJSON() ([]byte, error) {
	type alias EncryptedLoginURI
	return marshalWithExtra(alias(u), u.Extra)
}

// EncryptedFido2Credential is a passkey as the server stores it. Every
// field but creationDate is an EncString under the cipher key. Raw is the
// entry exactly as received and is what GoVault sends back, so a passkey
// it cannot create or use is never altered; the parsed fields are only read.
type EncryptedFido2Credential struct {
	Raw json.RawMessage

	CredentialID    *string
	KeyType         *string
	KeyAlgorithm    *string
	KeyCurve        *string
	KeyValue        *string
	RpID            *string
	UserHandle      *string
	UserName        *string
	Counter         *string
	RpName          *string
	UserDisplayName *string
	Discoverable    *string
	CreationDate    string
}

type fido2Fields struct {
	CredentialID    *string `json:"credentialId"`
	KeyType         *string `json:"keyType"`
	KeyAlgorithm    *string `json:"keyAlgorithm"`
	KeyCurve        *string `json:"keyCurve"`
	KeyValue        *string `json:"keyValue"`
	RpID            *string `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         *string `json:"counter"`
	RpName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    *string `json:"discoverable"`
	CreationDate    string  `json:"creationDate"`
}

func (f *EncryptedFido2Credential) UnmarshalJSON(data []byte) error {
	var v fido2Fields
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*f = EncryptedFido2Credential{
		Raw:          bytes.Clone(data),
		CredentialID: v.CredentialID, KeyType: v.KeyType, KeyAlgorithm: v.KeyAlgorithm,
		KeyCurve: v.KeyCurve, KeyValue: v.KeyValue, RpID: v.RpID, UserHandle: v.UserHandle,
		UserName: v.UserName, Counter: v.Counter, RpName: v.RpName,
		UserDisplayName: v.UserDisplayName, Discoverable: v.Discoverable, CreationDate: v.CreationDate,
	}
	return nil
}

// MarshalJSON sends Raw when the credential came from the server, and the
// fields otherwise (a passkey GoVault encrypted itself, such as one imported
// from a backup).
func (f EncryptedFido2Credential) MarshalJSON() ([]byte, error) {
	if len(f.Raw) > 0 {
		return f.Raw, nil
	}
	return json.Marshal(fido2Fields{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
		KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle,
		UserName: f.UserName, Counter: f.Counter, RpName: f.RpName,
		UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable, CreationDate: f.CreationDate,
	})
}

type EncryptedSecureNote struct {
	Type  int                        `json:"type"`
	Extra map[string]json.RawMessage `json:"-"`
}

func (n *EncryptedSecureNote) UnmarshalJSON(data []byte) error {
	type alias EncryptedSecureNote
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*n = EncryptedSecureNote(v)
	return nil
}

func (n EncryptedSecureNote) MarshalJSON() ([]byte, error) {
	type alias EncryptedSecureNote
	return marshalWithExtra(alias(n), n.Extra)
}

type EncryptedCard struct {
	CardholderName *string                    `json:"cardholderName"`
	Brand          *string                    `json:"brand"`
	Number         *string                    `json:"number"`
	ExpMonth       *string                    `json:"expMonth"`
	ExpYear        *string                    `json:"expYear"`
	Code           *string                    `json:"code"`
	Extra          map[string]json.RawMessage `json:"-"`
}

func (c *EncryptedCard) UnmarshalJSON(data []byte) error {
	type alias EncryptedCard
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*c = EncryptedCard(v)
	return nil
}

func (c EncryptedCard) MarshalJSON() ([]byte, error) {
	type alias EncryptedCard
	return marshalWithExtra(alias(c), c.Extra)
}

type EncryptedIdentity struct {
	Title          *string                    `json:"title"`
	FirstName      *string                    `json:"firstName"`
	MiddleName     *string                    `json:"middleName"`
	LastName       *string                    `json:"lastName"`
	Address1       *string                    `json:"address1"`
	Address2       *string                    `json:"address2"`
	Address3       *string                    `json:"address3"`
	City           *string                    `json:"city"`
	State          *string                    `json:"state"`
	PostalCode     *string                    `json:"postalCode"`
	Country        *string                    `json:"country"`
	Company        *string                    `json:"company"`
	Email          *string                    `json:"email"`
	Phone          *string                    `json:"phone"`
	SSN            *string                    `json:"ssn"`
	Username       *string                    `json:"username"`
	PassportNumber *string                    `json:"passportNumber"`
	LicenseNumber  *string                    `json:"licenseNumber"`
	Extra          map[string]json.RawMessage `json:"-"`
}

func (i *EncryptedIdentity) UnmarshalJSON(data []byte) error {
	type alias EncryptedIdentity
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*i = EncryptedIdentity(v)
	return nil
}

func (i EncryptedIdentity) MarshalJSON() ([]byte, error) {
	type alias EncryptedIdentity
	return marshalWithExtra(alias(i), i.Extra)
}

type EncryptedSSHKey struct {
	PrivateKey     *string                    `json:"privateKey"`
	PublicKey      *string                    `json:"publicKey"`
	KeyFingerprint *string                    `json:"keyFingerprint"`
	Extra          map[string]json.RawMessage `json:"-"`
}

func (k *EncryptedSSHKey) UnmarshalJSON(data []byte) error {
	type alias EncryptedSSHKey
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*k = EncryptedSSHKey(v)
	return nil
}

func (k EncryptedSSHKey) MarshalJSON() ([]byte, error) {
	type alias EncryptedSSHKey
	return marshalWithExtra(alias(k), k.Extra)
}

type EncryptedField struct {
	Name     *string                    `json:"name"`
	Value    *string                    `json:"value"`
	Type     int                        `json:"type"`
	LinkedID *int                       `json:"linkedId,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
}

func (f *EncryptedField) UnmarshalJSON(data []byte) error {
	type alias EncryptedField
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*f = EncryptedField(v)
	return nil
}

func (f EncryptedField) MarshalJSON() ([]byte, error) {
	type alias EncryptedField
	return marshalWithExtra(alias(f), f.Extra)
}

type EncryptedPasswordHistory struct {
	Password     string                     `json:"password"`
	LastUsedDate time.Time                  `json:"lastUsedDate"`
	Extra        map[string]json.RawMessage `json:"-"`
}

func (h *EncryptedPasswordHistory) UnmarshalJSON(data []byte) error {
	type alias EncryptedPasswordHistory
	var v alias
	if err := unmarshalWithExtra(data, &v, &v.Extra); err != nil {
		return err
	}
	*h = EncryptedPasswordHistory(v)
	return nil
}

func (h EncryptedPasswordHistory) MarshalJSON() ([]byte, error) {
	type alias EncryptedPasswordHistory
	return marshalWithExtra(alias(h), h.Extra)
}
