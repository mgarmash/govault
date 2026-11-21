package api

import (
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"time"
)

type CipherType int

const (
	CipherTypeLogin          CipherType = 1
	CipherTypeSecureNote     CipherType = 2
	CipherTypeCard           CipherType = 3
	CipherTypeIdentity       CipherType = 4
	CipherTypeSSHKey         CipherType = 5
	CipherTypeBankAccount    CipherType = 6
	CipherTypeDriversLicense CipherType = 7
	CipherTypePassport       CipherType = 8
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey"`
	KDF          int    `json:"Kdf"`
	KDFIters     int    `json:"KdfIterations"`
	KDFMemory    *int   `json:"KdfMemory"`
	KDFParallel  *int   `json:"KdfParallelism"`

	TwoFactorToken string `json:"TwoFactorToken"`
}

type SyncResponse struct {
	Profile  Profile                    `json:"profile"`
	Folders  []EncryptedFolder          `json:"folders"`
	Ciphers  []EncryptedCipher          `json:"ciphers"`
	Sends    json.RawMessage            `json:"sends,omitempty"`
	Policies json.RawMessage            `json:"policies,omitempty"`
	Extra    map[string]json.RawMessage `json:"-"`
}

func (s *SyncResponse) UnmarshalJSON(data []byte) error {
	type alias SyncResponse
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*s = SyncResponse(a)
	return nil
}

func (s SyncResponse) MarshalJSON() ([]byte, error) {
	type alias SyncResponse
	return marshalWithExtra(alias(s), s.Extra)
}

type Profile struct {
	ID          string                     `json:"id"`
	Email       string                     `json:"email"`
	Name        *string                    `json:"name,omitempty"`
	Key         string                     `json:"key"`
	PrivateKey  *string                    `json:"privateKey,omitempty"`
	KDF         int                        `json:"kdf"`
	KDFIters    int                        `json:"kdfIterations"`
	KDFMemory   *int                       `json:"kdfMemory,omitempty"`
	KDFParallel *int                       `json:"kdfParallelism,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	type alias Profile
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*p = Profile(a)
	return nil
}

func (p Profile) MarshalJSON() ([]byte, error) {
	type alias Profile
	return marshalWithExtra(alias(p), p.Extra)
}

type EncryptedFolder struct {
	ID           string                     `json:"id"`
	Name         string                     `json:"name"`
	RevisionDate *time.Time                 `json:"revisionDate,omitempty"`
	Extra        map[string]json.RawMessage `json:"-"`
}

func (f *EncryptedFolder) UnmarshalJSON(data []byte) error {
	type alias EncryptedFolder
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*f = EncryptedFolder(a)
	return nil
}

func (f EncryptedFolder) MarshalJSON() ([]byte, error) {
	type alias EncryptedFolder
	return marshalWithExtra(alias(f), f.Extra)
}

type EncryptedCipher struct {
	ID               string                     `json:"id"`
	Type             CipherType                 `json:"type"`
	FolderID         *string                    `json:"folderId"`
	OrganizationID   *string                    `json:"organizationId"`
	Favorite         bool                       `json:"favorite"`
	Reprompt         int                        `json:"reprompt"`
	Key              *string                    `json:"key,omitempty"`
	Name             string                     `json:"name"`
	Notes            *string                    `json:"notes"`
	RevisionDate     *time.Time                 `json:"revisionDate,omitempty"`
	CreationDate     *time.Time                 `json:"creationDate,omitempty"`
	DeletedDate      *time.Time                 `json:"deletedDate,omitempty"`
	ArchivedDate     *time.Time                 `json:"archivedDate,omitempty"`
	Login            *EncryptedLogin            `json:"login,omitempty"`
	SecureNote       *EncryptedSecureNote       `json:"secureNote,omitempty"`
	Card             *EncryptedCard             `json:"card,omitempty"`
	Identity         *EncryptedIdentity         `json:"identity,omitempty"`
	Fields           []EncryptedField           `json:"fields,omitempty"`
	PasswordHistory  []EncryptedPasswordHistory `json:"passwordHistory,omitempty"`
	Data             json.RawMessage            `json:"data,omitempty"`
	EncryptedFor     *string                    `json:"encryptedFor,omitempty"`
	EncryptedByKeyID *string                    `json:"encryptedByKeyId,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
}

func (c *EncryptedCipher) UnmarshalJSON(data []byte) error {
	type alias EncryptedCipher
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*c = EncryptedCipher(a)
	return nil
}

func (c EncryptedCipher) MarshalJSON() ([]byte, error) {
	type alias EncryptedCipher
	return marshalWithExtra(alias(c), c.Extra)
}

type CipherPayload struct {
	Type                  CipherType                 `json:"type"`
	FolderID              *string                    `json:"folderId"`
	OrganizationID        *string                    `json:"organizationId"`
	Favorite              bool                       `json:"favorite"`
	Reprompt              int                        `json:"reprompt"`
	Key                   *string                    `json:"key,omitempty"`
	Name                  string                     `json:"name"`
	Notes                 *string                    `json:"notes"`
	LastKnownRevisionDate *time.Time                 `json:"lastKnownRevisionDate,omitempty"`
	Login                 *EncryptedLogin            `json:"login,omitempty"`
	SecureNote            *EncryptedSecureNote       `json:"secureNote,omitempty"`
	Card                  *EncryptedCard             `json:"card,omitempty"`
	Identity              *EncryptedIdentity         `json:"identity,omitempty"`
	Fields                []EncryptedField           `json:"fields,omitempty"`
	PasswordHistory       []EncryptedPasswordHistory `json:"passwordHistory,omitempty"`
	Extra                 map[string]json.RawMessage `json:"-"`
}

func (p *CipherPayload) UnmarshalJSON(data []byte) error {
	type alias CipherPayload
	var a alias
	if err := unmarshalWithExtra(data, &a, &a.Extra); err != nil {
		return err
	}
	*p = CipherPayload(a)
	return nil
}

func (p CipherPayload) MarshalJSON() ([]byte, error) {
	type alias CipherPayload
	return marshalWithExtra(alias(p), p.Extra)
}

type EncryptedLogin struct {
	Username             *string             `json:"username"`
	Password             *string             `json:"password"`
	TOTP                 *string             `json:"totp"`
	URIs                 []EncryptedLoginURI `json:"uris,omitempty"`
	PasswordRevisionDate *time.Time          `json:"passwordRevisionDate,omitempty"`
}

type EncryptedLoginURI struct {
	URI   *string `json:"uri"`
	Match *int    `json:"match"`
}

type EncryptedSecureNote struct {
	Type int `json:"type"`
}

type EncryptedCard struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type EncryptedIdentity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

type EncryptedField struct {
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	Type     int     `json:"type"`
	LinkedID *int    `json:"linkedId,omitempty"`
}

type EncryptedPasswordHistory struct {
	Password     string    `json:"password"`
	LastUsedDate time.Time `json:"lastUsedDate"`
}

func unmarshalWithExtra(data []byte, dst any, extra *map[string]json.RawMessage) error {
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	t := reflect.TypeOf(dst).Elem()
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			delete(all, name)
		}
	}
	if len(all) > 0 {
		*extra = all
	}
	return nil
}

func marshalWithExtra(src any, extra map[string]json.RawMessage) ([]byte, error) {
	baseBytes, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	if merged == nil {
		merged = make(map[string]json.RawMessage, len(extra))
	}
	out := make(map[string]json.RawMessage, len(extra)+len(merged))
	maps.Copy(out, extra)
	maps.Copy(out, merged)
	return json.Marshal(out)
}
