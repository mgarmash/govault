// Package export reads and writes Bitwarden-compatible JSON vault exports,
// both plain and password protected, and plans imports that the user
// approves item by item.
package export

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// Vault is the plain Bitwarden JSON export: {"encrypted": false, ...}.
type Vault struct {
	Encrypted bool     `json:"encrypted"`
	Folders   []Folder `json:"folders"`
	Items     []Item   `json:"items"`
}

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Item struct {
	PasswordHistory []PasswordHistory `json:"passwordHistory"`
	RevisionDate    *time.Time        `json:"revisionDate"`
	CreationDate    *time.Time        `json:"creationDate"`
	DeletedDate     *time.Time        `json:"deletedDate"`
	ID              string            `json:"id"`
	OrganizationID  *string           `json:"organizationId"`
	FolderID        *string           `json:"folderId"`
	Type            api.CipherType    `json:"type"`
	Reprompt        int               `json:"reprompt"`
	Name            string            `json:"name"`
	Notes           *string           `json:"notes"`
	Favorite        bool              `json:"favorite"`
	Fields          []Field           `json:"fields,omitempty"`
	Login           *Login            `json:"login,omitempty"`
	SecureNote      *SecureNote       `json:"secureNote,omitempty"`
	Card            *Card             `json:"card,omitempty"`
	Identity        *Identity         `json:"identity,omitempty"`
	SSHKey          *SSHKey           `json:"sshKey,omitempty"`
	CollectionIDs   []string          `json:"collectionIds,omitempty"`
}

type PasswordHistory struct {
	LastUsedDate time.Time `json:"lastUsedDate"`
	Password     string    `json:"password"`
}

type Field struct {
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	Type     int     `json:"type"`
	LinkedID *int    `json:"linkedId"`
}

type Login struct {
	URIs     []URI   `json:"uris"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	TOTP     *string `json:"totp"`
}

type URI struct {
	Match *int    `json:"match"`
	URI   *string `json:"uri"`
}

type SecureNote struct {
	Type int `json:"type"`
}

type Card struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type Identity struct {
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

type SSHKey struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func val(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Build exports the active personal items and the folders, as a Bitwarden
// individual vault export does: organization items and Trash are left out.
func Build(ciphers []*state.Cipher, folders []state.Folder) *Vault {
	v := &Vault{Folders: []Folder{}, Items: []Item{}}
	for _, f := range folders {
		v.Folders = append(v.Folders, Folder{ID: f.ID, Name: f.Name})
	}
	slices.SortFunc(v.Folders, func(a, b Folder) int { return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil || (c.OrganizationID != nil && *c.OrganizationID != "") {
			continue
		}
		v.Items = append(v.Items, FromCipher(c))
	}
	slices.SortFunc(v.Items, func(a, b Item) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.ID, b.ID))
	})
	return v
}

func FromCipher(c *state.Cipher) Item {
	it := Item{
		RevisionDate: c.RevisionDate, CreationDate: c.CreationDate,
		ID: c.ID, FolderID: c.FolderID, Type: c.Type, Reprompt: c.Reprompt,
		Name: c.Name, Notes: opt(c.Notes), Favorite: c.Favorite,
	}
	for _, h := range c.PasswordHistory {
		it.PasswordHistory = append(it.PasswordHistory, PasswordHistory{LastUsedDate: h.LastUsedDate, Password: h.Password})
	}
	for _, f := range c.Fields {
		it.Fields = append(it.Fields, Field{Name: opt(f.Name), Value: opt(f.Value), Type: f.Type, LinkedID: f.LinkedID})
	}
	if l := c.Login; l != nil {
		out := &Login{URIs: []URI{}, Username: opt(l.Username), Password: opt(l.Password), TOTP: opt(l.TOTP)}
		for _, u := range l.URIs {
			out.URIs = append(out.URIs, URI{Match: u.Match, URI: opt(u.URI)})
		}
		it.Login = out
	}
	if c.SecureNote != nil {
		it.SecureNote = &SecureNote{Type: c.SecureNote.Type}
	}
	if k := c.Card; k != nil {
		it.Card = &Card{CardholderName: opt(k.CardholderName), Brand: opt(k.Brand), Number: opt(k.Number), ExpMonth: opt(k.ExpMonth), ExpYear: opt(k.ExpYear), Code: opt(k.Code)}
	}
	if i := c.Identity; i != nil {
		it.Identity = &Identity{
			Title: opt(i.Title), FirstName: opt(i.FirstName), MiddleName: opt(i.MiddleName), LastName: opt(i.LastName),
			Address1: opt(i.Address1), Address2: opt(i.Address2), Address3: opt(i.Address3), City: opt(i.City),
			State: opt(i.State), PostalCode: opt(i.PostalCode), Country: opt(i.Country), Company: opt(i.Company),
			Email: opt(i.Email), Phone: opt(i.Phone), SSN: opt(i.SSN), Username: opt(i.Username),
			PassportNumber: opt(i.PassportNumber), LicenseNumber: opt(i.LicenseNumber),
		}
	}
	if k := c.SSHKey; k != nil {
		it.SSHKey = &SSHKey{PrivateKey: k.PrivateKey, PublicKey: k.PublicKey, KeyFingerprint: k.KeyFingerprint}
	}
	return it
}

// content returns the item as a new personal cipher without an ID, folder,
// organization or dates; callers place it.
func (it Item) content() *state.Cipher {
	c := &state.Cipher{Type: it.Type, Reprompt: it.Reprompt, Name: it.Name, Notes: val(it.Notes), Favorite: it.Favorite}
	for _, h := range it.PasswordHistory {
		c.PasswordHistory = append(c.PasswordHistory, state.PasswordHistoryEntry{Password: h.Password, LastUsedDate: h.LastUsedDate})
	}
	applyContent(c, it)
	return c
}

// applyContent replaces the type-specific fields of c with those of it.
func applyContent(c *state.Cipher, it Item) {
	c.Login, c.SecureNote, c.Card, c.Identity, c.SSHKey, c.Fields = nil, nil, nil, nil, nil, nil
	for _, f := range it.Fields {
		c.Fields = append(c.Fields, state.CustomField{Name: val(f.Name), Value: val(f.Value), Type: f.Type, LinkedID: f.LinkedID})
	}
	if l := it.Login; l != nil {
		out := &state.Login{Username: val(l.Username), Password: val(l.Password), TOTP: val(l.TOTP)}
		for _, u := range l.URIs {
			if val(u.URI) != "" {
				out.URIs = append(out.URIs, state.LoginURI{URI: val(u.URI), Match: u.Match})
			}
		}
		c.Login = out
	}
	if it.SecureNote != nil || it.Type == api.CipherTypeSecureNote {
		c.SecureNote = &state.SecureNote{}
		if it.SecureNote != nil {
			c.SecureNote.Type = it.SecureNote.Type
		}
	}
	if k := it.Card; k != nil {
		c.Card = &state.Card{CardholderName: val(k.CardholderName), Brand: val(k.Brand), Number: val(k.Number), ExpMonth: val(k.ExpMonth), ExpYear: val(k.ExpYear), Code: val(k.Code)}
	}
	if i := it.Identity; i != nil {
		c.Identity = &state.Identity{
			Title: val(i.Title), FirstName: val(i.FirstName), MiddleName: val(i.MiddleName), LastName: val(i.LastName),
			Address1: val(i.Address1), Address2: val(i.Address2), Address3: val(i.Address3), City: val(i.City),
			State: val(i.State), PostalCode: val(i.PostalCode), Country: val(i.Country), Company: val(i.Company),
			Email: val(i.Email), Phone: val(i.Phone), SSN: val(i.SSN), Username: val(i.Username),
			PassportNumber: val(i.PassportNumber), LicenseNumber: val(i.LicenseNumber),
		}
	}
	if k := it.SSHKey; k != nil {
		c.SSHKey = &state.SSHKey{PrivateKey: k.PrivateKey, PublicKey: k.PublicKey, KeyFingerprint: k.KeyFingerprint}
	}
}
