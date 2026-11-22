// Package export reads and writes Bitwarden-compatible JSON vault exports,
// both plain and password protected, and plans imports that the user
// approves item by item.
package export

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	URIs             []URI   `json:"uris"`
	Username         *string `json:"username"`
	Password         *string `json:"password"`
	TOTP             *string `json:"totp"`
	Fido2Credentials []Fido2 `json:"fido2Credentials"`
}

// Fido2 is a passkey as Bitwarden exports it (Fido2CredentialExport): every
// field in plaintext, inside the encryption of the export itself.
type Fido2 struct {
	CredentialID    string `json:"credentialId"`
	KeyType         string `json:"keyType"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyCurve        string `json:"keyCurve"`
	KeyValue        string `json:"keyValue"`
	RpID            string `json:"rpId"`
	UserHandle      string `json:"userHandle"`
	UserName        string `json:"userName"`
	Counter         string `json:"counter"`
	RpName          string `json:"rpName"`
	UserDisplayName string `json:"userDisplayName"`
	Discoverable    string `json:"discoverable"`
	CreationDate    string `json:"creationDate"`
}

func fido2FromState(f state.Fido2Credential) Fido2 {
	return Fido2{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm, KeyCurve: f.KeyCurve,
		KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle, UserName: f.UserName, Counter: f.Counter,
		RpName: f.RpName, UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable, CreationDate: f.CreationDate,
	}
}

// toState gives a passkey from a backup in plaintext; a save seals it under
// the key of the item it is saved to.
func (f Fido2) toState() state.Fido2Credential {
	return state.Fido2Credential{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm, KeyCurve: f.KeyCurve,
		KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle, UserName: f.UserName, Counter: f.Counter,
		RpName: f.RpName, UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable, CreationDate: f.CreationDate,
	}
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
//
// An item whose passkey does not fully decrypt fails the export with
// ErrUnreadablePasskey naming the item.
func Build(ciphers []*state.Cipher, folders []state.Folder) (*Vault, error) {
	v := &Vault{Folders: []Folder{}, Items: []Item{}}
	var errs []error
	for _, f := range folders {
		v.Folders = append(v.Folders, Folder{ID: f.ID, Name: f.Name})
	}
	slices.SortFunc(v.Folders, func(a, b Folder) int { return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil || (c.OrganizationID != nil && *c.OrganizationID != "") {
			continue
		}
		if c.Login != nil {
			for _, f := range c.Login.Fido2Credentials {
				if len(f.Unreadable) > 0 {
					errs = append(errs, fmt.Errorf("%w in %q (%s)", ErrUnreadablePasskey, c.Name, strings.Join(f.Unreadable, ", ")))
				}
			}
		}
		v.Items = append(v.Items, FromCipher(c))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	slices.SortFunc(v.Items, func(a, b Item) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.ID, b.ID))
	})
	return v, nil
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
		out := &Login{URIs: []URI{}, Username: opt(l.Username), Password: opt(l.Password), TOTP: opt(l.TOTP), Fido2Credentials: []Fido2{}}
		for _, u := range l.URIs {
			out.URIs = append(out.URIs, URI{Match: u.Match, URI: opt(u.URI)})
		}
		for _, f := range l.Fido2Credentials {
			out.Fido2Credentials = append(out.Fido2Credentials, fido2FromState(f))
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
	// A new cipher has no existing entries, so matching cannot fail.
	_ = mergeContent(c, it)
	return c
}

// mergeContent replaces the content of c with that of the backup item while
// keeping what the backup does not describe: unknown fields the server
// stores, URI checksums of unchanged URIs, and passkeys. An existing passkey
// is never removed; a backup passkey is only taken when c has none. A
// nested object the backup lacks is kept, never cleared.
//
// Each backup field or URI is matched to an existing one (see matchOld) to
// carry over what GoVault keeps for it. When that cannot be done without
// guessing, mergeContent returns ErrAmbiguousUpdate and c must not be saved.
func mergeContent(c *state.Cipher, it Item) error {
	want := make([]state.CustomField, len(it.Fields))
	for i, f := range it.Fields {
		want[i] = state.CustomField{Name: val(f.Name), Value: val(f.Value), Type: f.Type, LinkedID: f.LinkedID}
	}
	old := c.Fields
	picks, err := matchOld(len(want), len(old),
		func(i, j int) bool {
			return old[j].Name == want[i].Name && old[j].Type == want[i].Type && old[j].Value == want[i].Value && sameMatch(old[j].LinkedID, want[i].LinkedID)
		},
		func(i, j int) bool { return old[j].Name == want[i].Name && old[j].Type == want[i].Type },
		func(a, b int) bool {
			return sameRaw(old[a].Extra, old[b].Extra) && sameShape(old[a].Shape, old[b].Shape) && sameMatch(old[a].LinkedID, old[b].LinkedID)
		})
	if err != nil {
		return fmt.Errorf("%w (custom fields)", err)
	}
	for i, j := range picks {
		if j < 0 {
			continue
		}
		want[i].Extra, want[i].Shape = old[j].Extra, old[j].Shape
		if want[i].LinkedID == nil {
			want[i].LinkedID = old[j].LinkedID
		}
	}
	c.Fields = nil
	if len(want) > 0 {
		c.Fields = want
	}

	if l := it.Login; l != nil {
		out := &state.Login{}
		if c.Login != nil {
			cp := *c.Login
			out = &cp
		}
		out.Username, out.Password, out.TOTP = val(l.Username), val(l.Password), val(l.TOTP)
		prev := out.URIs
		var next []state.LoginURI
		for _, u := range l.URIs {
			if text := val(u.URI); text != "" {
				next = append(next, state.LoginURI{URI: text, Match: u.Match})
			}
		}
		full := func(i, j int) bool { return prev[j].URI == next[i].URI && sameMatch(prev[j].Match, next[i].Match) }
		picks, err := matchOld(len(next), len(prev), full, full, func(a, b int) bool {
			return sameRaw(prev[a].Extra, prev[b].Extra) && sameShape(prev[a].Shape, prev[b].Shape)
		})
		if err != nil {
			return fmt.Errorf("%w (websites)", err)
		}
		for i, j := range picks {
			if j >= 0 {
				p := prev[j]
				next[i].Checksum, next[i].ChecksumOf, next[i].Extra, next[i].Shape = p.Checksum, p.ChecksumOf, p.Extra, p.Shape
			}
		}
		out.URIs = next
		if len(out.Fido2Credentials) == 0 {
			for _, f := range l.Fido2Credentials {
				out.Fido2Credentials = append(out.Fido2Credentials, f.toState())
			}
		}
		c.Login = out
	}

	if it.SecureNote != nil || it.Type == api.CipherTypeSecureNote {
		sn := &state.SecureNote{}
		if c.SecureNote != nil {
			sn.Extra, sn.Shape = c.SecureNote.Extra, c.SecureNote.Shape
		}
		if it.SecureNote != nil {
			sn.Type = it.SecureNote.Type
		}
		c.SecureNote = sn
	}

	if k := it.Card; k != nil {
		out := &state.Card{}
		if c.Card != nil {
			out.Extra, out.Shape = c.Card.Extra, c.Card.Shape
		}
		out.CardholderName, out.Brand, out.Number = val(k.CardholderName), val(k.Brand), val(k.Number)
		out.ExpMonth, out.ExpYear, out.Code = val(k.ExpMonth), val(k.ExpYear), val(k.Code)
		c.Card = out
	}

	if i := it.Identity; i != nil {
		out := &state.Identity{
			Title: val(i.Title), FirstName: val(i.FirstName), MiddleName: val(i.MiddleName), LastName: val(i.LastName),
			Address1: val(i.Address1), Address2: val(i.Address2), Address3: val(i.Address3), City: val(i.City),
			State: val(i.State), PostalCode: val(i.PostalCode), Country: val(i.Country), Company: val(i.Company),
			Email: val(i.Email), Phone: val(i.Phone), SSN: val(i.SSN), Username: val(i.Username),
			PassportNumber: val(i.PassportNumber), LicenseNumber: val(i.LicenseNumber),
		}
		if c.Identity != nil {
			out.Extra, out.Shape = c.Identity.Extra, c.Identity.Shape
		}
		c.Identity = out
	}

	if k := it.SSHKey; k != nil {
		out := &state.SSHKey{PrivateKey: k.PrivateKey, PublicKey: k.PublicKey, KeyFingerprint: k.KeyFingerprint}
		if c.SSHKey != nil {
			out.Extra, out.Shape = c.SSHKey.Extra, c.SSHKey.Shape
		}
		c.SSHKey = out
	}
	return nil
}

// ErrAmbiguousUpdate means the backup item cannot be laid over the vault
// item without guessing which existing entry each backup entry is, and the
// entries hold different data the backup does not have. Update is not
// offered; Skip and Create Copy are.
var ErrAmbiguousUpdate = errors.New("export: cannot tell which existing entries the backup entries are")

// matchOld pairs each of n backup entries with at most one of m existing
// ones, returning the existing index per backup entry or -1.
//
// First every backup entry with exactly one unused full match (the same
// content) takes it. Then each remaining entry takes its only unused
// candidate: a full match, else a loose one (same name and type). Several
// candidates are told apart by position only when they hold identical
// hidden data (same reports that), since then picking either loses
// nothing; otherwise matchOld fails with ErrAmbiguousUpdate.
func matchOld(n, m int, full, loose func(i, j int) bool, same func(a, b int) bool) ([]int, error) {
	picks := make([]int, n)
	used := make([]bool, m)
	unused := func(i int, ok func(i, j int) bool) []int {
		var out []int
		for j := range m {
			if !used[j] && ok(i, j) {
				out = append(out, j)
			}
		}
		return out
	}
	for i := range n {
		picks[i] = -1
		if c := unused(i, full); len(c) == 1 {
			picks[i], used[c[0]] = c[0], true
		}
	}
	for i := range n {
		if picks[i] >= 0 {
			continue
		}
		cands := unused(i, full)
		if len(cands) == 0 {
			cands = unused(i, loose)
		}
		switch {
		case len(cands) == 0:
			continue
		case len(cands) > 1:
			for _, j := range cands[1:] {
				if !same(cands[0], j) {
					return nil, ErrAmbiguousUpdate
				}
			}
			if slices.Contains(cands, i) {
				cands[0] = i
			}
		}
		picks[i], used[cands[0]] = cands[0], true
	}
	return picks, nil
}

func sameRaw(a, b map[string]json.RawMessage) bool {
	return maps.EqualFunc(a, b, func(x, y json.RawMessage) bool { return bytes.Equal(x, y) })
}

func sameShape(a, b api.Shape) bool {
	return maps.EqualFunc(a, b, func(x, y api.Presence) bool {
		return x.Absent == y.Absent && bytes.Equal(x.Raw, y.Raw) && bytes.Equal(x.Zero, y.Zero)
	})
}

func sameMatch(a, b *int) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// complete reports whether the item has the nested object its type needs.
// An item without it cannot update a vault item: that would erase the
// vault item's login, card, identity or key.
func (it Item) complete() bool {
	switch it.Type {
	case api.CipherTypeLogin:
		return it.Login != nil
	case api.CipherTypeCard:
		return it.Card != nil
	case api.CipherTypeIdentity:
		return it.Identity != nil
	case api.CipherTypeSSHKey:
		return it.SSHKey != nil
	}
	return true
}

// ErrUnreadablePasskey means a passkey did not decrypt, so a backup of it
// would not work; the export is refused rather than written incomplete.
var ErrUnreadablePasskey = errors.New("export: a passkey could not be decrypted")
