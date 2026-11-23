package state

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// VaultView is a read-only, decrypted copy of a sync snapshot for clients
// that open the vault once per invocation, such as the gv command. It keeps
// the keys it needs for attachments to itself; Close wipes them.
type VaultView struct {
	Profile       ViewProfile
	Ciphers       []*Cipher
	Folders       []Folder
	Collections   []ViewCollection
	Organizations []ViewOrganization
	Policies      []Policy
	// Unreadable lists the IDs of personal items GoVault cannot read, which
	// a complete export cannot leave out.
	Unreadable []string

	typeData map[string]map[string]any
	enc      *api.SyncResponse
	userKey  *crypto.SymmetricKey
	orgKeys  map[string]*crypto.SymmetricKey
}

// ViewProfile is the signed-in user.
type ViewProfile struct {
	ID      string
	Email   string
	Premium bool
}

// ViewCollection is a collection as the server describes it.
type ViewCollection struct {
	Collection
	ExternalID *string
}

// ViewOrganization is a membership from the profile, with or without a
// usable key.
type ViewOrganization struct {
	ID      string
	Name    string
	Status  int
	Type    int
	Enabled bool
	// CanViewAllCollections: an owner or admin, or a custom role that may
	// edit or delete any collection.
	CanViewAllCollections bool
}

// Policy is an organization policy from the sync.
type Policy struct {
	OrganizationID string
	Type           int
	Enabled        bool
	Data           json.RawMessage
}

// Organization user types.
const (
	OrgUserOwner  = 0
	OrgUserAdmin  = 1
	OrgUserCustom = 4
)

// OpenVault decrypts a raw sync response with userKey, keeping the
// server's order. Items that do not decrypt are left out, as Bitwarden's
// clients do, and personal ones are named in Unreadable. ReadOnly and
// HidePassword are each item's effective access (EffectiveAccess).
func OpenVault(rawSync []byte, userKey *crypto.SymmetricKey) (*VaultView, error) {
	if userKey == nil {
		return nil, crypto.ErrInvalidKeyLength
	}
	var resp api.SyncResponse
	if err := json.Unmarshal(rawSync, &resp); err != nil {
		return nil, err
	}
	raw := userKey.Bytes()
	ownKey, err := crypto.SymmetricKeyFromBytes(raw[:])
	crypto.ZeroBytes(raw[:])
	if err != nil {
		return nil, err
	}
	data, err := decryptSyncResponse(&resp, ownKey)
	if err != nil {
		ownKey.Zero()
		return nil, err
	}
	v := &VaultView{
		Profile: ViewProfile{
			ID:      resp.Profile.ID,
			Email:   resp.Profile.Email,
			Premium: data.premium,
		},
		Unreadable: data.unreadable,
		typeData:   map[string]map[string]any{},
		enc:        &resp,
		userKey:    ownKey,
		orgKeys:    data.orgKeys,
	}
	for i := range resp.Ciphers {
		enc := &resp.Ciphers[i]
		c := data.ciphers[enc.ID]
		if c == nil {
			continue
		}
		if field := typeDataField(enc.Type); field != "" {
			obj, err := v.decryptTypeData(c, enc.Extra[field])
			switch {
			case err != nil && (c.OrganizationID == nil || *c.OrganizationID == ""):
				// The item reads, but its body does not: an export
				// would lose it.
				v.Unreadable = append(v.Unreadable, c.ID)
			case err == nil && obj != nil:
				v.typeData[c.ID] = obj
			}
		}
		v.Ciphers = append(v.Ciphers, c)
	}
	for _, f := range resp.Folders {
		if folder, ok := data.folders[f.ID]; ok {
			v.Folders = append(v.Folders, folder)
		}
	}
	v.Collections = v.DecryptCollections(resp.Collections)
	cols := map[string]Collection{}
	for _, col := range v.Collections {
		cols[col.ID] = col.Collection
	}
	for _, c := range v.Ciphers {
		c.ReadOnly, c.HidePassword = EffectiveAccess(c, func(id string) (Collection, bool) {
			col, ok := cols[id]
			return col, ok
		})
	}
	for _, o := range resp.Profile.Organizations {
		v.Organizations = append(v.Organizations, viewOrganization(o))
	}
	v.Policies = parsePolicies(resp.Policies)
	return v, nil
}

func viewOrganization(o api.ProfileOrganization) ViewOrganization {
	var perms struct {
		EditAnyCollection   bool `json:"editAnyCollection"`
		DeleteAnyCollection bool `json:"deleteAnyCollection"`
	}
	_ = json.Unmarshal(o.Extra["permissions"], &perms)
	return ViewOrganization{
		ID: o.ID, Name: o.Name, Status: o.Status, Type: o.Type, Enabled: o.Enabled,
		CanViewAllCollections: o.Type == OrgUserOwner || o.Type == OrgUserAdmin || perms.EditAnyCollection || perms.DeleteAnyCollection,
	}
}

func parsePolicies(raw json.RawMessage) []Policy {
	var list []struct {
		OrganizationID string          `json:"organizationId"`
		Type           int             `json:"type"`
		Enabled        bool            `json:"enabled"`
		Data           json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]Policy, 0, len(list))
	for _, p := range list {
		out = append(out, Policy{OrganizationID: p.OrganizationID, Type: p.Type, Enabled: p.Enabled, Data: p.Data})
	}
	return out
}

// PublicKey derives the user's RSA public key (SPKI DER) from the private
// key the sync holds, or returns nil when the account has none.
func (v *VaultView) PublicKey() []byte {
	wrapped := wrappedPrivateKey(&v.enc.Profile)
	if wrapped == "" {
		return nil
	}
	priv, err := crypto.DecryptPrivateKey(wrapped, v.userKey)
	if err != nil {
		return nil
	}
	defer crypto.ZeroPrivateKey(priv)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return der
}

// Close wipes the view's keys.
func (v *VaultView) Close() {
	if v == nil {
		return
	}
	v.userKey.Zero()
	for _, k := range v.orgKeys {
		k.Zero()
	}
	clear(v.orgKeys)
}

// DecryptCollections decrypts collections with the organization keys of
// the view, leaving out those it has no key for.
func (v *VaultView) DecryptCollections(enc []api.EncryptedCollection) []ViewCollection {
	out := make([]ViewCollection, 0, len(enc))
	for _, col := range enc {
		key := v.orgKeys[col.OrganizationID]
		if key == nil {
			continue
		}
		name, err := crypto.DecryptString(col.Name, key)
		if err != nil {
			continue
		}
		out = append(out, ViewCollection{
			Collection: Collection{ID: col.ID, OrganizationID: col.OrganizationID, Name: name, ReadOnly: col.ReadOnly, HidePasswords: col.HidePasswords, Manage: col.Manage},
			ExternalID: col.ExternalID,
		})
	}
	return out
}

// TypeData is the decrypted body of an item of a type GoVault has no
// model for (bank account, driver's license, passport), or nil.
func (v *VaultView) TypeData(cipherID string) map[string]any { return v.typeData[cipherID] }

func typeDataField(t api.CipherType) string {
	switch t {
	case api.CipherTypeBankAccount:
		return "bankAccount"
	case api.CipherTypeDriversLicense:
		return "driversLicense"
	case api.CipherTypePassport:
		return "passport"
	}
	return ""
}

// decryptTypeData decrypts every encrypted string of a flat type object.
func (v *VaultView) decryptTypeData(c *Cipher, raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	key, err := v.cipherKey(c)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	for name, val := range fields {
		s, ok := val.(string)
		if !ok || crypto.ClassifyEncString(s) != crypto.IsEncString {
			continue
		}
		plain, err := crypto.DecryptString(s, key)
		if err != nil {
			return nil, err
		}
		fields[name] = plain
	}
	return fields, nil
}

// cipherKey returns a copy of the key that encrypts c's fields.
func (v *VaultView) cipherKey(c *Cipher) (*crypto.SymmetricKey, error) {
	base := v.userKey
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		if base = v.orgKeys[*c.OrganizationID]; base == nil {
			return nil, ErrOrganizationKeyMissing
		}
	}
	if c.Key == nil || *c.Key == "" {
		raw := base.Bytes()
		defer crypto.ZeroBytes(raw[:])
		return crypto.SymmetricKeyFromBytes(raw[:])
	}
	raw, err := decryptBytesFromString(*c.Key, base)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

// AttachmentSource fetches an attachment for DownloadAttachment.
type AttachmentSource interface {
	// Metadata returns the server's current record of the attachment,
	// with a download URL; api.ErrNotFound when the server has no such
	// endpoint or record.
	Metadata(ctx context.Context, cipherID, attachmentID string) (*api.EncryptedAttachment, error)
	// Download fetches the encrypted bytes at url.
	Download(ctx context.Context, url string) ([]byte, error)
}

// DownloadAttachment fetches, authenticates and decrypts an attachment of
// c. Hidden passwords forbid it.
func (v *VaultView) DownloadAttachment(ctx context.Context, src AttachmentSource, c *Cipher, attachmentID string) ([]byte, error) {
	if c.HidePassword {
		return nil, ErrHiddenByOrganization
	}
	var att *Attachment
	for i := range c.Attachments {
		if c.Attachments[i].ID == attachmentID {
			att = &c.Attachments[i]
		}
	}
	if att == nil {
		return nil, ErrAttachmentNotFound
	}
	url, encKey := att.URL, att.Key
	meta, err := src.Metadata(ctx, c.ID, attachmentID)
	switch {
	case err == nil:
		url = meta.URL
		if meta.Key != nil && *meta.Key != "" {
			encKey = meta.Key
		}
	case !errors.Is(err, api.ErrNotFound):
		return nil, err
	}
	if url == "" {
		return nil, fmt.Errorf("state: attachment %s has no download URL", attachmentID)
	}
	data, err := src.Download(ctx, url)
	if err != nil {
		return nil, err
	}
	cipherKey, err := v.cipherKey(c)
	if err != nil {
		return nil, err
	}
	defer cipherKey.Zero()
	attKey, err := attachmentKey(encKey, cipherKey)
	if err != nil {
		return nil, err
	}
	defer attKey.Zero()
	return crypto.DecryptBuffer(data, attKey)
}
