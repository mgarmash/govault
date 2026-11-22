package export

import (
	"errors"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// ErrTypeChange means an edit would change an item's type, which GoVault
// does not do: the old type's data would be lost.
var ErrTypeChange = errors.New("export: an item's type cannot be changed")

// NewCipher is a new item with the content of it, placed in its folder
// and, for an organization item, its organization and collections.
func NewCipher(it Item) (*state.Cipher, error) {
	if !it.savable() {
		return nil, ErrUnsupportedType
	}
	c := it.content()
	// Bitwarden clients give a new item the empty object of its type.
	switch {
	case it.Type == api.CipherTypeLogin && c.Login == nil:
		c.Login = &state.Login{}
	case it.Type == api.CipherTypeCard && c.Card == nil:
		c.Card = &state.Card{}
	case it.Type == api.CipherTypeIdentity && c.Identity == nil:
		c.Identity = &state.Identity{}
	case it.Type == api.CipherTypeSSHKey && c.SSHKey == nil:
		c.SSHKey = &state.SSHKey{}
	}
	if it.FolderID != nil && *it.FolderID != "" {
		c.FolderID = it.FolderID
	}
	if it.OrganizationID != nil && *it.OrganizationID != "" {
		c.OrganizationID = it.OrganizationID
		c.CollectionIDs = append([]string{}, it.CollectionIDs...)
	}
	return c, nil
}

// Edit lays it over cur as Bitwarden's CLI edit does: the name, notes,
// favorite, reprompt and folder are replaced, and so is each nested object
// it carries. Custom fields and password history are replaced only when it
// has them. What it does not describe is kept as mergeContent keeps it:
// fields the server stores that GoVault does not model, URI checksums and
// passkeys.
func Edit(cur *state.Cipher, it Item) error {
	if !it.savable() {
		return ErrUnsupportedType
	}
	if it.Type != cur.Type {
		return ErrTypeChange
	}
	if it.Fields == nil {
		it.Fields = FromCipher(cur).Fields
	}
	if it.PasswordHistory != nil {
		cur.PasswordHistory = make([]state.PasswordHistoryEntry, 0, len(it.PasswordHistory))
		for _, h := range it.PasswordHistory {
			cur.PasswordHistory = append(cur.PasswordHistory, state.PasswordHistoryEntry{Password: h.Password, LastUsedDate: h.LastUsedDate})
		}
	}
	cur.Name, cur.Notes, cur.Favorite, cur.Reprompt = it.Name, val(it.Notes), it.Favorite, it.Reprompt
	cur.FolderID = nil
	if it.FolderID != nil && *it.FolderID != "" {
		cur.FolderID = it.FolderID
	}
	return mergeContent(cur, it)
}

// IsSavableType reports whether GoVault can create and edit items of t.
func IsSavableType(t api.CipherType) bool { return Item{Type: t}.savable() }
