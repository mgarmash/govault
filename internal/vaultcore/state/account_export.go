package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// ErrForeignExport means an account-key export was made with another
// account's key.
var ErrForeignExport = errors.New("state: this export is encrypted with another account's key")

// PersonalEncrypted returns the vault's personal items outside Trash and
// its folders as the server stores them, encrypted, for an export that
// only this account can read.
func (v *VaultView) PersonalEncrypted() ([]api.EncryptedCipher, []api.EncryptedFolder) {
	var out []api.EncryptedCipher
	for _, c := range v.enc.Ciphers {
		if c.DeletedDate == nil && (c.OrganizationID == nil || *c.OrganizationID == "") && len(c.Data) == 0 {
			out = append(out, c)
		}
	}
	return out, v.enc.Folders
}

// ExportValidation encrypts a random value with the user key, which an
// account-key export carries so a reader can tell whether it has the key.
func (v *VaultView) ExportValidation() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return crypto.EncryptString(hex.EncodeToString(b[:]), v.userKey)
}

// OpenAccountExport decrypts the items and folders of an account-key
// export after checking its validation value opens with this account's
// key.
func (v *VaultView) OpenAccountExport(validation string, items []api.EncryptedCipher, folders []api.EncryptedFolder) ([]*Cipher, []Folder, error) {
	if _, err := crypto.DecryptString(validation, v.userKey); err != nil {
		return nil, nil, ErrForeignExport
	}
	ciphers := make([]*Cipher, 0, len(items))
	for i := range items {
		c, err := decryptCipher(&items[i], v.userKey)
		if err != nil {
			return nil, nil, err
		}
		ciphers = append(ciphers, c)
	}
	out := make([]Folder, 0, len(folders))
	for i := range folders {
		f, err := decryptFolder(&folders[i], v.userKey)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, f)
	}
	return ciphers, out, nil
}
