package state

import "github.com/txchen/govault/internal/vaultcore/api"

// hidesPassword is the item's own viewPassword: false hides, and so does an
// organization item whose permissions the server did not state.
func hidesPassword(enc *api.EncryptedCipher) bool {
	if enc.ViewPassword == nil {
		return enc.OrganizationID != nil && *enc.OrganizationID != ""
	}
	return !*enc.ViewPassword
}

// EffectiveAccess is the access the user has to c, as every GoVault client
// computes it: read-only or with hidden passwords through the item's own
// flags, or through every collection of it that collection knows.
func EffectiveAccess(c *Cipher, collection func(id string) (Collection, bool)) (readOnly, hidePassword bool) {
	all := func(pred func(Collection) bool) bool {
		known := 0
		for _, id := range c.CollectionIDs {
			col, ok := collection(id)
			if !ok {
				continue
			}
			if !pred(col) {
				return false
			}
			known++
		}
		return known > 0
	}
	readOnly = c.ReadOnly || all(func(col Collection) bool { return col.ReadOnly })
	hidePassword = c.HidePassword || all(func(col Collection) bool { return col.HidePasswords })
	return readOnly, hidePassword
}

// CipherForWrite returns a copy of an item with its effective access in
// ReadOnly and HidePassword and every value kept, for a client that edits
// it and must keep what the user may not see.
func (s *Service) CipherForWrite(id string) (*Cipher, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil, ErrLocked
	}
	c, ok := s.ciphers[id]
	if !ok {
		return nil, ErrCipherNotFound
	}
	cp := cloneCipher(c)
	cp.ReadOnly, cp.HidePassword = s.effectiveAccessLocked(c)
	return cp, nil
}

func (s *Service) effectiveAccessLocked(c *Cipher) (readOnly, hide bool) {
	return EffectiveAccess(c, func(id string) (Collection, bool) {
		col, ok := s.collections[id]
		return col, ok
	})
}
