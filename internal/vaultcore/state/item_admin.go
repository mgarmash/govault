package state

import (
	"context"
	"errors"

	"github.com/txchen/govault/internal/vaultcore/api"
)

var (
	// ErrCipherChanged means the server's copy of an item is not the one
	// the change was confirmed for, so nothing was changed.
	ErrCipherChanged = errors.New("state: the item changed on the server; sync and try again")
	// ErrNotOrganizationItem means a collection change was asked of a
	// personal item.
	ErrNotOrganizationItem = errors.New("state: the item does not belong to an organization")
)

// DeleteCipherPermanently deletes an item for good, in or out of Trash,
// after checking, as EmptyTrash does, that the server still has it at the
// revision this vault shows and lets the user change it.
func (s *Service) DeleteCipherPermanently(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	local, err := o.editableCipher(id)
	if err != nil {
		return err
	}
	cur, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		return o.client.GetCipher(ctx, tok, id)
	})
	if errors.Is(err, api.ErrNotFound) {
		return ErrCipherNotFound
	}
	if err != nil {
		return err
	}
	if !sameTime(cur.RevisionDate, local.RevisionDate) || (cur.Edit != nil && !*cur.Edit) {
		return ErrCipherChanged
	}
	// The server deletes unconditionally: a change between the check and
	// the delete is still lost, as with Empty Trash.
	if _, err := withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.HardDeleteCipher(ctx, tok, id)
	}); err != nil {
		return err
	}
	err = o.removeCipher(id)
	s.notifyUpdated()
	return err
}

// SetCipherCollections sets the collections of an organization item. An
// item whose passwords are hidden from the user cannot be changed.
func (s *Service) SetCipherCollections(ctx context.Context, id string, collectionIDs []string) (*Cipher, error) {
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()
	s.mu.RLock()
	c, ok := s.ciphers[id]
	var org *string
	hidden := false
	if ok {
		org = cloneStringPtr(c.OrganizationID)
		hidden = s.effectiveHidePasswordLocked(c)
	}
	s.mu.RUnlock()
	switch {
	case !ok:
		return nil, ErrCipherNotFound
	case org == nil || *org == "":
		return nil, ErrNotOrganizationItem
	case hidden:
		return nil, ErrHiddenByOrganization
	}
	enc, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		return o.client.UpdateCipherCollections(ctx, tok, id, collectionIDs)
	})
	if err != nil {
		return nil, err
	}
	if enc == nil {
		// The user can no longer see the item.
		err := o.removeCipher(id)
		s.notifyUpdated()
		return nil, err
	}
	key, err := o.itemKey(enc.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(enc, key)
	if err != nil {
		return nil, err
	}
	if enc.CollectionIDs == nil {
		decrypted.CollectionIDs = append([]string{}, collectionIDs...)
	}
	return o.commitCipher(decrypted, enc)
}
