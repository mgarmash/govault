package state

import (
	"context"
	"encoding/json"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func (s *Service) DownloadAttachment(ctx context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return nil, "", err
	}
	defer userKey.Zero()

	c, att, err := s.lookupAttachment(cipherID, attachmentID)
	if err != nil {
		return nil, "", err
	}
	cipherKey, err := s.cipherKey(c, userKey)
	if err != nil {
		return nil, "", err
	}
	defer cipherKey.Zero()

	meta, err := withAuth(s, ctx, func(tok string) (*api.EncryptedAttachment, error) {
		return client.GetAttachment(ctx, tok, cipherID, attachmentID)
	})
	if err != nil {
		return nil, "", err
	}
	if meta.Key != nil && *meta.Key != "" {
		att.Key = meta.Key
	}
	encData, err := withAuth(s, ctx, func(tok string) ([]byte, error) {
		return client.DownloadAttachmentBytes(ctx, tok, meta.URL)
	})
	if err != nil {
		return nil, "", err
	}

	attKey, err := attachmentKey(att.Key, cipherKey)
	if err != nil {
		return nil, "", err
	}
	defer attKey.Zero()
	plain, err := crypto.DecryptBuffer(encData, attKey)
	if err != nil {
		return nil, "", err
	}
	return plain, att.FileName, nil
}

func (s *Service) UploadAttachment(ctx context.Context, cipherID, fileName string, plain []byte) (*Cipher, error) {
	if len(plain) > api.MaxAttachmentSize {
		return nil, api.ErrAttachmentTooLarge
	}
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return nil, err
	}
	defer userKey.Zero()

	c, err := s.GetCipher(cipherID)
	if err != nil {
		return nil, err
	}
	if c.ReadOnly {
		return nil, ErrReadOnlyCipher
	}
	cipherKey, err := s.cipherKey(c, userKey)
	if err != nil {
		return nil, err
	}
	defer cipherKey.Zero()

	attKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	defer attKey.Zero()
	rawAttKey := attKey.Bytes()
	encAttKey, err := crypto.EncryptBytes(rawAttKey[:], cipherKey)
	crypto.ZeroBytes(rawAttKey[:])
	if err != nil {
		return nil, err
	}
	encName, err := crypto.EncryptString(fileName, cipherKey)
	if err != nil {
		return nil, err
	}
	data, err := crypto.EncryptBuffer(plain, attKey)
	if err != nil {
		return nil, err
	}

	created, err := withAuth(s, ctx, func(tok string) (*api.AttachmentUploadResponse, error) {
		return client.CreateAttachmentV2(ctx, tok, cipherID, api.AttachmentUploadRequest{
			Key: encAttKey.String(), FileName: encName, FileSize: int64(len(data)),
		})
	})
	if err != nil {
		return nil, err
	}
	if created.FileUploadType != api.FileUploadTypeDirect {
		s.discardAttachment(ctx, client, cipherID, created.AttachmentID)
		return nil, ErrUnsupportedUpload
	}
	_, err = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.UploadAttachmentData(ctx, tok, cipherID, created.AttachmentID, encName, data)
	})
	if err != nil {
		s.discardAttachment(ctx, client, cipherID, created.AttachmentID)
		return nil, err
	}
	return s.refreshCipher(ctx, client, userKey, c, created.CipherResponse)
}

func (s *Service) DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (*Cipher, error) {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return nil, err
	}
	defer userKey.Zero()

	c, _, err := s.lookupAttachment(cipherID, attachmentID)
	if err != nil {
		return nil, err
	}
	if c.ReadOnly {
		return nil, ErrReadOnlyCipher
	}
	_, err = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.DeleteAttachment(ctx, tok, cipherID, attachmentID)
	})
	if err != nil {
		return nil, err
	}
	return s.refreshCipher(ctx, client, userKey, c, nil)
}

func (s *Service) discardAttachment(ctx context.Context, client *api.Client, cipherID, attachmentID string) {
	if attachmentID == "" {
		return
	}
	_, _ = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.DeleteAttachment(ctx, tok, cipherID, attachmentID)
	})
}

func (s *Service) lookupAttachment(cipherID, attachmentID string) (*Cipher, Attachment, error) {
	c, err := s.GetCipher(cipherID)
	if err != nil {
		return nil, Attachment{}, err
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			return c, a, nil
		}
	}
	return nil, Attachment{}, ErrAttachmentNotFound
}

// cipherKey returns a copy of the key that encrypts the fields of c.
func (s *Service) cipherKey(c *Cipher, userKey *crypto.SymmetricKey) (*crypto.SymmetricKey, error) {
	key, err := s.itemKey(c.OrganizationID, userKey)
	if err != nil {
		return nil, err
	}
	if c.Key == nil || *c.Key == "" {
		return key, nil
	}
	defer key.Zero()
	raw, err := decryptBytesFromString(*c.Key, key)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

func attachmentKey(encKey *string, cipherKey *crypto.SymmetricKey) (*crypto.SymmetricKey, error) {
	if encKey == nil || *encKey == "" {
		raw := cipherKey.Bytes()
		defer crypto.ZeroBytes(raw[:])
		return crypto.SymmetricKeyFromBytes(raw[:])
	}
	raw, err := decryptBytesFromString(*encKey, cipherKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

// refreshCipher reloads the cipher from the server, falling back to fallback,
// and stores it in memory and in the encrypted snapshot.
func (s *Service) refreshCipher(ctx context.Context, client *api.Client, userKey *crypto.SymmetricKey, prev *Cipher, fallback *api.EncryptedCipher) (*Cipher, error) {
	enc, err := withAuth(s, ctx, func(tok string) (*api.EncryptedCipher, error) {
		return client.GetCipher(ctx, tok, prev.ID)
	})
	if err != nil {
		if fallback == nil {
			return nil, err
		}
		enc = fallback
	}
	key, err := s.itemKey(enc.OrganizationID, userKey)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(enc, key)
	if err != nil {
		return nil, err
	}
	if len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), prev.CollectionIDs...)
	}

	s.mu.Lock()
	if s.status != StatusUnlocked {
		s.mu.Unlock()
		return nil, ErrLocked
	}
	s.ciphers[decrypted.ID] = decrypted
	s.mu.Unlock()

	s.storeSnapshotCipher(enc)
	s.notifyUpdated()
	return cloneCipher(decrypted), nil
}

func (s *Service) storeSnapshotCipher(enc *api.EncryptedCipher) {
	s.mu.RLock()
	snap := s.snapshot
	s.mu.RUnlock()
	if snap == nil {
		return
	}
	var resp api.SyncResponse
	if err := json.Unmarshal(snap.RawSyncJSON, &resp); err != nil {
		return
	}
	replaced := false
	for i := range resp.Ciphers {
		if resp.Ciphers[i].ID == enc.ID {
			if len(enc.CollectionIDs) == 0 {
				enc.CollectionIDs = resp.Ciphers[i].CollectionIDs
			}
			resp.Ciphers[i] = *enc
			replaced = true
		}
	}
	if !replaced {
		resp.Ciphers = append(resp.Ciphers, *enc)
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	updated := *snap
	updated.RawSyncJSON = raw
	if err := s.cfg.Store.SaveSnapshot(&updated); err != nil {
		return
	}
	s.mu.Lock()
	if s.snapshot == snap {
		s.snapshot = &updated
	}
	s.mu.Unlock()
}
