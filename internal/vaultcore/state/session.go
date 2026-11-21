package state

import (
	"context"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

// op is one network operation bound to the session that started it. It keeps
// that session's client, account and keys, so a lock, logout or account
// switch in the meantime can never mix credentials or state across sessions.
type op struct {
	s         *Service
	gen       uint64
	ctx       context.Context
	release   context.CancelFunc
	client    *api.Client
	accountID string
	snap      *store.Snapshot
	userKey   *crypto.SymmetricKey
}

// startSessionLocked invalidates the previous session and begins a new one.
// The caller holds s.mu.
func (s *Service) startSessionLocked() {
	s.endSessionLocked()
	s.sessionCtx, s.sessionCancel = context.WithCancel(context.Background())
}

// endSessionLocked invalidates the current session: in-flight operations are
// cancelled and can no longer commit. The caller holds s.mu.
func (s *Service) endSessionLocked() {
	s.sessionGen++
	if s.sessionCancel != nil {
		s.sessionCancel()
	}
	s.sessionCtx, s.sessionCancel = nil, nil
	s.accessToken = ""
}

func (s *Service) beginOp(ctx context.Context) (*op, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked || s.userKey == nil || s.sessionCtx == nil {
		return nil, ErrLocked
	}
	if s.apiClient == nil || s.snapshot == nil {
		return nil, ErrLoggedOut
	}
	raw := s.userKey.Bytes()
	keyCopy, err := crypto.SymmetricKeyFromBytes(raw[:])
	crypto.ZeroBytes(raw[:])
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.sessionCtx, cancel)
	snapCopy := *s.snapshot
	return &op{
		s:         s,
		gen:       s.sessionGen,
		ctx:       opCtx,
		release:   func() { stop(); cancel() },
		client:    s.apiClient,
		accountID: s.accountID,
		snap:      &snapCopy,
		userKey:   keyCopy,
	}, nil
}

func (o *op) end() {
	o.userKey.Zero()
	o.release()
}

// currentLocked reports whether o's session is still the active, unlocked
// one. The caller holds s.mu.
func (o *op) currentLocked() bool {
	return o.s.sessionGen == o.gen && o.s.status == StatusUnlocked
}

func (o *op) current() bool {
	o.s.mu.RLock()
	defer o.s.mu.RUnlock()
	return o.currentLocked()
}

// saveSnapshot persists snap only while o's session is current. Snapshot
// writes and deletes are serialized, so a stale operation can never recreate
// a snapshot that logout removed.
func (o *op) saveSnapshot(snap *store.Snapshot) error {
	o.s.persistMu.Lock()
	defer o.s.persistMu.Unlock()
	if !o.current() {
		return ErrLocked
	}
	return o.s.cfg.Store.SaveSnapshot(snap)
}

func (o *op) accessToken() (string, error) {
	o.s.mu.RLock()
	tok, ok := o.s.accessToken, o.currentLocked()
	o.s.mu.RUnlock()
	if !ok {
		return "", ErrLocked
	}
	if tok != "" {
		return tok, nil
	}
	return o.refreshToken(o.ctx)
}

func (o *op) refreshToken(ctx context.Context) (string, error) {
	if !o.current() {
		return "", ErrLocked
	}
	if o.s.cfg.Secrets == nil {
		return "", api.ErrUnauthorized
	}
	refreshTok, ok, err := o.s.cfg.Secrets.Get(refreshTokenKeyPrefix + o.accountID)
	if err != nil {
		return "", err
	}
	if !ok || refreshTok == "" {
		return "", api.ErrUnauthorized
	}
	resp, err := o.client.RefreshToken(ctx, refreshTok)
	if err != nil {
		return "", err
	}

	// Keychain writes can be slow or interactive, so they run outside s.mu.
	// secretMu orders them with logout, which advances the session first.
	if resp.RefreshToken != "" {
		o.s.secretMu.Lock()
		if !o.current() {
			o.s.secretMu.Unlock()
			return "", ErrLocked
		}
		_ = o.s.cfg.Secrets.Set(refreshTokenKeyPrefix+o.accountID, resp.RefreshToken)
		o.s.secretMu.Unlock()
	}

	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if !o.currentLocked() {
		return "", ErrLocked
	}
	o.s.accessToken = resp.AccessToken
	return resp.AccessToken, nil
}

func withAuth[T any](o *op, fn func(ctx context.Context, token string) (T, error)) (T, error) {
	tok, err := o.accessToken()
	if err != nil {
		var zero T
		return zero, err
	}
	return api.DoWithRefresh(o.ctx, tok, o.refreshToken, func(t string) (T, error) { return fn(o.ctx, t) })
}

// itemKey returns a copy of the key that encrypts items owned by orgID, or
// of the user key for personal items.
func (o *op) itemKey(orgID *string) (*crypto.SymmetricKey, error) {
	var raw [64]byte
	defer crypto.ZeroBytes(raw[:])
	if orgID == nil || *orgID == "" {
		raw = o.userKey.Bytes()
		return crypto.SymmetricKeyFromBytes(raw[:])
	}
	o.s.mu.RLock()
	k := o.s.orgKeys[*orgID]
	ok := o.currentLocked()
	if k != nil && ok {
		raw = k.Bytes()
	}
	o.s.mu.RUnlock()
	if !ok {
		return nil, ErrLocked
	}
	if k == nil {
		return nil, ErrOrganizationKeyMissing
	}
	return crypto.SymmetricKeyFromBytes(raw[:])
}

// editableCipher returns a copy of the cipher with id after checking that the
// organization lets the user change it.
func (o *op) editableCipher(id string) (*Cipher, error) {
	o.s.mu.RLock()
	defer o.s.mu.RUnlock()
	if !o.currentLocked() {
		return nil, ErrLocked
	}
	c, ok := o.s.ciphers[id]
	if !ok {
		return nil, ErrCipherNotFound
	}
	if o.s.effectiveReadOnlyLocked(c) {
		return nil, ErrReadOnlyCipher
	}
	return cloneCipher(c), nil
}

// effectiveReadOnlyLocked reports whether c is read-only for the item itself
// or through every known collection it belongs to. The caller holds s.mu.
func (s *Service) effectiveReadOnlyLocked(c *Cipher) bool {
	return c.ReadOnly || s.allCollectionsLocked(c, func(col Collection) bool { return col.ReadOnly })
}

// effectiveHidePasswordLocked is effectiveReadOnlyLocked for hidePasswords.
func (s *Service) effectiveHidePasswordLocked(c *Cipher) bool {
	return c.HidePassword || s.allCollectionsLocked(c, func(col Collection) bool { return col.HidePasswords })
}

func (s *Service) allCollectionsLocked(c *Cipher, pred func(Collection) bool) bool {
	known := 0
	for _, id := range c.CollectionIDs {
		col, ok := s.collections[id]
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
