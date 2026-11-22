package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/realtime"
	"github.com/txchen/govault/internal/vaultcore/store"
)

const (
	refreshTokenKeyPrefix = "refresh_token:"
	userKeyPrefix         = "userkey:"

	twoFactorRememberPrefix = "twofactor_remember:"
)

type ServiceConfig struct {
	Store             store.Store
	Secrets           store.SecretStore
	AccountID         string
	DeviceID          string
	DeviceName        string
	DeviceType        int
	HTTPClient        *http.Client
	NewRealtimeClient func(serverURL string) (realtime.Client, error)
	OnStatusChange    func(LockStatus)
	OnVaultUpdated    func()
}

type Service struct {
	cfg ServiceConfig

	mu             sync.RWMutex
	status         LockStatus
	accountID      string
	snapshot       *store.Snapshot
	apiClient      *api.Client
	accessToken    string
	userKey        *crypto.SymmetricKey
	ciphers        map[string]*Cipher
	folders        map[string]Folder
	orgs           map[string]Organization
	collections    map[string]Collection
	orgKeys        map[string]*crypto.SymmetricKey
	realtimeCancel context.CancelFunc

	sessionGen    uint64
	sessionCtx    context.Context
	sessionCancel context.CancelFunc
	persistMu     sync.Mutex
	secretMu      sync.Mutex
}

var _ VaultService = (*Service)(nil)

func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("state: Store is required")
	}
	s := &Service{
		cfg:       cfg,
		status:    StatusLoggedOut,
		accountID: cfg.AccountID,
	}
	if cfg.AccountID != "" {
		if snap, err := cfg.Store.LoadSnapshot(cfg.AccountID); err == nil {
			s.snapshot = snap
			s.status = StatusLocked
		}
	}
	return s, nil
}

func (s *Service) Status() LockStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Service) Login(ctx context.Context, req LoginRequest) error {
	serverURL, email := req.ServerURL, req.Email
	client, kdfCfg, masterKey, pwHash, err := s.prepareLogin(ctx, req)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	rememberKey := twoFactorRememberKey(serverURL, email)
	var twoFactor *api.TwoFactorLogin
	usedRemembered := false
	if code := strings.TrimSpace(req.TwoFactorCode); code != "" {
		twoFactor = &api.TwoFactorLogin{Provider: req.TwoFactorProvider, Token: code, Remember: req.RememberDevice}
	} else if s.cfg.Secrets != nil {
		if remembered, ok, _ := s.cfg.Secrets.Get(rememberKey); ok && remembered != "" {
			twoFactor = &api.TwoFactorLogin{Provider: api.TwoFactorRemember, Token: remembered}
			usedRemembered = true
		}
	}

	tok, err := client.LoginPassword(ctx, email, pwHash, twoFactor)
	if err != nil {
		if usedRemembered && errors.Is(err, api.ErrTwoFactorRequired) {
			_ = s.cfg.Secrets.Delete(rememberKey)
		}
		return err
	}

	userKey, err := crypto.DecryptUserKey(tok.Key, masterKey)
	if err != nil {
		return err
	}

	syncResp, rawSync, err := client.Sync(ctx, tok.AccessToken)
	if err != nil {
		userKey.Zero()
		return err
	}

	data, err := decryptSyncResponse(syncResp, userKey)
	if err != nil {
		userKey.Zero()
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	accountID := syncResp.Profile.ID
	if accountID == "" {
		accountID = crypto.NormalizeEmail(email)
	}
	revDate, _ := client.RevisionDate(ctx, tok.AccessToken)
	snap := &store.Snapshot{
		SchemaVersion: store.CurrentSchemaVersion,
		AccountID:     accountID,
		ServerURL:     strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		Email:         crypto.NormalizeEmail(email),
		KDF:           kdfCfg,
		ProtectedKey:  tok.Key,
		RevisionDate:  revDate,
		LastSyncAt:    time.Now().UTC(),
		RawSyncJSON:   rawSync,
	}
	if err := s.cfg.Store.SaveSnapshot(snap); err != nil {
		userKey.Zero()
		return err
	}
	if s.cfg.Secrets != nil && tok.RefreshToken != "" {
		if err := s.cfg.Secrets.Set(refreshTokenKeyPrefix+accountID, tok.RefreshToken); err != nil {
			userKey.Zero()
			return err
		}
	}
	if s.cfg.Secrets != nil && tok.TwoFactorToken != "" {
		_ = s.cfg.Secrets.Set(rememberKey, tok.TwoFactorToken)
	}

	s.mu.Lock()
	s.stopRealtimeLocked()
	s.startSessionLocked()
	if s.userKey != nil {
		s.userKey.Zero()
	}
	s.accountID = accountID
	s.snapshot = snap
	s.apiClient = client
	s.accessToken = tok.AccessToken
	s.userKey = userKey
	s.applyDataLocked(data)
	committed = true
	s.status = StatusUnlocked
	s.mu.Unlock()

	s.notifyStatus(StatusUnlocked)
	s.notifyUpdated()
	return nil
}

func (s *Service) SendEmailTwoFactorCode(ctx context.Context, req LoginRequest) error {
	client, _, masterKey, pwHash, err := s.prepareLogin(ctx, req)
	if err != nil {
		return err
	}
	crypto.ZeroBytes(masterKey[:])
	return client.SendEmailTwoFactorLogin(ctx, req.Email, pwHash)
}

func (s *Service) prepareLogin(ctx context.Context, req LoginRequest) (*api.Client, crypto.KDFConfig, [32]byte, string, error) {
	client, err := s.newAPIClient(req.ServerURL)
	if err != nil {
		return nil, crypto.KDFConfig{}, [32]byte{}, "", err
	}
	kdfCfg, err := client.Prelogin(ctx, req.Email)
	if err != nil {
		return nil, kdfCfg, [32]byte{}, "", err
	}
	masterKey, err := crypto.DeriveMasterKey(req.MasterPassword, req.Email, kdfCfg)
	if err != nil {
		return nil, kdfCfg, [32]byte{}, "", err
	}
	return client, kdfCfg, masterKey, crypto.HashMasterPasswordForServer(masterKey, req.MasterPassword), nil
}

func twoFactorRememberKey(serverURL, email string) string {
	return twoFactorRememberPrefix + strings.TrimRight(strings.TrimSpace(serverURL), "/") + "|" + crypto.NormalizeEmail(email)
}

func (s *Service) UnlockWithPassword(ctx context.Context, masterPassword []byte) error {
	snap, err := s.loadCurrentSnapshot()
	if err != nil {
		return err
	}

	masterKey, err := crypto.DeriveMasterKey(masterPassword, snap.Email, snap.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, masterKey)
	if err != nil {
		return err
	}
	defer userKey.Zero()

	return s.UnlockWithUserKey(ctx, userKey)
}

func (s *Service) UnlockWithUserKey(ctx context.Context, userKey *crypto.SymmetricKey) error {
	if userKey == nil {
		return crypto.ErrInvalidKeyLength
	}
	snap, err := s.loadCurrentSnapshot()
	if err != nil {
		return err
	}

	var syncResp api.SyncResponse
	if err := json.Unmarshal(snap.RawSyncJSON, &syncResp); err != nil {
		return err
	}

	ownedBytes := userKey.Bytes()
	ownedKey, err := crypto.SymmetricKeyFromBytes(ownedBytes[:])
	crypto.ZeroBytes(ownedBytes[:])
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(&syncResp, ownedKey)
	if err != nil {
		ownedKey.Zero()
		return err
	}

	var client *api.Client
	if snap.ServerURL != "" {
		client, err = s.newAPIClient(snap.ServerURL)
		if err != nil {
			ownedKey.Zero()
			data.zero()
			return err
		}
	}

	s.mu.Lock()
	s.stopRealtimeLocked()
	s.startSessionLocked()
	if s.userKey != nil {
		s.userKey.Zero()
	}
	s.accountID = snap.AccountID
	s.snapshot = snap
	s.apiClient = client
	s.userKey = ownedKey
	s.applyDataLocked(data)
	s.status = StatusUnlocked
	s.mu.Unlock()

	s.notifyStatus(StatusUnlocked)
	s.notifyUpdated()
	return nil
}

func (s *Service) EnableBiometricUnlock(secrets store.SecretStore) error {
	if secrets == nil {
		return ErrInvalidSecretStore
	}
	s.mu.RLock()
	if s.status != StatusUnlocked || s.userKey == nil {
		s.mu.RUnlock()
		return ErrLocked
	}
	accountID := s.accountID
	raw := s.userKey.Bytes()
	s.mu.RUnlock()
	defer crypto.ZeroBytes(raw[:])

	return secrets.Set(userKeyPrefix+accountID, base64.StdEncoding.EncodeToString(raw[:]))
}

func (s *Service) DisableBiometricUnlock(secrets store.SecretStore) error {
	if secrets == nil {
		return ErrInvalidSecretStore
	}
	s.mu.RLock()
	accountID := s.accountID
	s.mu.RUnlock()
	if accountID == "" {
		return ErrLoggedOut
	}
	return secrets.Delete(userKeyPrefix + accountID)
}

func (s *Service) Lock() {
	s.mu.Lock()
	s.endSessionLocked()
	s.stopRealtimeLocked()
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	nextStatus := s.status
	if s.status == StatusUnlocked {
		if s.snapshot != nil || s.accountID != "" {
			s.status = StatusLocked
		} else {
			s.status = StatusLoggedOut
		}
		nextStatus = s.status
	}
	s.mu.Unlock()

	s.notifyStatus(nextStatus)
}

// Logout ends the session and clears memory first, so observers can revoke
// derived secrets before the slower snapshot and keychain deletion.
func (s *Service) Logout(ctx context.Context, secrets store.SecretStore) error {
	return s.logout(secrets, nil)
}

// logoutIfSession logs out only while gen is still the active session, so a
// delayed event from an earlier session cannot end a later one.
func (s *Service) logoutIfSession(gen uint64, secrets store.SecretStore) error {
	return s.logout(secrets, &gen)
}

func (s *Service) logout(secrets store.SecretStore, gen *uint64) error {
	s.mu.Lock()
	if gen != nil && (s.sessionGen != *gen || s.sessionCtx == nil) {
		s.mu.Unlock()
		return nil
	}
	s.endSessionLocked()
	s.stopRealtimeLocked()
	accountID := s.accountID
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	s.snapshot = nil
	s.apiClient = nil
	s.accountID = ""
	s.status = StatusLoggedOut
	s.mu.Unlock()

	s.notifyStatus(StatusLoggedOut)
	if accountID == "" {
		return nil
	}

	var errs []error
	s.persistMu.Lock()
	if err := s.cfg.Store.DeleteSnapshot(accountID); err != nil && !errors.Is(err, store.ErrSnapshotNotFound) {
		errs = append(errs, err)
	}
	s.persistMu.Unlock()
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	stores := []store.SecretStore{secrets}
	if s.cfg.Secrets != nil && s.cfg.Secrets != secrets {
		stores = append(stores, s.cfg.Secrets)
	}
	for _, sec := range stores {
		if sec == nil {
			continue
		}
		for _, key := range []string{refreshTokenKeyPrefix + accountID, userKeyPrefix + accountID} {
			if err := sec.Delete(key); err != nil {
				errs = append(errs, fmt.Errorf("state: delete %s: %w", strings.TrimSuffix(key, accountID), err))
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Service) SyncNow(ctx context.Context) error {
	return s.sync(ctx, false)
}

func (s *Service) forceSync(ctx context.Context) error {
	return s.sync(ctx, true)
}

func (s *Service) sync(ctx context.Context, force bool) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()

	revDate, revErr := withAuth(o, func(ctx context.Context, tok string) (time.Time, error) {
		return o.client.RevisionDate(ctx, tok)
	})
	if !force && revErr == nil && !o.snap.RevisionDate.IsZero() && revDate.Equal(o.snap.RevisionDate) {
		return nil
	}

	type syncResult struct {
		resp *api.SyncResponse
		raw  []byte
	}
	res, err := withAuth(o, func(ctx context.Context, tok string) (syncResult, error) {
		resp, raw, err := o.client.Sync(ctx, tok)
		return syncResult{resp: resp, raw: raw}, err
	})
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(res.resp, o.userKey)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	updatedSnap := *o.snap
	if !revDate.IsZero() {
		updatedSnap.RevisionDate = revDate
	}
	if res.resp.Profile.Key != "" {
		updatedSnap.ProtectedKey = res.resp.Profile.Key
	}
	updatedSnap.LastSyncAt = time.Now().UTC()
	updatedSnap.RawSyncJSON = res.raw
	if err := o.saveSnapshot(&updatedSnap); err != nil {
		return err
	}

	s.mu.Lock()
	if !o.currentLocked() {
		s.mu.Unlock()
		return ErrLocked
	}
	s.snapshot = &updatedSnap
	s.applyDataLocked(data)
	committed = true
	s.mu.Unlock()

	s.notifyUpdated()
	return nil
}

func (s *Service) StartRealtime(ctx context.Context) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	o.userKey.Zero()
	serverURL := o.snap.ServerURL

	s.mu.Lock()
	if !o.currentLocked() {
		s.mu.Unlock()
		o.release()
		return ErrLocked
	}
	s.stopRealtimeLocked()
	s.realtimeCancel = o.release
	s.mu.Unlock()

	var rtClient realtime.Client
	if s.cfg.NewRealtimeClient != nil {
		rtClient, err = s.cfg.NewRealtimeClient(serverURL)
	} else {
		rtClient, err = realtime.NewClient(realtime.Config{
			ServerURL:  serverURL,
			HTTPClient: s.cfg.HTTPClient,
		})
	}
	if err != nil {
		o.release()
		return err
	}

	go func() {
		_ = rtClient.Run(o.ctx, o.accessToken, func(ev realtime.Event) {
			_ = s.handleRealtimeEvent(o.ctx, o.gen, ev)
		})
	}()
	return nil
}

// HandleRealtimeEvent applies ev to the current session.
func (s *Service) HandleRealtimeEvent(ctx context.Context, ev realtime.Event) error {
	s.mu.RLock()
	gen := s.sessionGen
	s.mu.RUnlock()
	return s.handleRealtimeEvent(ctx, gen, ev)
}

// handleRealtimeEvent applies ev only while gen, the session whose stream
// delivered it, is still active.
func (s *Service) handleRealtimeEvent(ctx context.Context, gen uint64, ev realtime.Event) error {
	if ev.Type == realtime.LogOut {
		return s.logoutIfSession(gen, s.cfg.Secrets)
	}
	s.mu.RLock()
	stale := s.sessionGen != gen
	s.mu.RUnlock()
	if stale {
		return nil
	}
	if ev.ContextID != "" && ev.ContextID == s.cfg.DeviceID {
		return nil
	}
	if ev.Type >= realtime.SyncCipherUpdate && ev.Type <= realtime.SyncFolderUpdate {
		return s.forceSync(ctx)
	}
	return nil
}

func (s *Service) Search(query string, filter SearchFilter) []CipherSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	return searchCiphers(s.ciphers, query, filter)
}

func (s *Service) GetCipher(id string) (*Cipher, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil, ErrLocked
	}
	c, ok := s.ciphers[id]
	if !ok {
		return nil, ErrCipherNotFound
	}
	return cloneCipher(c), nil
}

// AllCiphers returns copies of every decrypted item for local analysis.
// HidePassword also reflects collections that hide passwords, and hidden
// passwords are removed from the copies.
func (s *Service) AllCiphers() []*Cipher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]*Cipher, 0, len(s.ciphers))
	for _, c := range s.ciphers {
		cp := cloneCipher(c)
		cp.HidePassword = s.effectiveHidePasswordLocked(c)
		cp.ReadOnly = s.effectiveReadOnlyLocked(c)
		if cp.HidePassword {
			if cp.Login != nil {
				cp.Login.Password = ""
			}
			cp.PasswordHistory = nil
		}
		out = append(out, cp)
	}
	return out
}

func (s *Service) SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error) {
	if c == nil {
		return nil, ErrCipherNotFound
	}
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	c = cloneCipher(c)
	if c.ID != "" {
		existing, err := o.editableCipher(c.ID)
		if err != nil && !errors.Is(err, ErrCipherNotFound) {
			return nil, err
		}
		if existing != nil {
			recordPasswordChange(existing, c, time.Now().UTC())
			if c.OrganizationID == nil {
				c.OrganizationID = cloneStringPtr(existing.OrganizationID)
			}
			if len(c.CollectionIDs) == 0 {
				c.CollectionIDs = append([]string(nil), existing.CollectionIDs...)
			}
		}
	}
	key, err := o.itemKey(c.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	payload, err := encryptCipherPayload(c, key)
	if err != nil {
		return nil, err
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		if c.ID == "" {
			return o.client.CreateCipher(ctx, tok, payload)
		}
		return o.client.UpdateCipher(ctx, tok, c.ID, payload)
	})
	if err != nil {
		return nil, err
	}

	respKey := key
	if !sameOrg(encResp.OrganizationID, c.OrganizationID) {
		if respKey, err = o.itemKey(encResp.OrganizationID); err != nil {
			return nil, err
		}
		defer respKey.Zero()
	}
	decrypted, err := decryptCipher(encResp, respKey)
	if err != nil {
		return nil, err
	}
	if len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), c.CollectionIDs...)
	}
	return o.commitCipher(decrypted, encResp)
}

// commitCipher records a cipher the server returned after a change: first
// in the encrypted snapshot, then in memory. Memory always takes the
// server's version, even when the snapshot write fails and the error is
// returned.
func (o *op) commitCipher(decrypted *Cipher, enc *api.EncryptedCipher) (*Cipher, error) {
	stored := *enc
	if len(stored.CollectionIDs) == 0 {
		stored.CollectionIDs = append([]string(nil), decrypted.CollectionIDs...)
	}
	snapErr := o.storeSnapshotCipher(&stored)
	if errors.Is(snapErr, ErrLocked) {
		return nil, ErrLocked
	}
	o.s.mu.Lock()
	if !o.currentLocked() {
		o.s.mu.Unlock()
		return nil, ErrLocked
	}
	o.s.ciphers[decrypted.ID] = decrypted
	o.s.mu.Unlock()
	o.s.notifyUpdated()
	if snapErr != nil {
		return nil, snapErr
	}
	return cloneCipher(decrypted), nil
}

func (s *Service) SoftDeleteCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.SoftDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	snapErr := o.updateSnapshot(func(resp *api.SyncResponse) {
		for i := range resp.Ciphers {
			if resp.Ciphers[i].ID == id {
				resp.Ciphers[i].DeletedDate = &now
			}
		}
	})
	s.mu.Lock()
	if c, ok := s.ciphers[id]; ok && o.currentLocked() {
		c.DeletedDate = &now
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return snapErr
}

func (s *Service) RestoreCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		return o.client.RestoreCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	key, err := o.itemKey(encResp.OrganizationID)
	if err != nil {
		return err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(encResp, key)
	if err != nil {
		return err
	}
	s.mu.RLock()
	if prev := s.ciphers[decrypted.ID]; prev != nil && len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), prev.CollectionIDs...)
	}
	s.mu.RUnlock()
	_, err = o.commitCipher(decrypted, encResp)
	return err
}

func (s *Service) HardDeleteCipher(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()
	if _, err := o.editableCipher(id); err != nil {
		return err
	}

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.HardDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	snapErr := o.removeSnapshotCiphers(id)
	s.mu.Lock()
	if o.currentLocked() {
		delete(s.ciphers, id)
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return snapErr
}

func (o *op) removeSnapshotCiphers(ids ...string) error {
	return o.updateSnapshot(func(resp *api.SyncResponse) {
		resp.Ciphers = slices.DeleteFunc(resp.Ciphers, func(c api.EncryptedCipher) bool { return slices.Contains(ids, c.ID) })
	})
}

// EmptyTrash permanently deletes every item in Trash the user may delete and
// leaves read-only ones, then resyncs so memory and the snapshot match.
func (s *Service) EmptyTrash(ctx context.Context) (TrashResult, error) {
	var res TrashResult
	o, err := s.beginOp(ctx)
	if err != nil {
		return res, err
	}
	defer o.end()

	var ids []string
	s.mu.RLock()
	for id, c := range s.ciphers {
		if c.DeletedDate == nil {
			continue
		}
		if s.effectiveReadOnlyLocked(c) {
			res.ReadOnly++
			continue
		}
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	slices.Sort(ids)

	var errs []error
	var deleted []string
	for _, id := range ids {
		_, err := withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
			return struct{}{}, o.client.HardDeleteCipher(ctx, tok, id)
		})
		if err != nil {
			errs = append(errs, err)
			if errors.Is(err, ErrLocked) || o.ctx.Err() != nil {
				break
			}
			continue
		}
		res.Deleted++
		deleted = append(deleted, id)
		s.mu.Lock()
		if o.currentLocked() {
			delete(s.ciphers, id)
		}
		s.mu.Unlock()
	}
	if res.Deleted > 0 {
		if err := o.removeSnapshotCiphers(deleted...); err != nil {
			errs = append(errs, err)
		}
		if err := s.sync(ctx, true); err != nil && !errors.Is(err, ErrLocked) {
			errs = append(errs, err)
		}
		s.notifyUpdated()
	}
	return res, errors.Join(errs...)
}

func (s *Service) Folders() []Folder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Folder, 0, len(s.folders))
	for _, f := range s.folders {
		out = append(out, Folder{
			ID:           f.ID,
			Name:         f.Name,
			RevisionDate: cloneTimePtr(f.RevisionDate),
			Extra:        cloneExtra(f.Extra),
		})
	}
	slices.SortFunc(out, func(a, b Folder) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}

func (s *Service) SaveFolder(ctx context.Context, f *Folder) (*Folder, error) {
	if f == nil {
		return nil, ErrFolderNotFound
	}
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	encName, err := crypto.EncryptString(f.Name, o.userKey)
	if err != nil {
		return nil, err
	}

	encResp, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedFolder, error) {
		if f.ID == "" {
			return o.client.CreateFolder(ctx, tok, encName)
		}
		return o.client.UpdateFolder(ctx, tok, f.ID, encName)
	})
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptFolder(encResp, o.userKey)
	if err != nil {
		return nil, err
	}

	snapErr := o.updateSnapshot(func(resp *api.SyncResponse) {
		for i := range resp.Folders {
			if resp.Folders[i].ID == encResp.ID {
				resp.Folders[i] = *encResp
				return
			}
		}
		resp.Folders = append(resp.Folders, *encResp)
	})
	if errors.Is(snapErr, ErrLocked) {
		return nil, ErrLocked
	}
	s.mu.Lock()
	if !o.currentLocked() {
		s.mu.Unlock()
		return nil, ErrLocked
	}
	s.folders[decrypted.ID] = decrypted
	s.mu.Unlock()

	s.notifyUpdated()
	if snapErr != nil {
		return nil, snapErr
	}
	cp := decrypted
	return &cp, nil
}

func (s *Service) DeleteFolder(ctx context.Context, id string) error {
	o, err := s.beginOp(ctx)
	if err != nil {
		return err
	}
	defer o.end()

	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.DeleteFolder(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	snapErr := o.updateSnapshot(func(resp *api.SyncResponse) {
		resp.Folders = slices.DeleteFunc(resp.Folders, func(f api.EncryptedFolder) bool { return f.ID == id })
		for i := range resp.Ciphers {
			if f := resp.Ciphers[i].FolderID; f != nil && *f == id {
				resp.Ciphers[i].FolderID = nil
			}
		}
	})
	s.mu.Lock()
	if o.currentLocked() {
		delete(s.folders, id)
		for _, c := range s.ciphers {
			if c.FolderID != nil && *c.FolderID == id {
				c.FolderID = nil
			}
		}
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return snapErr
}

func (s *Service) loadCurrentSnapshot() (*store.Snapshot, error) {
	s.mu.RLock()
	snap := s.snapshot
	accountID := s.accountID
	s.mu.RUnlock()

	if snap != nil {
		cp := *snap
		return &cp, nil
	}
	if accountID == "" {
		return nil, ErrLoggedOut
	}
	return s.cfg.Store.LoadSnapshot(accountID)
}

func (s *Service) newAPIClient(serverURL string) (*api.Client, error) {
	return api.NewClient(api.ClientConfig{
		ServerURL:  serverURL,
		DeviceID:   s.cfg.DeviceID,
		DeviceName: s.cfg.DeviceName,
		DeviceType: s.cfg.DeviceType,
		HTTPClient: s.cfg.HTTPClient,
	})
}

func (s *Service) stopRealtimeLocked() {
	if s.realtimeCancel != nil {
		s.realtimeCancel()
		s.realtimeCancel = nil
	}
}

func (s *Service) notifyStatus(st LockStatus) {
	if s.cfg.OnStatusChange != nil {
		s.cfg.OnStatusChange(st)
	}
}

func (s *Service) notifyUpdated() {
	if s.cfg.OnVaultUpdated != nil {
		s.cfg.OnVaultUpdated()
	}
}

type vaultData struct {
	ciphers     map[string]*Cipher
	folders     map[string]Folder
	orgs        map[string]Organization
	collections map[string]Collection
	orgKeys     map[string]*crypto.SymmetricKey
}

func (d *vaultData) zero() {
	if d == nil {
		return
	}
	for _, k := range d.orgKeys {
		k.Zero()
	}
	clear(d.orgKeys)
}

func (s *Service) applyDataLocked(d *vaultData) {
	s.clearDataLocked()
	s.ciphers = d.ciphers
	s.folders = d.folders
	s.orgs = d.orgs
	s.collections = d.collections
	s.orgKeys = d.orgKeys
}

func (s *Service) clearDataLocked() {
	for _, k := range s.orgKeys {
		k.Zero()
	}
	s.orgKeys = nil
	s.orgs = nil
	s.collections = nil
	s.ciphers = nil
	s.folders = nil
}

func (s *Service) Organizations() []Organization {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Organization, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b Organization) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

func (s *Service) Collections() []Collection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked {
		return nil
	}
	out := make([]Collection, 0, len(s.collections))
	for _, c := range s.collections {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Collection) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

func unwrapOrgKeys(p *api.Profile, userKey *crypto.SymmetricKey) map[string]*crypto.SymmetricKey {
	keys := map[string]*crypto.SymmetricKey{}
	if p.PrivateKey == nil || *p.PrivateKey == "" || len(p.Organizations) == 0 {
		return keys
	}
	priv, err := crypto.DecryptPrivateKey(*p.PrivateKey, userKey)
	if err != nil {
		return keys
	}
	defer crypto.ZeroPrivateKey(priv)
	for _, org := range p.Organizations {
		if !org.Enabled || org.Key == "" {
			continue
		}
		if k, err := crypto.DecryptOrgKey(org.Key, priv); err == nil {
			keys[org.ID] = k
		}
	}
	return keys
}

func decryptSyncResponse(resp *api.SyncResponse, userKey *crypto.SymmetricKey) (*vaultData, error) {
	d := &vaultData{
		ciphers:     make(map[string]*Cipher, len(resp.Ciphers)),
		folders:     make(map[string]Folder, len(resp.Folders)),
		orgs:        map[string]Organization{},
		collections: map[string]Collection{},
		orgKeys:     unwrapOrgKeys(&resp.Profile, userKey),
	}
	for _, org := range resp.Profile.Organizations {
		if _, ok := d.orgKeys[org.ID]; ok {
			d.orgs[org.ID] = Organization{ID: org.ID, Name: org.Name, Type: org.Type, Enabled: org.Enabled}
		}
	}

	for i := range resp.Ciphers {
		enc := &resp.Ciphers[i]
		key := userKey
		isOrg := enc.OrganizationID != nil && *enc.OrganizationID != ""
		if isOrg {
			if key = d.orgKeys[*enc.OrganizationID]; key == nil {
				continue
			}
		}
		c, err := decryptCipher(enc, key)
		if err != nil {
			if isOrg || errors.Is(err, ErrUnsupportedCipherFormat) {
				continue
			}
			d.zero()
			return nil, err
		}
		d.ciphers[c.ID] = c
	}

	for i := range resp.Folders {
		f, err := decryptFolder(&resp.Folders[i], userKey)
		if err != nil {
			d.zero()
			return nil, err
		}
		d.folders[f.ID] = f
	}

	for _, col := range resp.Collections {
		key := d.orgKeys[col.OrganizationID]
		if key == nil {
			continue
		}
		name, err := crypto.DecryptString(col.Name, key)
		if err != nil {
			continue
		}
		d.collections[col.ID] = Collection{
			ID: col.ID, OrganizationID: col.OrganizationID, Name: name,
			ReadOnly: col.ReadOnly, HidePasswords: col.HidePasswords, Manage: col.Manage,
		}
	}
	return d, nil
}

const maxPasswordHistory = 5

func recordPasswordChange(existing, updated *Cipher, now time.Time) {
	if existing.Login == nil || updated.Login == nil {
		return
	}
	old := existing.Login.Password
	if old == "" || old == updated.Login.Password {
		return
	}
	history := updated.PasswordHistory
	if history == nil {
		history = existing.PasswordHistory
	}
	next := make([]PasswordHistoryEntry, 0, maxPasswordHistory)
	next = append(next, PasswordHistoryEntry{Password: old, LastUsedDate: now})
	for _, h := range history {
		if len(next) == maxPasswordHistory {
			break
		}
		next = append(next, h)
	}
	updated.PasswordHistory = next
	updated.Login.PasswordRevisionDate = &now
}

func sameOrg(a, b *string) bool {
	av, bv := "", ""
	if a != nil {
		av = *a
	}
	if b != nil {
		bv = *b
	}
	return av == bv
}
