package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	s.stopRealtimeLocked()
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	s.accessToken = ""
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

func (s *Service) Logout(ctx context.Context, secrets store.SecretStore) error {
	s.mu.Lock()
	s.stopRealtimeLocked()
	accountID := s.accountID
	if s.userKey != nil {
		s.userKey.Zero()
		s.userKey = nil
	}
	s.clearDataLocked()
	s.accessToken = ""
	s.snapshot = nil
	s.apiClient = nil
	s.accountID = ""
	s.status = StatusLoggedOut
	s.mu.Unlock()

	var firstErr error
	if accountID != "" {
		if err := s.cfg.Store.DeleteSnapshot(accountID); err != nil {
			firstErr = err
		}
		for _, sec := range []store.SecretStore{secrets, s.cfg.Secrets} {
			if sec == nil {
				continue
			}
			_ = sec.Delete(refreshTokenKeyPrefix + accountID)
			_ = sec.Delete(userKeyPrefix + accountID)
		}
	}

	s.notifyStatus(StatusLoggedOut)
	return firstErr
}

func (s *Service) SyncNow(ctx context.Context) error {
	client, snap, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	revDate, err := withAuth(s, ctx, func(tok string) (time.Time, error) {
		return client.RevisionDate(ctx, tok)
	})
	if err == nil && !snap.RevisionDate.IsZero() && revDate.Equal(snap.RevisionDate) {
		return nil
	}

	type syncResult struct {
		resp *api.SyncResponse
		raw  []byte
	}
	res, err := withAuth(s, ctx, func(tok string) (syncResult, error) {
		resp, raw, err := client.Sync(ctx, tok)
		return syncResult{resp: resp, raw: raw}, err
	})
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(res.resp, userKey)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	updatedSnap := *snap
	if !revDate.IsZero() {
		updatedSnap.RevisionDate = revDate
	}
	if res.resp.Profile.Key != "" {
		updatedSnap.ProtectedKey = res.resp.Profile.Key
	}
	updatedSnap.LastSyncAt = time.Now().UTC()
	updatedSnap.RawSyncJSON = res.raw
	if err := s.cfg.Store.SaveSnapshot(&updatedSnap); err != nil {
		return err
	}

	s.mu.Lock()
	if s.status != StatusUnlocked {
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
	s.mu.Lock()
	if s.status != StatusUnlocked || s.snapshot == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	serverURL := s.snapshot.ServerURL
	s.stopRealtimeLocked()
	rtCtx, cancel := context.WithCancel(ctx)
	s.realtimeCancel = cancel
	s.mu.Unlock()

	var rtClient realtime.Client
	var err error
	if s.cfg.NewRealtimeClient != nil {
		rtClient, err = s.cfg.NewRealtimeClient(serverURL)
	} else {
		rtClient, err = realtime.NewClient(realtime.Config{
			ServerURL:  serverURL,
			HTTPClient: s.cfg.HTTPClient,
		})
	}
	if err != nil {
		cancel()
		return err
	}

	go func() {
		_ = rtClient.Run(rtCtx, func() (string, error) {
			return s.ensureAccessToken(rtCtx)
		}, func(ev realtime.Event) {
			_ = s.HandleRealtimeEvent(rtCtx, ev)
		})
	}()
	return nil
}

func (s *Service) HandleRealtimeEvent(ctx context.Context, ev realtime.Event) error {
	if ev.Type == realtime.LogOut {
		return s.Logout(ctx, s.cfg.Secrets)
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

func (s *Service) SaveCipher(ctx context.Context, c *Cipher) (*Cipher, error) {
	if c == nil {
		return nil, ErrCipherNotFound
	}
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return nil, err
	}
	defer userKey.Zero()

	c = cloneCipher(c)
	if c.ID != "" {
		s.mu.RLock()
		existing := cloneCipher(s.ciphers[c.ID])
		s.mu.RUnlock()
		if existing != nil {
			if existing.ReadOnly {
				return nil, ErrReadOnlyCipher
			}
			recordPasswordChange(existing, c, time.Now().UTC())
			if c.OrganizationID == nil {
				c.OrganizationID = cloneStringPtr(existing.OrganizationID)
			}
			if len(c.CollectionIDs) == 0 {
				c.CollectionIDs = append([]string(nil), existing.CollectionIDs...)
			}
		}
	}
	key, err := s.itemKey(c.OrganizationID, userKey)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	payload, err := encryptCipherPayload(c, key)
	if err != nil {
		return nil, err
	}

	var encResp *api.EncryptedCipher
	if c.ID == "" {
		encResp, err = withAuth(s, ctx, func(tok string) (*api.EncryptedCipher, error) {
			return client.CreateCipher(ctx, tok, payload)
		})
	} else {
		encResp, err = withAuth(s, ctx, func(tok string) (*api.EncryptedCipher, error) {
			return client.UpdateCipher(ctx, tok, c.ID, payload)
		})
	}
	if err != nil {
		return nil, err
	}

	respKey := key
	if !sameOrg(encResp.OrganizationID, c.OrganizationID) {
		if respKey, err = s.itemKey(encResp.OrganizationID, userKey); err != nil {
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

	s.mu.Lock()
	if s.status != StatusUnlocked {
		s.mu.Unlock()
		return nil, ErrLocked
	}
	s.ciphers[decrypted.ID] = decrypted
	s.mu.Unlock()

	s.notifyUpdated()
	return cloneCipher(decrypted), nil
}

func (s *Service) SoftDeleteCipher(ctx context.Context, id string) error {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	_, err = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.SoftDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	if c, ok := s.ciphers[id]; ok {
		c.DeletedDate = &now
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return nil
}

func (s *Service) RestoreCipher(ctx context.Context, id string) error {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	encResp, err := withAuth(s, ctx, func(tok string) (*api.EncryptedCipher, error) {
		return client.RestoreCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	key, err := s.itemKey(encResp.OrganizationID, userKey)
	if err != nil {
		return err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(encResp, key)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.status == StatusUnlocked {
		s.ciphers[decrypted.ID] = decrypted
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return nil
}

func (s *Service) HardDeleteCipher(ctx context.Context, id string) error {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	_, err = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.HardDeleteCipher(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.ciphers, id)
	s.mu.Unlock()

	s.notifyUpdated()
	return nil
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
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return nil, err
	}
	defer userKey.Zero()

	encName, err := crypto.EncryptString(f.Name, userKey)
	if err != nil {
		return nil, err
	}

	var encResp *api.EncryptedFolder
	if f.ID == "" {
		encResp, err = withAuth(s, ctx, func(tok string) (*api.EncryptedFolder, error) {
			return client.CreateFolder(ctx, tok, encName)
		})
	} else {
		encResp, err = withAuth(s, ctx, func(tok string) (*api.EncryptedFolder, error) {
			return client.UpdateFolder(ctx, tok, f.ID, encName)
		})
	}
	if err != nil {
		return nil, err
	}

	decrypted, err := decryptFolder(encResp, userKey)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.status != StatusUnlocked {
		s.mu.Unlock()
		return nil, ErrLocked
	}
	s.folders[decrypted.ID] = decrypted
	s.mu.Unlock()

	s.notifyUpdated()
	cp := decrypted
	return &cp, nil
}

func (s *Service) DeleteFolder(ctx context.Context, id string) error {
	client, _, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	_, err = withAuth(s, ctx, func(tok string) (struct{}, error) {
		return struct{}{}, client.DeleteFolder(ctx, tok, id)
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.folders, id)
	for _, c := range s.ciphers {
		if c.FolderID != nil && *c.FolderID == id {
			c.FolderID = nil
		}
	}
	s.mu.Unlock()

	s.notifyUpdated()
	return nil
}

func (s *Service) forceSync(ctx context.Context) error {
	client, snap, userKey, err := s.requireUnlockedNetwork()
	if err != nil {
		return err
	}
	defer userKey.Zero()

	type syncResult struct {
		resp *api.SyncResponse
		raw  []byte
	}
	res, err := withAuth(s, ctx, func(tok string) (syncResult, error) {
		resp, raw, err := client.Sync(ctx, tok)
		return syncResult{resp: resp, raw: raw}, err
	})
	if err != nil {
		return err
	}

	data, err := decryptSyncResponse(res.resp, userKey)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			data.zero()
		}
	}()

	revDate, _ := withAuth(s, ctx, func(tok string) (time.Time, error) {
		return client.RevisionDate(ctx, tok)
	})

	updatedSnap := *snap
	if !revDate.IsZero() {
		updatedSnap.RevisionDate = revDate
	}
	updatedSnap.LastSyncAt = time.Now().UTC()
	updatedSnap.RawSyncJSON = res.raw
	if err := s.cfg.Store.SaveSnapshot(&updatedSnap); err != nil {
		return err
	}

	s.mu.Lock()
	if s.status != StatusUnlocked {
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

func (s *Service) requireUnlockedNetwork() (*api.Client, *store.Snapshot, *crypto.SymmetricKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.status != StatusUnlocked || s.userKey == nil {
		return nil, nil, nil, ErrLocked
	}
	if s.apiClient == nil || s.snapshot == nil {
		return nil, nil, nil, ErrLoggedOut
	}
	raw := s.userKey.Bytes()
	keyCopy, err := crypto.SymmetricKeyFromBytes(raw[:])
	crypto.ZeroBytes(raw[:])
	if err != nil {
		return nil, nil, nil, err
	}
	snapCopy := *s.snapshot
	return s.apiClient, &snapCopy, keyCopy, nil
}

func (s *Service) ensureAccessToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	tok := s.accessToken
	s.mu.RUnlock()
	if tok != "" {
		return tok, nil
	}
	return s.refreshAccessToken(ctx)
}

func (s *Service) refreshAccessToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	client := s.apiClient
	accountID := s.accountID
	s.mu.RUnlock()

	if client == nil || accountID == "" {
		return "", ErrLoggedOut
	}
	if s.cfg.Secrets == nil {
		return "", api.ErrUnauthorized
	}
	refreshTok, ok, err := s.cfg.Secrets.Get(refreshTokenKeyPrefix + accountID)
	if err != nil {
		return "", err
	}
	if !ok || refreshTok == "" {
		return "", api.ErrUnauthorized
	}

	resp, err := client.RefreshToken(ctx, refreshTok)
	if err != nil {
		return "", err
	}
	if resp.RefreshToken != "" {
		_ = s.cfg.Secrets.Set(refreshTokenKeyPrefix+accountID, resp.RefreshToken)
	}

	s.mu.Lock()
	if s.accountID == accountID {
		s.accessToken = resp.AccessToken
	}
	s.mu.Unlock()
	return resp.AccessToken, nil
}

func withAuth[T any](s *Service, ctx context.Context, fn func(token string) (T, error)) (T, error) {
	tok, err := s.ensureAccessToken(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	return api.DoWithRefresh(ctx, tok, s.refreshAccessToken, fn)
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

// itemKey returns a copy of the key that encrypts items owned by orgID, or
// of userKey for personal items.
func (s *Service) itemKey(orgID *string, userKey *crypto.SymmetricKey) (*crypto.SymmetricKey, error) {
	var raw [64]byte
	defer crypto.ZeroBytes(raw[:])
	if orgID == nil || *orgID == "" {
		raw = userKey.Bytes()
	} else {
		s.mu.RLock()
		k := s.orgKeys[*orgID]
		if k != nil {
			raw = k.Bytes()
		}
		s.mu.RUnlock()
		if k == nil {
			return nil, ErrOrganizationKeyMissing
		}
	}
	return crypto.SymmetricKeyFromBytes(raw[:])
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
