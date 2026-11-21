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

func (s *Service) Login(ctx context.Context, serverURL, email string, masterPassword []byte) error {
	client, err := s.newAPIClient(serverURL)
	if err != nil {
		return err
	}

	kdfCfg, err := client.Prelogin(ctx, email)
	if err != nil {
		return err
	}
	masterKey, err := crypto.DeriveMasterKey(masterPassword, email, kdfCfg)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	pwHash := crypto.HashMasterPasswordForServer(masterKey, masterPassword)
	tok, err := client.LoginPassword(ctx, email, pwHash)
	if err != nil {
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

	ciphers, folders, err := decryptSyncResponse(syncResp, userKey)
	if err != nil {
		userKey.Zero()
		return err
	}

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
	s.ciphers = ciphers
	s.folders = folders
	s.status = StatusUnlocked
	s.mu.Unlock()

	s.notifyStatus(StatusUnlocked)
	s.notifyUpdated()
	return nil
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

	ciphers, folders, err := decryptSyncResponse(&syncResp, ownedKey)
	if err != nil {
		ownedKey.Zero()
		return err
	}

	var client *api.Client
	if snap.ServerURL != "" {
		client, err = s.newAPIClient(snap.ServerURL)
		if err != nil {
			ownedKey.Zero()
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
	s.ciphers = ciphers
	s.folders = folders
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
	s.ciphers = nil
	s.folders = nil
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
	s.ciphers = nil
	s.folders = nil
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

	ciphers, folders, err := decryptSyncResponse(res.resp, userKey)
	if err != nil {
		return err
	}

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
	s.ciphers = ciphers
	s.folders = folders
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

	payload, err := encryptCipherPayload(c, userKey)
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

	decrypted, err := decryptCipher(encResp, userKey)
	if err != nil {
		return nil, err
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

	decrypted, err := decryptCipher(encResp, userKey)
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

	ciphers, folders, err := decryptSyncResponse(res.resp, userKey)
	if err != nil {
		return err
	}

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
	s.ciphers = ciphers
	s.folders = folders
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

func decryptSyncResponse(resp *api.SyncResponse, userKey *crypto.SymmetricKey) (map[string]*Cipher, map[string]Folder, error) {
	ciphers := make(map[string]*Cipher, len(resp.Ciphers))
	for i := range resp.Ciphers {
		enc := &resp.Ciphers[i]
		// Skip organization-owned ciphers in MVP (Phase 2 adds RSA-OAEP org key unwrap).
		if enc.OrganizationID != nil && *enc.OrganizationID != "" {
			continue
		}
		c, err := decryptCipher(enc, userKey)
		if err != nil {
			if errors.Is(err, ErrUnsupportedCipherFormat) {
				continue
			}
			return nil, nil, err
		}
		ciphers[c.ID] = c
	}

	folders := make(map[string]Folder, len(resp.Folders))
	for i := range resp.Folders {
		f, err := decryptFolder(&resp.Folders[i], userKey)
		if err != nil {
			return nil, nil, err
		}
		folders[f.ID] = f
	}
	return ciphers, folders, nil
}
