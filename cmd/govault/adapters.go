package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type SecretStoreAdapter struct {
	secrets core.Secrets
}

func NewSecretStoreAdapter(secrets core.Secrets) *SecretStoreAdapter {
	return &SecretStoreAdapter{secrets: secrets}
}

func (a *SecretStoreAdapter) Get(account string) (string, bool, error) {
	return a.secrets.Get(account)
}

func (a *SecretStoreAdapter) Set(account, value string) error {
	return a.secrets.Set(account, value)
}

func (a *SecretStoreAdapter) Delete(account string) error {
	return a.secrets.Delete(account)
}

type ClipboardAdapter struct {
	scope     *core.Scope
	concealed *ConcealedClipboard

	mu    sync.Mutex
	timer *time.Timer
}

func NewClipboardAdapter(scope *core.Scope) *ClipboardAdapter {
	return &ClipboardAdapter{
		scope:     scope,
		concealed: NewConcealedClipboard(),
	}
}

func (c *ClipboardAdapter) IsConcealed() bool {
	return runtime.GOOS == "darwin"
}

func (c *ClipboardAdapter) CopySecret(secret string, clearAfter time.Duration) (bool, error) {
	if runtime.GOOS == "darwin" {
		if _, err := c.concealed.Copy(secret, clearAfter); err != nil {
			return false, err
		}
		return true, nil
	}

	c.scope.SetClipboard(secret)

	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if clearAfter > 0 {
		expected := secret
		c.timer = time.AfterFunc(clearAfter, func() {
			c.scope.Post(func() {
				c.scope.ReadClipboard(func(current string) {
					if current == expected {
						c.scope.SetClipboard("")
					}
				})
			})
		})
	}
	c.mu.Unlock()

	return false, nil
}

func (c *ClipboardAdapter) CopyPlain(text string) {
	c.scope.SetClipboard(text)
}

// ClearOnQuit clears a pending concealed secret synchronously and stops the
// fallback timer.
func (c *ClipboardAdapter) ClearOnQuit() {
	c.concealed.ClearPending()
	c.Cancel()
}

func (c *ClipboardAdapter) Cancel() {
	c.concealed.Cancel()
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
}

func DiscoverAccountSnapshot(dataDir, preferredAccountID string) *govaultui.AccountSnapshotMeta {
	fs := store.NewFileStore(dataDir)
	if preferredAccountID != "" {
		if snap, err := fs.LoadSnapshot(preferredAccountID); err == nil {
			return snapshotToMeta(snap)
		}
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil
	}

	var latest *store.Snapshot
	var latestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "vault_") || !strings.HasSuffix(name, ".enc.json") {
			continue
		}
		accountID := strings.TrimSuffix(strings.TrimPrefix(name, "vault_"), ".enc.json")
		snap, err := fs.LoadSnapshot(accountID)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if latest == nil || info.ModTime().After(latestMod) {
			latest = snap
			latestMod = info.ModTime()
		}
	}
	if latest == nil {
		return nil
	}
	return snapshotToMeta(latest)
}

func VerifyMasterPasswordOffline(dataDir, accountID string, password []byte) error {
	if accountID == "" {
		return errors.New("no active account")
	}
	snap, err := store.NewFileStore(dataDir).LoadSnapshot(accountID)
	if err != nil {
		return err
	}
	masterKey, err := crypto.DeriveMasterKey(password, snap.Email, snap.KDF)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey[:])

	userKey, err := crypto.DecryptUserKey(snap.ProtectedKey, masterKey)
	if err != nil {
		return err
	}
	userKey.Zero()
	return nil
}

func snapshotToMeta(snap *store.Snapshot) *govaultui.AccountSnapshotMeta {
	return &govaultui.AccountSnapshotMeta{
		AccountID:  snap.AccountID,
		ServerURL:  snap.ServerURL,
		Email:      snap.Email,
		KDFSummary: formatKDFSummary(snap.KDF),
		LastSyncAt: snap.LastSyncAt,
	}
}

func formatKDFSummary(kdf crypto.KDFConfig) string {
	switch kdf.Type {
	case crypto.KDFArgon2id:
		return fmt.Sprintf("Argon2id (%d iter, %d MiB, %d threads)", kdf.Iterations, kdf.MemoryMB, kdf.Parallelism)
	default:
		return fmt.Sprintf("PBKDF2-SHA256 (%d iterations)", kdf.Iterations)
	}
}

func ensureDataDir(scope *core.Scope) string {
	dir := scope.DataDir()
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".govault")
		} else {
			dir = os.TempDir()
		}
	}
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

func deviceTypeForOS() int {
	switch runtime.GOOS {
	case "darwin":
		return 7 // macOS Desktop
	case "linux":
		return 8 // Linux Desktop
	default:
		return 6 // Windows Desktop
	}
}
