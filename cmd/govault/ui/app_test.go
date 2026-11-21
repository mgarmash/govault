package ui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type mockVaultService struct {
	mu       sync.RWMutex
	status   state.LockStatus
	password string
	ciphers  map[string]*state.Cipher
	order    []string
	folders  []state.Folder
}

func newMockVaultService(initial state.LockStatus) *mockVaultService {
	c1 := &state.Cipher{
		ID:       "c-github",
		Type:     api.CipherTypeLogin,
		Name:     "GitHub",
		Favorite: true,
		Login: &state.Login{
			Username: "alice@example.com",
			Password: "gh-secret-password",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs:     []state.LoginURI{{URI: "https://github.com"}},
		},
	}
	c2 := &state.Cipher{
		ID:   "c-note",
		Type: api.CipherTypeSecureNote,
		Name: "SSH Recovery Note",
		Notes: "Keep safe",
		SecureNote: &state.SecureNote{Type: 0},
	}
	return &mockVaultService{
		status:   initial,
		password: "master-password",
		ciphers: map[string]*state.Cipher{
			c1.ID: c1,
			c2.ID: c2,
		},
		order: []string{c1.ID, c2.ID},
		folders: []state.Folder{
			{ID: "f-work", Name: "Work"},
		},
	}
}

func (m *mockVaultService) Status() state.LockStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *mockVaultService) Login(_ context.Context, _, _ string, pw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(pw) != m.password {
		return api.ErrUnauthorized
	}
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) UnlockWithPassword(_ context.Context, pw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(pw) != m.password {
		return crypto.ErrInvalidMAC
	}
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) UnlockWithUserKey(_ context.Context, _ *crypto.SymmetricKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) EnableBiometricUnlock(_ store.SecretStore) error  { return nil }
func (m *mockVaultService) DisableBiometricUnlock(_ store.SecretStore) error { return nil }

func (m *mockVaultService) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) Logout(_ context.Context, _ store.SecretStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusLoggedOut
	return nil
}

func (m *mockVaultService) SyncNow(_ context.Context) error { return nil }

func (m *mockVaultService) Search(query string, filter state.SearchFilter) []state.CipherSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var out []state.CipherSummary
	for _, id := range m.order {
		c := m.ciphers[id]
		if c == nil {
			continue
		}
		deleted := c.DeletedDate != nil
		if filter.Category == state.FilterTrash {
			if !deleted {
				continue
			}
		} else if deleted {
			continue
		}
		if filter.Category == state.FilterFavorites && !c.Favorite {
			continue
		}
		if filter.Type != nil && c.Type != *filter.Type {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		sub := ""
		hasTOTP := false
		if c.Login != nil {
			sub = c.Login.Username
			hasTOTP = strings.TrimSpace(c.Login.TOTP) != ""
		}
		out = append(out, state.CipherSummary{
			ID:       c.ID,
			Type:     c.Type,
			FolderID: c.FolderID,
			Favorite: c.Favorite,
			Deleted:  deleted,
			Name:     c.Name,
			Subtitle: sub,
			HasTOTP:  hasTOTP,
			Reprompt: c.Reprompt,
		})
	}
	return out
}

func (m *mockVaultService) GetCipher(id string) (*state.Cipher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	c, ok := m.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	cp := *c
	if cp.ID == "" {
		cp.ID = "c-new"
		m.order = append(m.order, cp.ID)
	}
	m.ciphers[cp.ID] = &cp
	return &cp, nil
}

func (m *mockVaultService) SoftDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now()
	c.DeletedDate = &now
	return nil
}

func (m *mockVaultService) RestoreCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	c.DeletedDate = nil
	return nil
}

func (m *mockVaultService) HardDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ciphers, id)
	return nil
}

func (m *mockVaultService) Folders() []state.Folder {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Folder(nil), m.folders...)
}

func (m *mockVaultService) SaveFolder(_ context.Context, f *state.Folder) (*state.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == "" {
		f.ID = "f-new"
		m.folders = append(m.folders, *f)
	}
	return f, nil
}

func (m *mockVaultService) DeleteFolder(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.folders {
		if f.ID == id {
			m.folders = append(m.folders[:i], m.folders[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func TestCoreStateTransitions(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.Find("id:login-screen")
	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)

	app.Type("id:vault-search", "GitHub")
	app.Find("id:vault-item-list >> text:GitHub")
	app.Press("id:vault-row")
	app.Find("id:detail-view")
	app.Find("id:detail-view >> text:alice@example.com")

	app.Press("id:detail-edit")
	app.Find("id:editor-pane")
	app.Clear("id:editor-name")
	app.Type("id:editor-name", "GitHub Enterprise")
	app.Press("id:editor-save")
	app.WaitFor("id:detail-view", 2*time.Second)
	app.Find("id:detail-title")
	app.Find("id:detail-view >> text:GitHub Enterprise")

	app.Press("id:toolbar-lock")
	app.WaitFor("id:lock-screen", 2*time.Second)

	app.Type("id:lock-password", "master-password")
	app.Press("id:lock-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)
}

func TestTOTPTickerVisibilityGating(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if model.TOTPTickerActive() {
		t.Fatal("expected TOTP ticker stopped before selecting a TOTP item")
	}

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive() && model.TOTPCode.Get() != ""
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-note")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(false)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(true)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.Lock()
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})
}

func TestTrayIconOffKeepsDockReachable(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var trayCalls, dockCalls []bool

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			SetTrayVisible: func(on bool) { trayCalls = append(trayCalls, on) },
			SetDockVisible: func(on bool) { dockCalls = append(dockCalls, on) },
		})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if !model.Prefs.Get().ShowTrayIcon {
		t.Fatal("expected the tray icon to be shown by default")
	}

	app.Post(func() {
		model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.HideDockIcon = true; return p })
		model.SetShowTrayIcon(false)
	})
	app.Settle()

	p := model.Prefs.Get()
	if p.ShowTrayIcon || p.HideDockIcon {
		t.Fatalf("expected tray off and Dock shown, got ShowTrayIcon=%v HideDockIcon=%v", p.ShowTrayIcon, p.HideDockIcon)
	}
	if len(trayCalls) != 1 || trayCalls[0] || len(dockCalls) != 1 || !dockCalls[0] {
		t.Fatalf("expected tray hidden and Dock shown, got tray=%v dock=%v", trayCalls, dockCalls)
	}
	if raw, ok := app.Storage().GetItem("govault.prefs"); !ok || !strings.Contains(raw, `"showTrayIcon":false`) {
		t.Fatalf("expected showTrayIcon persisted, got ok=%v raw=%q", ok, raw)
	}
}

func TestSearchCoversWholeVaultUnlessNarrowed(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	noteType := api.CipherTypeSecureNote
	app.Post(func() {
		model.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &noteType})
		model.SetSearchQuery("GitHub")
	})
	app.Settle()
	if n := model.FilteredItems.Len(); n != 1 || model.FilteredItems.KeyAt(0) != "c-github" {
		t.Fatalf("expected the global search to find GitHub outside Secure Notes, got %d items", n)
	}

	app.Post(func() { model.SetSearchInSection(true) })
	app.Settle()
	if n := model.FilteredItems.Len(); n != 0 {
		t.Fatalf("expected no Secure Note named GitHub when narrowed, got %d", n)
	}
}
