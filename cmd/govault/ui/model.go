package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

type SyncStatus int

const (
	SyncIdle SyncStatus = iota
	SyncInProgress
	SyncOffline
	SyncAuthExpired
)

type MainRoute int

const (
	RouteVault MainRoute = iota
	RouteGenerator
	RouteSettings
)

type UserPrefs struct {
	DeviceID              string                `json:"deviceId"`
	AccountID             string                `json:"accountId"`
	ServerURL             string                `json:"serverUrl"`
	Email                 string                `json:"email"`
	KDFSummary            string                `json:"kdfSummary"`
	BiometricEnabled      bool                  `json:"biometricEnabled"`
	AutoPromptBiometric   bool                  `json:"autoPromptBiometric"`
	AutoLockMinutes       int                   `json:"autoLockMinutes"`
	ClipboardClearSeconds int                   `json:"clipboardClearSeconds"`
	QuickAccessHotKey     string                `json:"quickAccessHotKey"`
	LaunchAtLogin         bool                  `json:"launchAtLogin"`
	HideDockIcon          bool                  `json:"hideDockIcon"`
	GeneratorMode         string                `json:"generatorMode"`
	PasswordOpts          gen.PasswordOptions   `json:"passwordOpts"`
	PassphraseOpts        gen.PassphraseOptions `json:"passphraseOpts"`
}

func DefaultUserPrefs() UserPrefs {
	return UserPrefs{
		AutoPromptBiometric:   true,
		AutoLockMinutes:       15,
		ClipboardClearSeconds: 30,
		QuickAccessHotKey:     "",
		GeneratorMode:         "password",
		PasswordOpts: gen.PasswordOptions{
			Length:         20,
			Uppercase:      true,
			Lowercase:      true,
			Numbers:        true,
			Special:        true,
			MinNumbers:     1,
			MinSpecial:     1,
			AvoidAmbiguous: false,
		},
		PassphraseOpts: gen.PassphraseOptions{
			NumWords:   4,
			Separator:  "-",
			Capitalize: true,
			IncludeNum: true,
		},
	}
}

type AccountSnapshotMeta struct {
	AccountID  string
	ServerURL  string
	Email      string
	KDFSummary string
	LastSyncAt time.Time
}

type PlatformHooks struct {
	Secrets              store.SecretStore
	CopySecret           func(secret string, clearAfter time.Duration) (concealed bool, err error)
	CopyPlain            func(text string)
	IsClipboardConcealed func() bool
	ApplyHotKey          func(shortcut string)
	SetLaunchAtLogin     func(on bool)
	SetDockVisible       func(on bool)
	OpenMainWindow       func()
	HideQuickPanel       func()
	ToggleQuickPanel     func()
	DiscoverSnapshot     func(preferredAccountID string) *AccountSnapshotMeta
	VerifyMasterPassword func(password []byte) error
}

type EditURIDraft struct {
	URI string
}

type EditFieldDraft struct {
	Name  string
	Value string
	Type  int
}

type EditDraft struct {
	ID         string
	IsNew      bool
	Type       api.CipherType
	Name       string
	FolderID   string
	Favorite   bool
	Reprompt   bool
	Notes      string
	Username   string
	Password   string
	TOTP       string
	URIs       []EditURIDraft
	Cardholder string
	Brand      string
	CardNumber string
	ExpMonth   string
	ExpYear    string
	CardCode   string
	IdentTitle string
	FirstName  string
	MiddleName string
	LastName   string
	Company    string
	Email      string
	Phone      string
	Address1   string
	City       string
	State      string
	PostalCode string
	Country    string
	IdentUser  string
	SSN        string
	Passport   string
	License    string
	Fields     []EditFieldDraft
	Revision   *time.Time
	Source     *state.Cipher
}

type RepromptModal struct {
	Open    bool
	Title   string
	Action  string
	OnAllow func()
}

type FolderModal struct {
	Open     bool
	FolderID string
	Name     string
}

type TOTPController struct {
	mu      sync.Mutex
	active  bool
	stopCh  chan struct{}
	cfg     *totp.TOTPConfig
	rawSeed string
}

func (tc *TOTPController) Active() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.active
}

func (tc *TOTPController) Update(raw string, onTick func(code string, remaining, period int)) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		tc.Stop()
		return
	}

	cfg, err := totp.ParseTOTP(trimmed)
	if err != nil {
		tc.Stop()
		return
	}

	tc.mu.Lock()
	if tc.active && tc.rawSeed == trimmed {
		tc.mu.Unlock()
		return
	}
	if tc.stopCh != nil {
		close(tc.stopCh)
	}
	stopCh := make(chan struct{})
	tc.stopCh = stopCh
	tc.cfg = cfg
	tc.rawSeed = trimmed
	tc.active = true
	tc.mu.Unlock()

	if code, rem, period, err := totp.Generate(cfg, time.Now()); err == nil {
		onTick(code, rem, period)
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				if code, rem, period, err := totp.Generate(cfg, now); err == nil {
					onTick(code, rem, period)
				}
			}
		}
	}()
}

func (tc *TOTPController) Stop() {
	tc.mu.Lock()
	if tc.stopCh != nil {
		close(tc.stopCh)
		tc.stopCh = nil
	}
	tc.active = false
	tc.cfg = nil
	tc.rawSeed = ""
	tc.mu.Unlock()
}

type IdleTimer struct {
	mu    sync.Mutex
	timer *time.Timer
}

func (it *IdleTimer) Reset(d time.Duration, fn func()) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.timer != nil {
		it.timer.Stop()
		it.timer = nil
	}
	if d <= 0 {
		return
	}
	it.timer = time.AfterFunc(d, fn)
}

func (it *IdleTimer) Stop() {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.timer != nil {
		it.timer.Stop()
		it.timer = nil
	}
}

type AppModel struct {
	Scope *core.Scope
	Core  state.VaultService
	Hooks PlatformHooks
	Prefs *core.Persisted[UserPrefs]

	LockState *core.Signal[state.LockStatus]
	SyncState *core.Signal[SyncStatus]
	LastSync  *core.Signal[time.Time]
	Route     *core.Signal[MainRoute]

	BiometricKind *core.Signal[core.BiometricKind]
	HotKeyStatus  *core.Signal[string]

	LoginServer   *core.Signal[string]
	LoginEmail    *core.Signal[string]
	LoginPassword *core.Signal[string]
	LoginBusy     *core.Signal[bool]
	LoginError    *core.Signal[string]
	LoginShowPW   *core.Signal[bool]

	LockPassword    *core.Signal[string]
	LockBusy        *core.Signal[bool]
	LockError       *core.Signal[string]
	LockShowPW      *core.Signal[bool]
	LockAutoFired   bool
	LockPasswordRef core.Ref

	SidebarFilter *core.Signal[state.SearchFilter]
	SearchQuery   *core.Signal[string]
	SearchRef     core.Ref
	Folders       *core.Signal[[]state.Folder]
	AllCounts     *core.Signal[VaultCounts]
	FilteredItems *core.Collection[string, state.CipherSummary]
	SelectedID    *core.Signal[string]
	IsSelected    func(id string) bool
	ActiveCipher  *core.Signal[*state.Cipher]
	RevealPW      *core.Signal[bool]
	RevealCard    *core.Signal[bool]

	EditMode  *core.Signal[bool]
	EditDraft *core.Signal[*EditDraft]
	EditDirty *core.Signal[bool]
	EditBusy  *core.Signal[bool]
	EditError *core.Signal[string]

	TOTPCode      *core.Signal[string]
	TOTPRemaining *core.Signal[int]
	TOTPPeriod    *core.Signal[int]

	MainWinVisible    *core.Signal[bool]
	QuickPanelVisible *core.Signal[bool]

	QuickQuery       *core.Signal[string]
	QuickItems       *core.Signal[[]state.CipherSummary]
	QuickSelectedIdx *core.Signal[int]
	QuickSearchRef   core.Ref
	QuickPassword    *core.Signal[string]
	QuickUnlockBusy  *core.Signal[bool]
	QuickUnlockError *core.Signal[string]

	GenResult *core.Signal[string]

	RecordingHotKey *core.Signal[bool]

	Reprompt      *core.Signal[RepromptModal]
	RepromptPW    *core.Signal[string]
	RepromptError *core.Signal[string]
	RepromptBusy  *core.Signal[bool]

	FolderDialog *core.Signal[FolderModal]
	FolderError  *core.Signal[string]
	FolderBusy   *core.Signal[bool]

	Toaster *ui.Toaster

	totpCtrl  TOTPController
	idleTimer IdleTimer
}

type VaultCounts struct {
	All        int
	Favorites  int
	Trash      int
	NoFolder   int
	Login      int
	Card       int
	Identity   int
	SecureNote int
	ByFolder   map[string]int
}

func NewAppModel(app *core.Scope, coreSvc state.VaultService, hooks PlatformHooks) *AppModel {
	prefs := core.NewPersisted(app, "govault.prefs", DefaultUserPrefs(), core.PersistOptions{Version: 1})
	p := prefs.Get()
	if p.DeviceID == "" {
		p.DeviceID = newDeviceUUID()
		_ = prefs.Set(p)
	}

	m := &AppModel{
		Scope:             app,
		Core:              coreSvc,
		Hooks:             hooks,
		Prefs:             prefs,
		LockState:         core.NewSignal(app, coreSvc.Status()),
		SyncState:         core.NewSignal(app, SyncIdle),
		LastSync:          core.NewSignal(app, time.Time{}),
		Route:             core.NewSignal(app, RouteVault),
		BiometricKind:     core.NewSignal(app, core.BiometricNone),
		HotKeyStatus:      core.NewSignal(app, "Disabled"),
		LoginServer:       core.NewSignal(app, p.ServerURL),
		LoginEmail:        core.NewSignal(app, p.Email),
		LoginPassword:     core.NewSignal(app, ""),
		LoginBusy:         core.NewSignal(app, false),
		LoginError:        core.NewSignal(app, ""),
		LoginShowPW:       core.NewSignal(app, false),
		LockPassword:      core.NewSignal(app, ""),
		LockBusy:          core.NewSignal(app, false),
		LockError:         core.NewSignal(app, ""),
		LockShowPW:        core.NewSignal(app, false),
		SidebarFilter:     core.NewSignal(app, state.SearchFilter{Category: state.FilterAll}),
		SearchQuery:       core.NewSignal(app, ""),
		Folders:           core.NewSignalFunc(app, []state.Folder(nil), nil),
		AllCounts:         core.NewSignalFunc(app, VaultCounts{ByFolder: map[string]int{}}, nil),
		FilteredItems:     core.NewCollectionFunc(app, func(c state.CipherSummary) string { return c.ID }, cipherSummaryEqual, nil),
		SelectedID:        core.NewSignal(app, ""),
		ActiveCipher:      core.NewSignal[*state.Cipher](app, nil),
		RevealPW:          core.NewSignal(app, false),
		RevealCard:        core.NewSignal(app, false),
		EditMode:          core.NewSignal(app, false),
		EditDraft:         core.NewSignal[*EditDraft](app, nil),
		EditDirty:         core.NewSignal(app, false),
		EditBusy:          core.NewSignal(app, false),
		EditError:         core.NewSignal(app, ""),
		TOTPCode:          core.NewSignal(app, ""),
		TOTPRemaining:     core.NewSignal(app, 0),
		TOTPPeriod:        core.NewSignal(app, 30),
		MainWinVisible:    core.NewSignal(app, false),
		QuickPanelVisible: core.NewSignal(app, false),
		QuickQuery:        core.NewSignal(app, ""),
		QuickItems:        core.NewSignalFunc(app, []state.CipherSummary(nil), nil),
		QuickSelectedIdx:  core.NewSignal(app, 0),
		QuickPassword:     core.NewSignal(app, ""),
		QuickUnlockBusy:   core.NewSignal(app, false),
		QuickUnlockError:  core.NewSignal(app, ""),
		GenResult:         core.NewSignal(app, ""),
		RecordingHotKey:   core.NewSignal(app, false),
		Reprompt:          core.NewSignalFunc(app, RepromptModal{}, nil),
		RepromptPW:        core.NewSignal(app, ""),
		RepromptError:     core.NewSignal(app, ""),
		RepromptBusy:      core.NewSignal(app, false),
		FolderDialog:      core.NewSignal(app, FolderModal{}),
		FolderError:       core.NewSignal(app, ""),
		FolderBusy:        core.NewSignal(app, false),
		Toaster:           ui.NewToaster(app),
	}
	m.IsSelected = core.NewSelector(app, m.SelectedID.Get)

	m.RegenerateSecret()

	app.BiometricAvailability(func(kind core.BiometricKind) {
		m.BiometricKind.Set(kind)
	})

	app.Effect(func() {
		m.reconcileTOTPTicker()
	})

	app.Effect(func() {
		lock := m.LockState.Get()
		mins := m.Prefs.Get().AutoLockMinutes
		if lock == state.StatusUnlocked && mins > 0 {
			m.ResetIdleTimer()
		} else {
			m.idleTimer.Stop()
		}
	})

	app.Cleanup(func() {
		m.totpCtrl.Stop()
		m.idleTimer.Stop()
	})

	if m.LockState.Get() == state.StatusUnlocked {
		m.RefreshVaultData()
	}

	return m
}

func cipherSummaryEqual(a, b state.CipherSummary) bool {
	if a.ID != b.ID || a.Type != b.Type || a.Favorite != b.Favorite || a.Deleted != b.Deleted ||
		a.Name != b.Name || a.Subtitle != b.Subtitle || a.HasTOTP != b.HasTOTP || a.Reprompt != b.Reprompt {
		return false
	}
	if a.FolderID == nil && b.FolderID == nil {
		return true
	}
	if a.FolderID == nil || b.FolderID == nil {
		return false
	}
	return *a.FolderID == *b.FolderID
}

func (m *AppModel) TOTPTickerActive() bool {
	return m.totpCtrl.Active()
}

func (m *AppModel) reconcileTOTPTicker() {
	lock := m.LockState.Get()
	mainVis := m.MainWinVisible.Get()
	quickVis := m.QuickPanelVisible.Get()
	route := m.Route.Get()
	edit := m.EditMode.Get()
	active := m.ActiveCipher.Get()
	quickItems := m.QuickItems.Get()
	quickIdx := m.QuickSelectedIdx.Get()

	if lock != state.StatusUnlocked {
		m.stopTOTP()
		return
	}

	var totpSeed string
	if mainVis && route == RouteVault && !edit && active != nil && active.Login != nil && strings.TrimSpace(active.Login.TOTP) != "" {
		totpSeed = active.Login.TOTP
	} else if quickVis && quickIdx >= 0 && quickIdx < len(quickItems) && quickItems[quickIdx].HasTOTP {
		if c, err := m.Core.GetCipher(quickItems[quickIdx].ID); err == nil && c.Login != nil {
			totpSeed = c.Login.TOTP
		}
	}

	if totpSeed == "" {
		m.stopTOTP()
		return
	}

	m.totpCtrl.Update(totpSeed, func(code string, remaining, period int) {
		m.Scope.Post(func() {
			if m.LockState.Get() != state.StatusUnlocked {
				return
			}
			m.TOTPCode.Set(code)
			m.TOTPRemaining.Set(remaining)
			m.TOTPPeriod.Set(period)
		})
	})
}

func (m *AppModel) stopTOTP() {
	m.totpCtrl.Stop()
	m.TOTPCode.Set("")
	m.TOTPRemaining.Set(0)
}

func (m *AppModel) ResetIdleTimer() {
	if m.LockState.Get() != state.StatusUnlocked {
		m.idleTimer.Stop()
		return
	}
	mins := m.Prefs.Get().AutoLockMinutes
	if mins <= 0 {
		m.idleTimer.Stop()
		return
	}
	m.idleTimer.Reset(time.Duration(mins)*time.Minute, func() {
		m.Scope.Post(func() {
			if m.LockState.Get() == state.StatusUnlocked {
				m.Lock()
				m.ShowToast(ui.ToastInfo, "Vault locked", "Locked automatically due to inactivity.")
			}
		})
	})
}

func (m *AppModel) ShowToast(kind ui.ToastType, title, desc string) {
	if m.Toaster == nil {
		return
	}
	m.Toaster.Show(ui.ToastContent{
		Type:        kind,
		Title:       title,
		Description: desc,
		Duration:    3 * time.Second,
	})
}

func (m *AppModel) CanUseBiometric() bool {
	k := m.BiometricKind.Get()
	return k == core.BiometricFingerprint || k == core.BiometricFace
}

func (m *AppModel) BiometricLabel() string {
	switch m.BiometricKind.Get() {
	case core.BiometricFace:
		return "Face ID"
	case core.BiometricFingerprint:
		return "Touch ID"
	default:
		return "Biometric"
	}
}

func (m *AppModel) UpdatePrefs(fn func(p UserPrefs) UserPrefs) {
	_ = m.Prefs.Update(fn)
}

func (m *AppModel) SetQuickAccessHotKey(shortcut string) {
	trimmed := strings.TrimSpace(shortcut)
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.QuickAccessHotKey = trimmed
		return p
	})
	if m.Hooks.ApplyHotKey != nil {
		m.Hooks.ApplyHotKey(trimmed)
	}
	if trimmed == "" {
		m.HotKeyStatus.Set("Disabled")
	}
}

func (m *AppModel) SyncAccountMetaFromSnapshot() {
	if m.Hooks.DiscoverSnapshot == nil {
		return
	}
	meta := m.Hooks.DiscoverSnapshot(m.Prefs.Get().AccountID)
	if meta == nil {
		return
	}
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.AccountID = meta.AccountID
		if meta.ServerURL != "" {
			p.ServerURL = meta.ServerURL
		}
		if meta.Email != "" {
			p.Email = meta.Email
		}
		if meta.KDFSummary != "" {
			p.KDFSummary = meta.KDFSummary
		}
		return p
	})
	if !meta.LastSyncAt.IsZero() {
		m.LastSync.Set(meta.LastSyncAt)
	}
}

func (m *AppModel) Login() {
	if m.LoginBusy.Get() {
		return
	}
	serverURL := strings.TrimSpace(m.LoginServer.Get())
	email := strings.TrimSpace(m.LoginEmail.Get())
	password := m.LoginPassword.Get()
	if serverURL == "" || email == "" || password == "" {
		m.LoginError.Set("Server URL, email, and master password are required.")
		return
	}

	m.LoginBusy.Set(true)
	m.LoginError.Set("")
	pwBytes := []byte(password)

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		err := m.Core.Login(context.Background(), serverURL, email, pwBytes)
		m.Scope.Post(func() {
			m.LoginBusy.Set(false)
			if err != nil {
				m.LoginError.Set(friendlyError(err))
				return
			}
			m.LoginPassword.Set("")
			m.UpdatePrefs(func(p UserPrefs) UserPrefs {
				p.ServerURL = strings.TrimRight(serverURL, "/")
				p.Email = email
				return p
			})
			m.SyncAccountMetaFromSnapshot()
			m.LastSync.Set(time.Now())
			m.SyncState.Set(SyncIdle)
			m.LockState.Set(state.StatusUnlocked)
			m.Route.Set(RouteVault)
			m.RefreshVaultData()
			m.ResetIdleTimer()
		})
	}()
}

func (m *AppModel) UnlockWithPassword(fromQuickPanel bool) {
	if fromQuickPanel {
		if m.QuickUnlockBusy.Get() {
			return
		}
	} else if m.LockBusy.Get() {
		return
	}

	var password string
	if fromQuickPanel {
		password = m.QuickPassword.Get()
	} else {
		password = m.LockPassword.Get()
	}
	if password == "" {
		if fromQuickPanel {
			m.QuickUnlockError.Set("Enter your master password.")
		} else {
			m.LockError.Set("Enter your master password.")
		}
		return
	}

	if fromQuickPanel {
		m.QuickUnlockBusy.Set(true)
		m.QuickUnlockError.Set("")
	} else {
		m.LockBusy.Set(true)
		m.LockError.Set("")
	}
	pwBytes := []byte(password)

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		err := m.Core.UnlockWithPassword(context.Background(), pwBytes)
		m.Scope.Post(func() {
			m.LockBusy.Set(false)
			m.QuickUnlockBusy.Set(false)
			if err != nil {
				msg := friendlyError(err)
				if fromQuickPanel {
					m.QuickUnlockError.Set(msg)
				} else {
					m.LockError.Set(msg)
				}
				return
			}
			m.LockPassword.Set("")
			m.QuickPassword.Set("")
			m.LockAutoFired = false
			m.LockState.Set(state.StatusUnlocked)
			m.RefreshVaultData()
			m.ResetIdleTimer()
			m.SyncNow(true)
		})
	}()
}

func (m *AppModel) UnlockWithBiometric(cx *core.Scope, fromQuickPanel bool) {
	if !m.CanUseBiometric() || !m.Prefs.Get().BiometricEnabled || m.Hooks.Secrets == nil {
		return
	}
	accountID := m.Prefs.Get().AccountID
	if accountID == "" {
		return
	}
	if fromQuickPanel {
		m.QuickUnlockBusy.Set(true)
		m.QuickUnlockError.Set("")
	} else {
		m.LockBusy.Set(true)
		m.LockError.Set("")
	}

	cx.AuthenticateBiometric("Unlock GoVault", func(res core.BiometricResult) {
		if res != core.BiometricSuccess {
			m.LockBusy.Set(false)
			m.QuickUnlockBusy.Set(false)
			if res != core.BiometricCancelled {
				msg := "Biometric authentication failed. Enter master password."
				if fromQuickPanel {
					m.QuickUnlockError.Set(msg)
				} else {
					m.LockError.Set(msg)
				}
			}
			if !fromQuickPanel {
				m.LockPasswordRef.Focus()
			}
			return
		}

		secrets := m.Hooks.Secrets
		go func() {
			encoded, ok, err := secrets.Get("userkey:" + accountID)
			if err != nil || !ok || encoded == "" {
				m.Scope.Post(func() {
					m.LockBusy.Set(false)
					m.QuickUnlockBusy.Set(false)
					msg := "Saved biometric key unavailable. Unlock with master password."
					if fromQuickPanel {
						m.QuickUnlockError.Set(msg)
					} else {
						m.LockError.Set(msg)
					}
					if !fromQuickPanel {
						m.LockPasswordRef.Focus()
					}
				})
				return
			}

			raw, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				m.Scope.Post(func() {
					m.LockBusy.Set(false)
					m.QuickUnlockBusy.Set(false)
					m.LockError.Set("Corrupt biometric key. Unlock with master password.")
				})
				return
			}
			defer crypto.ZeroBytes(raw)

			key, err := crypto.SymmetricKeyFromBytes(raw)
			if err != nil {
				m.Scope.Post(func() {
					m.LockBusy.Set(false)
					m.QuickUnlockBusy.Set(false)
					m.LockError.Set("Invalid biometric key. Unlock with master password.")
				})
				return
			}
			defer key.Zero()

			err = m.Core.UnlockWithUserKey(context.Background(), key)
			m.Scope.Post(func() {
				m.LockBusy.Set(false)
				m.QuickUnlockBusy.Set(false)
				if err != nil {
					if fromQuickPanel {
						m.QuickUnlockError.Set(friendlyError(err))
					} else {
						m.LockError.Set(friendlyError(err))
					}
					return
				}
				m.LockPassword.Set("")
				m.QuickPassword.Set("")
				m.LockAutoFired = false
				m.LockState.Set(state.StatusUnlocked)
				m.RefreshVaultData()
				m.ResetIdleTimer()
				m.SyncNow(true)
			})
		}()
	})
}

func (m *AppModel) ToggleBiometric(cx *core.Scope, enable bool) {
	if m.Hooks.Secrets == nil {
		m.ShowToast(ui.ToastError, "Keychain unavailable", "Cannot access system keychain.")
		return
	}
	if !enable {
		secrets := m.Hooks.Secrets
		go func() {
			err := m.Core.DisableBiometricUnlock(secrets)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Disable failed", err.Error())
					return
				}
				m.UpdatePrefs(func(p UserPrefs) UserPrefs {
					p.BiometricEnabled = false
					return p
				})
				m.ShowToast(ui.ToastInfo, m.BiometricLabel()+" disabled", "")
			})
		}()
		return
	}

	cx.AuthenticateBiometric("Enable "+m.BiometricLabel()+" for GoVault", func(res core.BiometricResult) {
		if res != core.BiometricSuccess {
			return
		}
		secrets := m.Hooks.Secrets
		go func() {
			err := m.Core.EnableBiometricUnlock(secrets)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Enable failed", err.Error())
					return
				}
				m.UpdatePrefs(func(p UserPrefs) UserPrefs {
					p.BiometricEnabled = true
					return p
				})
				m.ShowToast(ui.ToastSuccess, m.BiometricLabel()+" enabled", "You can now unlock GoVault with "+m.BiometricLabel()+".")
			})
		}()
	})
}

func (m *AppModel) Lock() {
	m.Core.Lock()
	m.stopTOTP()
	m.idleTimer.Stop()
	m.LockAutoFired = false
	m.LockState.Set(m.Core.Status())
	m.ActiveCipher.Set(nil)
	m.SelectedID.Set("")
	m.EditMode.Set(false)
	m.EditDraft.Set(nil)
	m.EditDirty.Set(false)
	m.RevealPW.Set(false)
	m.RevealCard.Set(false)
	m.SearchQuery.Set("")
	m.QuickQuery.Set("")
	m.QuickItems.Set(nil)
	m.Folders.Set(nil)
	m.FilteredItems.Replace(nil)
	m.AllCounts.Set(VaultCounts{ByFolder: map[string]int{}})
}

func (m *AppModel) Logout(cx *core.Scope) {
	cx.ShowAlert(core.AlertConfig{
		Title:   "Log out of GoVault?",
		Message: "Your local encrypted vault cache and saved biometric key will be removed from this device.",
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Log Out", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		secrets := m.Hooks.Secrets
		go func() {
			_ = m.Core.Logout(context.Background(), secrets)
			m.Scope.Post(func() {
				m.Lock()
				m.LockState.Set(state.StatusLoggedOut)
				m.UpdatePrefs(func(p UserPrefs) UserPrefs {
					p.AccountID = ""
					p.BiometricEnabled = false
					return p
				})
				m.Route.Set(RouteVault)
			})
		}()
	})
}

func (m *AppModel) SyncNow(silent bool) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncInProgress {
		return
	}
	m.SyncState.Set(SyncInProgress)
	go func() {
		err := m.Core.SyncNow(context.Background())
		m.Scope.Post(func() {
			if m.LockState.Get() != state.StatusUnlocked {
				m.SyncState.Set(SyncIdle)
				return
			}
			if err != nil {
				switch {
				case errors.Is(err, api.ErrUnauthorized):
					m.SyncState.Set(SyncAuthExpired)
					if !silent {
						m.ShowToast(ui.ToastWarning, "Session expired", "Sign in again to resume syncing.")
					}
				case errors.Is(err, api.ErrNetworkOffline):
					m.SyncState.Set(SyncOffline)
					if !silent {
						m.ShowToast(ui.ToastWarning, "Offline", "Showing cached vault.")
					}
				default:
					m.SyncState.Set(SyncOffline)
					if !silent {
						m.ShowToast(ui.ToastError, "Sync failed", friendlyError(err))
					}
				}
				return
			}
			m.SyncState.Set(SyncIdle)
			m.LastSync.Set(time.Now())
			m.RefreshVaultData()
			if !silent {
				m.ShowToast(ui.ToastSuccess, "Vault synced", "")
			}
		})
	}()
}

func (m *AppModel) RefreshVaultData() {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	folders := m.Core.Folders()
	m.Folders.Set(folders)
	m.recomputeCounts()
	m.RefreshFilteredList()
	m.RefreshQuickItems()

	selID := m.SelectedID.Get()
	if selID != "" {
		if c, err := m.Core.GetCipher(selID); err == nil {
			m.ActiveCipher.Set(c)
		} else {
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
		}
	}
}

func (m *AppModel) recomputeCounts() {
	all := m.Core.Search("", state.SearchFilter{Category: state.FilterAll})
	trash := m.Core.Search("", state.SearchFilter{Category: state.FilterTrash})
	counts := VaultCounts{
		All:      len(all),
		Trash:    len(trash),
		ByFolder: make(map[string]int),
	}
	for _, item := range all {
		if item.Favorite {
			counts.Favorites++
		}
		if item.FolderID == nil || *item.FolderID == "" {
			counts.NoFolder++
		} else {
			counts.ByFolder[*item.FolderID]++
		}
		switch item.Type {
		case api.CipherTypeLogin:
			counts.Login++
		case api.CipherTypeCard:
			counts.Card++
		case api.CipherTypeIdentity:
			counts.Identity++
		case api.CipherTypeSecureNote:
			counts.SecureNote++
		}
	}
	m.AllCounts.Set(counts)
}

func (m *AppModel) RefreshFilteredList() {
	if m.LockState.Get() != state.StatusUnlocked {
		m.FilteredItems.Replace(nil)
		return
	}
	items := m.Core.Search(m.SearchQuery.Get(), m.SidebarFilter.Get())
	m.FilteredItems.Replace(items)
}

func (m *AppModel) RefreshQuickItems() {
	if m.LockState.Get() != state.StatusUnlocked {
		m.QuickItems.Set(nil)
		m.QuickSelectedIdx.Set(0)
		return
	}
	items := m.Core.Search(m.QuickQuery.Get(), state.SearchFilter{Category: state.FilterAll})
	if len(items) > 12 {
		items = items[:12]
	}
	m.QuickItems.Set(items)
	if m.QuickSelectedIdx.Get() >= len(items) {
		m.QuickSelectedIdx.Set(0)
	}
}

func (m *AppModel) SetSearchQuery(q string) {
	m.ResetIdleTimer()
	m.SearchQuery.Set(q)
	m.RefreshFilteredList()
}

func (m *AppModel) SetSidebarFilter(f state.SearchFilter) {
	m.ResetIdleTimer()
	m.Route.Set(RouteVault)
	m.SidebarFilter.Set(f)
	m.RefreshFilteredList()
}

func (m *AppModel) GuardDirty(cx *core.Scope, proceed func()) {
	if !m.EditMode.Get() || !m.EditDirty.Get() {
		proceed()
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   "Discard unsaved changes?",
		Message: "Your edits to this item have not been saved.",
		Actions: []core.AlertAction{
			{Label: "Keep Editing", Role: core.AlertCancel},
			{Label: "Discard", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx == 1 {
			m.EditMode.Set(false)
			m.EditDraft.Set(nil)
			m.EditDirty.Set(false)
			m.EditError.Set("")
			proceed()
		}
	})
}

func (m *AppModel) SelectCipher(cx *core.Scope, id string) {
	m.ResetIdleTimer()
	if id == m.SelectedID.Get() && !m.EditMode.Get() {
		return
	}
	m.GuardDirty(cx, func() {
		m.SelectedID.Set(id)
		m.RevealPW.Set(false)
		m.RevealCard.Set(false)
		if id == "" {
			m.ActiveCipher.Set(nil)
			return
		}
		c, err := m.Core.GetCipher(id)
		if err != nil {
			m.ActiveCipher.Set(nil)
			return
		}
		m.ActiveCipher.Set(c)
	})
}

func (m *AppModel) MoveListSelection(cx *core.Scope, delta int) {
	n := m.FilteredItems.Len()
	if n == 0 {
		return
	}
	cur := m.SelectedID.Get()
	idx := -1
	for i := range n {
		if m.FilteredItems.KeyAt(i) == cur {
			idx = i
			break
		}
	}
	next := idx + delta
	if idx == -1 {
		if delta > 0 {
			next = 0
		} else {
			next = n - 1
		}
	}
	if next < 0 {
		next = 0
	}
	if next >= n {
		next = n - 1
	}
	m.SelectCipher(cx, m.FilteredItems.KeyAt(next))
}

func (m *AppModel) StartCreateCipher(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	m.GuardDirty(cx, func() {
		m.Route.Set(RouteVault)
		f := m.SidebarFilter.Get()
		ct := api.CipherTypeLogin
		if f.Type != nil {
			ct = *f.Type
		}
		draft := &EditDraft{
			IsNew:    true,
			Type:     ct,
			FolderID: f.FolderID,
			URIs:     []EditURIDraft{{URI: ""}},
		}
		m.EditDraft.Set(draft)
		m.EditDirty.Set(false)
		m.EditError.Set("")
		m.EditMode.Set(true)
	})
}

func (m *AppModel) StartEditCipher(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if c == nil || c.DeletedDate != nil {
		return
	}
	m.ResetIdleTimer()
	m.EditDraft.Set(draftFromCipher(c))
	m.EditDirty.Set(false)
	m.EditError.Set("")
	m.EditMode.Set(true)
}

func (m *AppModel) CancelEdit(cx *core.Scope) {
	m.GuardDirty(cx, func() {
		m.EditMode.Set(false)
		m.EditDraft.Set(nil)
		m.EditDirty.Set(false)
		m.EditError.Set("")
	})
}

func (m *AppModel) MutateDraft(fn func(d *EditDraft)) {
	cur := m.EditDraft.Get()
	if cur == nil {
		return
	}
	cp := cloneDraft(cur)
	fn(cp)
	m.EditDraft.Set(cp)
	m.EditDirty.Set(true)
	m.ResetIdleTimer()
}

func (m *AppModel) SaveDraft(cx *core.Scope) {
	draft := m.EditDraft.Get()
	if draft == nil || m.EditBusy.Get() {
		return
	}
	if strings.TrimSpace(draft.Name) == "" {
		m.EditError.Set("Name is required.")
		return
	}
	if m.SyncState.Get() == SyncOffline {
		m.EditError.Set("Cannot save while offline.")
		return
	}

	cipher := cipherFromDraft(draft)
	m.EditBusy.Set(true)
	m.EditError.Set("")

	go func() {
		saved, err := m.Core.SaveCipher(context.Background(), cipher)
		m.Scope.Post(func() {
			m.EditBusy.Set(false)
			if err != nil {
				if errors.Is(err, api.ErrRevisionConflict) {
					cx.ShowAlert(core.AlertConfig{
						Title:   "Item changed on another device",
						Message: "This item was updated elsewhere since your last sync. Reload the latest version to avoid overwriting changes.",
						Actions: []core.AlertAction{
							{Label: "Cancel", Role: core.AlertCancel},
							{Label: "Reload Latest", Role: core.AlertDefault},
						},
						Cancelable: true,
					}, func(idx int) {
						if idx == 1 {
							m.EditMode.Set(false)
							m.EditDraft.Set(nil)
							m.EditDirty.Set(false)
							m.SyncNow(false)
						}
					})
					return
				}
				m.EditError.Set(friendlyError(err))
				return
			}
			m.EditMode.Set(false)
			m.EditDraft.Set(nil)
			m.EditDirty.Set(false)
			m.EditError.Set("")
			m.RefreshVaultData()
			if saved != nil {
				m.SelectedID.Set(saved.ID)
				m.ActiveCipher.Set(saved)
			}
			m.ShowToast(ui.ToastSuccess, "Item saved", "")
		})
	}()
}

func (m *AppModel) ToggleFavorite() {
	c := m.ActiveCipher.Get()
	if c == nil || c.DeletedDate != nil || m.SyncState.Get() == SyncOffline {
		return
	}
	cp := *c
	cp.Favorite = !cp.Favorite
	go func() {
		saved, err := m.Core.SaveCipher(context.Background(), &cp)
		m.Scope.Post(func() {
			if err != nil {
				m.ShowToast(ui.ToastError, "Update failed", friendlyError(err))
				return
			}
			m.RefreshVaultData()
			if saved != nil {
				m.ActiveCipher.Set(saved)
			}
		})
	}()
}

func (m *AppModel) SoftDeleteActive() {
	c := m.ActiveCipher.Get()
	if c == nil || m.SyncState.Get() == SyncOffline {
		return
	}
	id := c.ID
	go func() {
		err := m.Core.SoftDeleteCipher(context.Background(), id)
		m.Scope.Post(func() {
			if err != nil {
				m.ShowToast(ui.ToastError, "Move to Trash failed", friendlyError(err))
				return
			}
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
			m.RefreshVaultData()
			m.ShowToast(ui.ToastInfo, "Moved to Trash", "")
		})
	}()
}

func (m *AppModel) RestoreActive() {
	c := m.ActiveCipher.Get()
	if c == nil || m.SyncState.Get() == SyncOffline {
		return
	}
	id := c.ID
	go func() {
		err := m.Core.RestoreCipher(context.Background(), id)
		m.Scope.Post(func() {
			if err != nil {
				m.ShowToast(ui.ToastError, "Restore failed", friendlyError(err))
				return
			}
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
			m.RefreshVaultData()
			m.ShowToast(ui.ToastSuccess, "Item restored", "")
		})
	}()
}

func (m *AppModel) HardDeleteActive(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if c == nil || m.SyncState.Get() == SyncOffline {
		return
	}
	id := c.ID
	name := c.Name
	cx.ShowAlert(core.AlertConfig{
		Title:   "Delete permanently?",
		Message: fmt.Sprintf("%q will be permanently deleted and cannot be recovered.", name),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Permanently", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		go func() {
			err := m.Core.HardDeleteCipher(context.Background(), id)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Delete failed", friendlyError(err))
					return
				}
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
				m.RefreshVaultData()
				m.ShowToast(ui.ToastInfo, "Permanently deleted", "")
			})
		}()
	})
}

func (m *AppModel) OpenNewFolderModal() {
	m.FolderError.Set("")
	m.FolderDialog.Set(FolderModal{Open: true})
}

func (m *AppModel) OpenRenameFolderModal(f state.Folder) {
	m.FolderError.Set("")
	m.FolderDialog.Set(FolderModal{Open: true, FolderID: f.ID, Name: f.Name})
}

func (m *AppModel) SaveFolderModal() {
	dlg := m.FolderDialog.Get()
	name := strings.TrimSpace(dlg.Name)
	if name == "" {
		m.FolderError.Set("Folder name is required.")
		return
	}
	if m.FolderBusy.Get() {
		return
	}
	m.FolderBusy.Set(true)
	m.FolderError.Set("")
	f := &state.Folder{ID: dlg.FolderID, Name: name}
	go func() {
		_, err := m.Core.SaveFolder(context.Background(), f)
		m.Scope.Post(func() {
			m.FolderBusy.Set(false)
			if err != nil {
				m.FolderError.Set(friendlyError(err))
				return
			}
			m.FolderDialog.Set(FolderModal{})
			m.RefreshVaultData()
			m.ShowToast(ui.ToastSuccess, "Folder saved", "")
		})
	}()
}

func (m *AppModel) DeleteFolder(cx *core.Scope, f state.Folder) {
	cx.ShowAlert(core.AlertConfig{
		Title:   "Delete folder?",
		Message: fmt.Sprintf("Items inside %q will be moved to No Folder.", f.Name),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Folder", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		go func() {
			err := m.Core.DeleteFolder(context.Background(), f.ID)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Delete folder failed", friendlyError(err))
					return
				}
				cur := m.SidebarFilter.Get()
				if cur.FolderID == f.ID {
					m.SidebarFilter.Set(state.SearchFilter{Category: state.FilterAll})
				}
				m.RefreshVaultData()
				m.ShowToast(ui.ToastInfo, "Folder deleted", "")
			})
		}()
	})
}

func (m *AppModel) GateReprompt(cx *core.Scope, cipher *state.Cipher, actionLabel string, onAllow func()) {
	if cipher == nil || cipher.Reprompt != 1 {
		onAllow()
		return
	}
	if m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled {
		cx.AuthenticateBiometric("Verify to "+actionLabel, func(res core.BiometricResult) {
			if res == core.BiometricSuccess {
				onAllow()
			} else if res != core.BiometricCancelled {
				m.openRepromptDialog(actionLabel, onAllow)
			}
		})
		return
	}
	m.openRepromptDialog(actionLabel, onAllow)
}

func (m *AppModel) openRepromptDialog(actionLabel string, onAllow func()) {
	m.RepromptPW.Set("")
	m.RepromptError.Set("")
	m.Reprompt.Set(RepromptModal{
		Open:    true,
		Title:   "Master Password Verification",
		Action:  actionLabel,
		OnAllow: onAllow,
	})
}

func (m *AppModel) SubmitReprompt() {
	if m.RepromptBusy.Get() {
		return
	}
	pw := m.RepromptPW.Get()
	if pw == "" {
		m.RepromptError.Set("Enter your master password.")
		return
	}
	if m.Hooks.VerifyMasterPassword == nil {
		m.RepromptError.Set("Master password verification is unavailable.")
		return
	}
	m.RepromptBusy.Set(true)
	m.RepromptError.Set("")
	pwBytes := []byte(pw)
	cb := m.Reprompt.Get().OnAllow

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		err := m.Hooks.VerifyMasterPassword(pwBytes)
		m.Scope.Post(func() {
			m.RepromptBusy.Set(false)
			if err != nil {
				m.RepromptError.Set("Incorrect master password.")
				return
			}
			m.RepromptPW.Set("")
			m.Reprompt.Set(RepromptModal{})
			if cb != nil {
				cb()
			}
		})
	}()
}

func (m *AppModel) CopySecretValue(label, secret string) {
	if secret == "" {
		return
	}
	m.ResetIdleTimer()
	secs := m.Prefs.Get().ClipboardClearSeconds
	clearAfter := time.Duration(secs) * time.Second
	var concealed bool
	if m.Hooks.CopySecret != nil {
		var err error
		concealed, err = m.Hooks.CopySecret(secret, clearAfter)
		if err != nil {
			m.ShowToast(ui.ToastError, "Copy failed", err.Error())
			return
		}
	} else {
		m.Scope.SetClipboard(secret)
	}
	desc := ""
	if secs > 0 {
		if concealed {
			desc = fmt.Sprintf("Concealed · clears in %ds", secs)
		} else {
			desc = fmt.Sprintf("Clears in %ds", secs)
		}
	} else if concealed {
		desc = "Concealed from clipboard history"
	}
	m.ShowToast(ui.ToastSuccess, label+" copied", desc)
}

func (m *AppModel) CopyPlainValue(label, text string) {
	if text == "" {
		return
	}
	m.ResetIdleTimer()
	if m.Hooks.CopyPlain != nil {
		m.Hooks.CopyPlain(text)
	} else {
		m.Scope.SetClipboard(text)
	}
	m.ShowToast(ui.ToastInfo, label+" copied", "")
}

func (m *AppModel) RegenerateSecret() {
	p := m.Prefs.Get()
	var out string
	var err error
	if p.GeneratorMode == "passphrase" {
		out, err = gen.GeneratePassphrase(p.PassphraseOpts)
	} else {
		out, err = gen.GeneratePassword(p.PasswordOpts)
	}
	if err != nil {
		m.GenResult.Set("")
		return
	}
	m.GenResult.Set(out)
}

func (m *AppModel) GenerateInlinePassword() string {
	pw, err := gen.GeneratePassword(m.Prefs.Get().PasswordOpts)
	if err != nil {
		pw, _ = gen.GeneratePassword(DefaultUserPrefs().PasswordOpts)
	}
	return pw
}

func draftFromCipher(c *state.Cipher) *EditDraft {
	d := &EditDraft{
		ID:       c.ID,
		IsNew:    false,
		Type:     c.Type,
		Name:     c.Name,
		Favorite: c.Favorite,
		Reprompt: c.Reprompt == 1,
		Notes:    c.Notes,
		Revision: c.RevisionDate,
		Source:   c,
	}
	if c.FolderID != nil {
		d.FolderID = *c.FolderID
	}
	if c.Login != nil {
		d.Username = c.Login.Username
		d.Password = c.Login.Password
		d.TOTP = c.Login.TOTP
		for _, u := range c.Login.URIs {
			d.URIs = append(d.URIs, EditURIDraft{URI: u.URI})
		}
	}
	if c.Card != nil {
		d.Cardholder = c.Card.CardholderName
		d.Brand = c.Card.Brand
		d.CardNumber = c.Card.Number
		d.ExpMonth = c.Card.ExpMonth
		d.ExpYear = c.Card.ExpYear
		d.CardCode = c.Card.Code
	}
	if c.Identity != nil {
		d.IdentTitle = c.Identity.Title
		d.FirstName = c.Identity.FirstName
		d.MiddleName = c.Identity.MiddleName
		d.LastName = c.Identity.LastName
		d.Company = c.Identity.Company
		d.Email = c.Identity.Email
		d.Phone = c.Identity.Phone
		d.Address1 = c.Identity.Address1
		d.City = c.Identity.City
		d.State = c.Identity.State
		d.PostalCode = c.Identity.PostalCode
		d.Country = c.Identity.Country
		d.IdentUser = c.Identity.Username
		d.SSN = c.Identity.SSN
		d.Passport = c.Identity.PassportNumber
		d.License = c.Identity.LicenseNumber
	}
	for _, f := range c.Fields {
		d.Fields = append(d.Fields, EditFieldDraft{Name: f.Name, Value: f.Value, Type: f.Type})
	}
	return d
}

func cloneDraft(d *EditDraft) *EditDraft {
	cp := *d
	cp.URIs = append([]EditURIDraft(nil), d.URIs...)
	cp.Fields = append([]EditFieldDraft(nil), d.Fields...)
	return &cp
}

func cipherFromDraft(d *EditDraft) *state.Cipher {
	var base state.Cipher
	if d.Source != nil {
		base = *d.Source
	}
	base.ID = d.ID
	base.Type = d.Type
	base.Name = strings.TrimSpace(d.Name)
	base.Favorite = d.Favorite
	base.Notes = d.Notes
	if d.Reprompt {
		base.Reprompt = 1
	} else {
		base.Reprompt = 0
	}
	if d.FolderID != "" {
		fid := d.FolderID
		base.FolderID = &fid
	} else {
		base.FolderID = nil
	}

	base.Login = nil
	base.SecureNote = nil
	base.Card = nil
	base.Identity = nil

	switch d.Type {
	case api.CipherTypeLogin:
		var uris []state.LoginURI
		for _, u := range d.URIs {
			if s := strings.TrimSpace(u.URI); s != "" {
				uris = append(uris, state.LoginURI{URI: s})
			}
		}
		base.Login = &state.Login{
			Username: d.Username,
			Password: d.Password,
			TOTP:     strings.TrimSpace(d.TOTP),
			URIs:     uris,
		}
	case api.CipherTypeSecureNote:
		base.SecureNote = &state.SecureNote{Type: 0}
	case api.CipherTypeCard:
		base.Card = &state.Card{
			CardholderName: d.Cardholder,
			Brand:          d.Brand,
			Number:         d.CardNumber,
			ExpMonth:       d.ExpMonth,
			ExpYear:        d.ExpYear,
			Code:           d.CardCode,
		}
	case api.CipherTypeIdentity:
		base.Identity = &state.Identity{
			Title:          d.IdentTitle,
			FirstName:      d.FirstName,
			MiddleName:     d.MiddleName,
			LastName:       d.LastName,
			Company:        d.Company,
			Email:          d.Email,
			Phone:          d.Phone,
			Address1:       d.Address1,
			City:           d.City,
			State:          d.State,
			PostalCode:     d.PostalCode,
			Country:        d.Country,
			Username:       d.IdentUser,
			SSN:            d.SSN,
			PassportNumber: d.Passport,
			LicenseNumber:  d.License,
		}
	}

	base.Fields = nil
	for _, f := range d.Fields {
		if strings.TrimSpace(f.Name) == "" && strings.TrimSpace(f.Value) == "" {
			continue
		}
		base.Fields = append(base.Fields, state.CustomField{
			Name:  f.Name,
			Value: f.Value,
			Type:  f.Type,
		})
	}
	return &base
}

func friendlyError(err error) string {
	switch {
	case errors.Is(err, api.ErrTwoFactorRequired):
		return "Two-factor authentication is required (planned for Phase 2)."
	case errors.Is(err, api.ErrUnauthorized):
		return "Invalid email or master password."
	case errors.Is(err, api.ErrNetworkOffline):
		return "Server unreachable. Check your connection and server URL."
	case errors.Is(err, crypto.ErrInvalidMAC):
		return "Incorrect master password."
	default:
		return err.Error()
	}
}

func newDeviceUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func FormatTOTPCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	if len(code) == 8 {
		return code[:4] + " " + code[4:]
	}
	return code
}

func CipherTypeLabel(t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return "Login"
	case api.CipherTypeSecureNote:
		return "Secure Note"
	case api.CipherTypeCard:
		return "Card"
	case api.CipherTypeIdentity:
		return "Identity"
	default:
		return "Item"
	}
}
