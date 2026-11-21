package main

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/updater"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type DesktopShell struct {
	scope     *core.Scope
	dataDir   string
	clipboard *ClipboardAdapter
	favicons  *govaultui.FaviconStore
	sshAgent  *sshAgentHost
	service   *state.Service
	model     *govaultui.AppModel

	mainWin   *desktop.Window
	trayScope *core.Scope

	rtMu      sync.Mutex
	rtRunning bool
}

func NewDesktopShell(app *core.Scope, demoMode bool) *DesktopShell {
	desktop.SetShutdownMode(app, desktop.ShutdownOnExplicit)
	if demoMode {
		return newDemoShell(app)
	}

	dataDir := ensureDataDir(app)
	secrets := NewBiometricSecretStore(NewSecretStoreAdapter(app.Secrets()), newHardwareKeychain())
	clip := NewClipboardAdapter(app)

	shell := &DesktopShell{
		scope:     app,
		dataDir:   dataDir,
		clipboard: clip,
		sshAgent:  newSSHAgentHost(dataDir),
	}
	if cacheDir := app.CacheDir(); cacheDir != "" {
		shell.favicons = govaultui.NewFaviconStore(govaultui.FaviconStoreConfig{CacheDir: filepath.Join(cacheDir, "icons")})
	}

	tempPrefs := core.NewPersisted(app, govaultui.DefaultPrefsKey, govaultui.DefaultUserPrefs(), core.PersistOptions{Version: 1})
	initialPrefs := tempPrefs.Get()

	meta := DiscoverAccountSnapshot(dataDir, initialPrefs.AccountID)
	accountID := initialPrefs.AccountID
	if meta != nil {
		accountID = meta.AccountID
	}

	svc, err := state.NewService(state.ServiceConfig{
		Store:      store.NewFileStore(dataDir),
		Secrets:    secrets,
		AccountID:  accountID,
		DeviceID:   initialPrefs.DeviceID,
		DeviceName: "GoVault Desktop",
		DeviceType: deviceTypeForOS(),
		OnStatusChange: func(st state.LockStatus) {
			if st != state.StatusUnlocked {
				shell.sshAgent.Clear()
			}
			app.Post(func() {
				if shell.model == nil {
					return
				}
				shell.model.LockState.Set(st)
				if st == state.StatusUnlocked {
					shell.startRealtimeAsync()
				}
			})
		},
		OnVaultUpdated: func() {
			app.Post(func() {
				if shell.model != nil && shell.model.LockState.Get() == state.StatusUnlocked {
					shell.model.RefreshVaultData()
				}
			})
		},
	})
	if err != nil {
		panic(err)
	}
	shell.service = svc

	hooks := shell.platformHooks(secrets)
	hooks.BiometricHardwareBound = secrets.HardwareBound
	hooks.DiscoverSnapshot = func(preferred string) *govaultui.AccountSnapshotMeta {
		return DiscoverAccountSnapshot(dataDir, preferred)
	}
	hooks.VerifyMasterPassword = func(password []byte) error {
		return VerifyMasterPasswordOffline(dataDir, shell.model.Prefs.Get().AccountID, password)
	}

	shell.model = govaultui.NewAppModel(app, svc, hooks)
	if meta != nil {
		shell.model.SyncAccountMetaFromSnapshot()
	}
	shell.finishSetup()
	return shell
}

func (s *DesktopShell) platformHooks(secrets store.SecretStore) govaultui.PlatformHooks {
	app := s.scope
	hooks := govaultui.PlatformHooks{
		Secrets:              secrets,
		CopySecret:           s.clipboard.CopySecret,
		CopyPlain:            s.clipboard.CopyPlain,
		IsClipboardConcealed: s.clipboard.IsConcealed,
		SetLaunchAtLogin: func(on bool) {
			desktop.SetLaunchAtLogin(app, on)
		},
		SetDockVisible: func(on bool) {
			if runtime.GOOS == "darwin" {
				desktop.SetDockVisible(app, on)
			}
		},
		SetTrayVisible:     s.SetTrayVisible,
		ReleaseSecureInput: ReleaseSecureInput,
		SleepLockSupported: sleepLockSupported,
		Favicons:           s.favicons,
	}
	if s.sshAgent != nil {
		hooks.SSHAgent = s.sshAgent
	}
	return hooks
}

func (s *DesktopShell) finishSetup() {
	app := s.scope
	shell := s
	clip := s.clipboard

	p := shell.model.Prefs.Get()
	if runtime.GOOS == "darwin" && p.HideDockIcon && p.ShowTrayIcon {
		desktop.SetDockVisible(app, false)
	}
	shell.SetTrayVisible(p.ShowTrayIcon)

	desktop.OnReopen(app, shell.OpenMainWindow)

	app.Effect(func() {
		if app.Env().Lifecycle() != core.LifecycleActive {
			ReleaseSecureInput(true)
		}
	})

	if stop, err := startSleepLockListener(func() {
		app.Post(func() { shell.model.LockOnSystemEvent() })
	}); err == nil {
		app.Cleanup(stop)
	}

	app.Cleanup(func() {
		clip.ClearOnQuit()
		if shell.trayScope != nil {
			shell.trayScope.Dispose()
		}
	})

	if !desktop.LaunchedAtLogin(app) || !p.ShowTrayIcon {
		shell.OpenMainWindow()
	}
}

func (s *DesktopShell) startRealtimeAsync() {
	s.rtMu.Lock()
	if s.rtRunning {
		s.rtMu.Unlock()
		return
	}
	s.rtRunning = true
	s.rtMu.Unlock()

	go func() {
		_ = s.service.StartRealtime(context.Background())
		s.rtMu.Lock()
		s.rtRunning = false
		s.rtMu.Unlock()
	}()
}

func (s *DesktopShell) trayMenu() []desktop.MenuItem {
	unlocked := s.model.LockState.Get() == state.StatusUnlocked
	offline := s.model.SyncState.Get() == govaultui.SyncOffline
	items := []desktop.MenuItem{
		{Label: "Open GoVault", OnSelect: s.OpenMainWindow},
		{Label: "Check for Updates…", OnSelect: func() { updater.Check(s.scope) }},
		{Separator: true},
		{
			Label:    "Sync Now",
			Disabled: !unlocked || offline,
			OnSelect: func() { s.model.SyncNow(false) },
		},
	}
	if unlocked {
		items = append(items, desktop.MenuItem{
			Label:    "Lock Now",
			OnSelect: s.model.Lock,
		})
	}
	items = append(items,
		desktop.MenuItem{Separator: true},
		desktop.MenuItem{Label: "Quit GoVault", OnSelect: s.scope.Quit},
	)
	return items
}

func (s *DesktopShell) OpenMainWindow() {
	if s.mainWin != nil && !s.mainWin.Closed() {
		s.mainWin.Focus()
		return
	}

	s.mainWin = desktop.OpenWindow(s.scope, desktop.WindowOptions{
		Title:  "GoVault",
		Key:    "main",
		Width:  1100,
		Height: 720,
		Constraints: desktop.WindowConstraints{
			MinWidth:  900,
			MinHeight: 560,
		},
	}, func(cx *core.Scope) core.Node {
		win := desktop.CurrentWindow(cx)
		cx.Effect(func() {
			vis := win.Visible() && !desktop.Minimized(cx)
			s.model.MainWinVisible.Set(vis)
		})
		cx.Effect(func() {
			if cx.Env().Lifecycle() != core.LifecycleActive {
				ReleaseSecureInput(true)
			}
		})
		win.OnClosing(cx, func(ev *desktop.WindowClosing) {
			if s.model.EditMode.Get() && s.model.EditDirty.Get() {
				ev.Cancel()
				s.model.GuardDirty(cx, func() {
					win.Close()
				})
			}
		})
		cx.Cleanup(func() {
			s.model.MainWinVisible.Set(false)
		})
		return govaultui.MainWindowView(cx, s.model)
	})
	desktop.SetMainWindow(s.scope, s.mainWin)
}

func (s *DesktopShell) SetTrayVisible(on bool) {
	mode := desktop.ShutdownOnExplicit
	if !on && runtime.GOOS != "darwin" {
		mode = desktop.ShutdownOnLastWindowClose
	}
	desktop.SetShutdownMode(s.scope, mode)
	if on == (s.trayScope != nil) {
		return
	}
	if !on {
		s.trayScope.Dispose()
		s.trayScope = nil
		return
	}
	s.trayScope = s.scope.Child()
	desktop.NewTray(s.trayScope, desktop.TrayOptions{
		Tooltip: "GoVault",
		Width:   26,
		View:    trayIconView,
		OnClick: s.OpenMainWindow,
		Menu:    s.trayMenu,
	})
}

func trayIconView(cx *core.Scope) core.Node {
	return core.View{
		Class: "flex-row items-center justify-center h-full",
		Children: []core.Node{
			core.Icon{
				SVG: lucide.Lock(),
				StyleFunc: func() core.Style {
					c := core.RGB(0x000000)
					if cx.Dark() {
						c = core.RGB(0xffffff)
					}
					return core.Style{Width: core.Pt(15), Height: core.Pt(15), Color: c}
				},
			},
		},
	}
}
