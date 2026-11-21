package main

import (
	"context"
	"runtime"
	"sync"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type DesktopShell struct {
	scope     *core.Scope
	dataDir   string
	clipboard *ClipboardAdapter
	service   *state.Service
	model     *govaultui.AppModel

	mainWin     *desktop.Window
	quickPanel  *desktop.Window
	hotKeyScope *core.Scope
	hotKey      *desktop.HotKey

	rtMu      sync.Mutex
	rtRunning bool
}

func NewDesktopShell(app *core.Scope, demoMode bool) *DesktopShell {
	desktop.SetShutdownMode(app, desktop.ShutdownOnExplicit)
	if demoMode {
		return newDemoShell(app)
	}

	dataDir := ensureDataDir(app)
	secrets := NewSecretStoreAdapter(app.Secrets())
	clip := NewClipboardAdapter(app)

	shell := &DesktopShell{
		scope:     app,
		dataDir:   dataDir,
		clipboard: clip,
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
	return govaultui.PlatformHooks{
		Secrets:              secrets,
		CopySecret:           s.clipboard.CopySecret,
		CopyPlain:            s.clipboard.CopyPlain,
		IsClipboardConcealed: s.clipboard.IsConcealed,
		ApplyHotKey:          s.ApplyHotKey,
		SetLaunchAtLogin: func(on bool) {
			desktop.SetLaunchAtLogin(app, on)
		},
		SetDockVisible: func(on bool) {
			if runtime.GOOS == "darwin" {
				desktop.SetDockVisible(app, on)
			}
		},
		OpenMainWindow:   s.OpenMainWindow,
		HideQuickPanel:   s.HideQuickPanel,
		ToggleQuickPanel: s.ToggleQuickPanel,
	}
}

func (s *DesktopShell) finishSetup() {
	app := s.scope
	shell := s
	clip := s.clipboard

	p := shell.model.Prefs.Get()
	if p.QuickAccessHotKey != "" {
		shell.ApplyHotKey(p.QuickAccessHotKey)
	}
	if runtime.GOOS == "darwin" && p.HideDockIcon {
		desktop.SetDockVisible(app, false)
	}

	desktop.NewTray(app, desktop.TrayOptions{
		Tooltip: "GoVault",
		Width:   26,
		View:    trayIconView,
		OnClick: shell.ToggleQuickPanel,
		Menu:    shell.trayMenu,
	})

	desktop.OnReopen(app, shell.OpenMainWindow)

	app.Cleanup(func() {
		clip.Cancel()
		if shell.hotKeyScope != nil {
			shell.hotKeyScope.Dispose()
		}
	})

	if !desktop.LaunchedAtLogin(app) {
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
	hk := s.model.Prefs.Get().QuickAccessHotKey
	quickLabel := "Quick Search"
	if hk != "" {
		quickLabel += " (" + s.scope.KeyLabel(hk) + ")"
	}

	items := []desktop.MenuItem{
		{Label: "Open GoVault", OnSelect: s.OpenMainWindow},
		{Label: quickLabel, OnSelect: s.ToggleQuickPanel},
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

func (s *DesktopShell) ensureQuickPanel() *desktop.Window {
	if s.quickPanel != nil && !s.quickPanel.Closed() {
		return s.quickPanel
	}
	s.quickPanel = desktop.OpenPanel(s.scope, desktop.PanelOptions{
		Width:       656,
		Height:      480,
		FitContent:  true,
		HideOnBlur:  true,
		Transparent: true,
	}, func(cx *core.Scope) core.Node {
		panel := desktop.CurrentWindow(cx)
		cx.Effect(func() {
			vis := panel.Visible()
			s.model.QuickPanelVisible.Set(vis)
			if vis {
				s.model.RefreshQuickItems()
			}
		})
		cx.Cleanup(func() {
			s.model.QuickPanelVisible.Set(false)
		})
		return govaultui.QuickPanelView(cx, s.model)
	})
	return s.quickPanel
}

func (s *DesktopShell) ToggleQuickPanel() {
	panel := s.ensureQuickPanel()
	if !panel.Visible() {
		s.model.QuickQuery.Set("")
		s.model.QuickSelectedIdx.Set(0)
		s.model.RefreshQuickItems()
	}
	panel.Toggle()
}

func (s *DesktopShell) HideQuickPanel() {
	if s.quickPanel != nil && !s.quickPanel.Closed() {
		s.quickPanel.Hide()
	}
}

func (s *DesktopShell) ApplyHotKey(shortcut string) {
	if s.hotKeyScope != nil {
		s.hotKeyScope.Dispose()
		s.hotKeyScope = nil
		s.hotKey = nil
	}
	if shortcut == "" {
		s.model.HotKeyStatus.Set("Disabled")
		return
	}

	hkScope := s.scope.Child()
	s.hotKeyScope = hkScope
	s.hotKey = desktop.RegisterHotKey(hkScope, shortcut, s.ToggleQuickPanel)
	hkScope.Effect(func() {
		switch s.hotKey.State() {
		case desktop.HotKeyRegistered:
			s.model.HotKeyStatus.Set("Active")
		case desktop.HotKeyTaken:
			s.model.HotKeyStatus.Set("Already in use by another app")
		case desktop.HotKeyUnsupported:
			s.model.HotKeyStatus.Set("Unsupported on this session")
		default:
			s.model.HotKeyStatus.Set("Registering...")
		}
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
