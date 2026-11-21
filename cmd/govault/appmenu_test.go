package main

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func roles(items []desktop.MenuItem) map[desktop.MenuRole]bool {
	out := map[desktop.MenuRole]bool{}
	for _, it := range items {
		out[it.Role] = true
		for r := range roles(it.Items) {
			out[r] = true
		}
	}
	return out
}

func TestApplicationMenuKeepsStandardRoles(t *testing.T) {
	mac := roles(applicationMenu("darwin", func() {}))
	for _, r := range []desktop.MenuRole{
		desktop.MenuAbout, desktop.MenuHide, desktop.MenuHideOthers, desktop.MenuShowAll, desktop.MenuQuit,
		desktop.MenuUndo, desktop.MenuRedo, desktop.MenuCut, desktop.MenuCopy, desktop.MenuPaste, desktop.MenuSelectAll,
		desktop.MenuWindowMenu, desktop.MenuMinimize, desktop.MenuZoom, desktop.MenuClose,
	} {
		if !mac[r] {
			t.Errorf("macOS menu lacks role %v", r)
		}
	}
	linux := applicationMenu("linux", func() {})
	if len(linux) != 1 || roles(linux)[desktop.MenuCopy] {
		t.Fatalf("Linux menu = %+v, want only the app items", linux)
	}
}

func TestCheckForUpdatesWhileLoggedOutAndShortcutsKept(t *testing.T) {
	for _, status := range []state.LockStatus{state.StatusLoggedOut, state.StatusUnlocked} {
		checks, copies, closings := 0, 0, 0
		var model *govaultui.AppModel
		app := nsgotest.StartApp(t, func(cx *core.Scope) {
			desktop.SetApplicationMenu(cx, applicationMenu("darwin", func() { checks++ }))
			cx.SetMainView(func(cx *core.Scope) core.Node {
				model = govaultui.NewAppModel(cx, demo.NewService(status), govaultui.PlatformHooks{
					PrefsKey:   "govault.menu-test",
					CopySecret: func(string, time.Duration) (bool, error) { copies++; return true, nil },
				})
				model.MainWinVisible.Set(true)
				model.RefreshVaultData()
				desktop.CurrentWindow(cx).OnClosing(cx, func(*desktop.WindowClosing) { closings++ })
				return govaultui.MainWindowView(cx, model)
			})
		}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop}), nsgotest.Size(1100, 720))

		app.ChooseMenu("GoVault", checkForUpdatesLabel)
		if checks != 1 {
			t.Fatalf("status %v: Check for Updates ran %d times", status, checks)
		}
		if status != state.StatusUnlocked {
			continue
		}
		app.Post(func() { model.SelectCipher(model.Scope, "c-netflix") })
		app.WaitFor("id:detail-view", 2*time.Second)
		app.Key("mod+c")
		if copies != 1 {
			t.Fatalf("mod+c copied %d times with the app menu installed", copies)
		}
		app.Key("mod+w")
		if closings != 1 {
			t.Fatalf("mod+w ran %d close handlers", closings)
		}
	}
}
