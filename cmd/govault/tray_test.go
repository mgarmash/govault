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

// recordedTray is a tray icon kept as NSGo keeps one: the owner running as
// it is added removes it when disposed, and Remove takes it away at once.
type recordedTray struct {
	trays   *trayRecorder
	removed bool
}

func (r *recordedTray) Remove() {
	if !r.removed {
		r.removed = true
		r.trays.shown--
	}
}

type trayRecorder struct{ added, shown int }

func (rec *trayRecorder) add(cx *core.Scope, _ desktop.TrayOptions) trayIcon {
	rec.added++
	rec.shown++
	tr := &recordedTray{trays: rec}
	cx.Cleanup(tr.Remove)
	return tr
}

// TestShowMenuBarIconSwitchAppliesLive turns the Settings switch off and on
// again, as a user does, and checks that the icon goes and comes back at
// once and stays after Settings closes.
func TestShowMenuBarIconSwitchAppliesLive(t *testing.T) {
	rec := &trayRecorder{}
	var shell *DesktopShell
	var dockShown []bool
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		shell = &DesktopShell{scope: cx, newTray: rec.add}
		model := govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{
			PrefsKey:       "govault.tray-test",
			SetTrayVisible: shell.SetTrayVisible,
			SetDockVisible: func(on bool) { dockShown = append(dockShown, on) },
		})
		shell.model = model
		model.UpdatePrefs(func(p govaultui.UserPrefs) govaultui.UserPrefs { p.HideDockIcon = true; return p })
		shell.SetTrayVisible(model.Prefs.Get().ShowTrayIcon)
		cx.SetMainView(func(cx *core.Scope) core.Node {
			model.MainWinVisible.Set(true)
			model.RefreshVaultData()
			return govaultui.MainWindowView(cx, model)
		})
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}), nsgotest.Size(1100, 720))

	if rec.shown != 1 {
		t.Fatalf("icons shown at launch = %d, want 1", rec.shown)
	}
	openSettings := func() {
		app.Post(func() { shell.model.Route.Set(govaultui.RouteSettings) })
		app.WaitFor("id:settings-show-tray", 2*time.Second)
	}
	closeSettings := func() {
		app.Post(func() { shell.model.Route.Set(govaultui.RouteVault) })
		app.WaitForGone("id:settings-view", 2*time.Second)
	}
	for round := 1; round <= 3; round++ {
		openSettings()
		app.Press("id:settings-show-tray")
		if rec.shown != 0 || shell.model.Prefs.Get().ShowTrayIcon {
			t.Fatalf("round %d: switching off left %d icons", round, rec.shown)
		}
		if len(dockShown) == 0 || !dockShown[len(dockShown)-1] || shell.model.Prefs.Get().HideDockIcon {
			t.Fatalf("round %d: the Dock icon did not come back with the menu bar icon off (%v)", round, dockShown)
		}
		app.Press("id:settings-show-tray")
		if rec.shown != 1 || !shell.model.Prefs.Get().ShowTrayIcon {
			t.Fatalf("round %d: switching on shows %d icons", round, rec.shown)
		}
		closeSettings()
		if rec.shown != 1 {
			t.Fatalf("round %d: closing Settings left %d icons, want the icon to stay", round, rec.shown)
		}
	}
	if rec.added != 4 {
		t.Fatalf("icons added = %d, want the launch's and one per round", rec.added)
	}
}
