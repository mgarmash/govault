package main

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/i18n"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	"github.com/txchen/govault/cmd/govault/locales"
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
	mac := roles(applicationMenu(locales.In("en"), "darwin", nil, nil))
	for _, r := range []desktop.MenuRole{
		desktop.MenuAbout, desktop.MenuHide, desktop.MenuHideOthers, desktop.MenuShowAll, desktop.MenuQuit,
		desktop.MenuUndo, desktop.MenuRedo, desktop.MenuCut, desktop.MenuCopy, desktop.MenuPaste, desktop.MenuSelectAll,
		desktop.MenuWindowMenu, desktop.MenuMinimize, desktop.MenuZoom, desktop.MenuClose,
	} {
		if !mac[r] {
			t.Errorf("macOS menu lacks role %v", r)
		}
	}
	for _, goos := range []string{"linux", "windows"} {
		menu := applicationMenu(locales.In("en"), goos, nil, nil)
		if len(menu) != 1 || roles(menu)[desktop.MenuCopy] {
			t.Fatalf("%s menu = %+v, want only the app items", goos, menu)
		}
	}
}

func TestApplicationMenuKeepsVaultShortcuts(t *testing.T) {
	copies, closings := 0, 0
	var model *govaultui.AppModel
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		installApplicationMenu(cx, "darwin", nil)
		cx.SetMainView(func(cx *core.Scope) core.Node {
			model = govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{
				PrefsKey:   "govault.menu-test",
				CopySecret: func(string, time.Duration) (bool, error) { copies++; return true, nil },
			})
			model.MainWinVisible.Set(true)
			model.RefreshVaultData()
			desktop.CurrentWindow(cx).OnClosing(cx, func(*desktop.WindowClosing) { closings++ })
			return govaultui.MainWindowView(cx, model)
		})
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop}), nsgotest.Size(1100, 720))

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

func TestMenusFollowTheLanguage(t *testing.T) {
	var shell *DesktopShell
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		installApplicationMenu(cx, "darwin", nil)
		cx.SetMainView(func(cx *core.Scope) core.Node {
			model := govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{PrefsKey: "govault.menu-language-test"})
			shell = &DesktopShell{scope: cx, model: model}
			return govaultui.MainWindowView(cx, model)
		})
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}), nsgotest.Size(1100, 720))

	trayLabels := func() []string {
		var labels []string
		for _, it := range shell.trayMenu() {
			labels = append(labels, it.Label)
		}
		return labels
	}
	english, pseudo := locales.In("en"), locales.In(i18n.PseudoAccents)
	if got := trayLabels(); got[0] != english.OpenGoVault() {
		t.Fatalf("tray menu = %q", got)
	}

	app.Post(func() { shell.model.SetLanguage(i18n.PseudoAccents) })
	app.Settle()
	if got := trayLabels(); got[0] != pseudo.OpenGoVault() || got[len(got)-1] != pseudo.QuitGoVault() {
		t.Fatalf("tray menu = %q, want it in the pseudo locale", got)
	}
}
