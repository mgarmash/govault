//go:build darwin && !ios

package main

import (
	"testing"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestHotKeySettingsRebindAndDisable(t *testing.T) {
	if nsgotest.Target() != "" {
		t.Skip("conflict fixture is headless; the real OS decides native conflicts")
	}
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		shell := &DesktopShell{scope: cx, model: govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{})}
		startQuickAccess(shell)
		cx.SetMainView(func(cx *core.Scope) core.Node { return govaultui.SettingsView(cx, shell.model) })
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop}),
		nsgotest.HotKeyTaken("ctrl+alt+k"), nsgotest.Size(900, 780))

	app.Find("text:Active")
	app.Press("id:settings-quick-hotkey")
	app.Key("ctrl+alt+k")
	app.Find("text:In use — choose another shortcut")
	app.Press("id:settings-quick-hotkey-off")
	app.Find("text:Off")
	app.Press("id:settings-quick-hotkey-reset")
	if !quickAutofillAvailable() {
		app.Press("id:quick-accessibility-settings")
		if got := app.PermissionSettings; len(got) != 1 || got[0] != core.PermissionAccessibility {
			t.Fatalf("opened permission settings %v, want Accessibility", got)
		}
	}
	app.Find("text:Active")
	app.Press("id:settings-quick-hotkey")
	app.Key("escape")
	app.Find("text:Active")
}

func TestHotKeySettingsNative(t *testing.T) {
	if nsgotest.Target() == "" {
		t.Skip("requires native pixels")
	}
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		shell := &DesktopShell{scope: cx, model: govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{})}
		startQuickAccess(shell)
		cx.SetMainView(func(cx *core.Scope) core.Node { return govaultui.SettingsView(cx, shell.model) })
	}, nsgotest.Size(900, 780))
	app.Press("id:settings-quick-hotkey-off")
	app.Find("text:Off")
	app.Screenshot("hotkey-settings.png")
}
