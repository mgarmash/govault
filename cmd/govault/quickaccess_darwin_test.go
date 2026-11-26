//go:build darwin && !ios

package main

import (
	"testing"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestMain(m *testing.M) { nsgotest.Main(m) }

func TestQuickAccessPanelClosesOnLock(t *testing.T) {
	var shell *DesktopShell
	app := nsgotest.StartApp(t, func(cx *core.Scope) {
		desktop.SetShutdownMode(cx, desktop.ShutdownOnExplicit)
		shell = &DesktopShell{scope: cx}
		shell.model = govaultui.NewAppModel(cx, demo.NewService(state.StatusUnlocked), govaultui.PlatformHooks{})
		installApplicationMenu(cx, "darwin", startQuickAccess(shell))
		cx.SetMainView(func(*core.Scope) core.Node { return core.Text{Content: "Main"} })
	}, nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop}))

	app.ChooseMenu("GoVault", "Quick Access")
	if got := len(app.Surfaces()); got != 2 {
		t.Fatalf("opened %d surfaces, want main and Quick Access", got)
	}
	app.Surface("index:1").Screenshot("quick-access.png")
	app.Post(shell.model.Lock)
	if got := len(app.Surfaces()); got != 1 {
		t.Fatalf("lock left %d surfaces, want only main", got)
	}
}
