package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// TestSidebarRowsShowTheirLabelAsATooltip keeps a label the sidebar cuts
// off readable: resting the pointer on a row shows its whole label, and
// the rows keep the full width of the sidebar.
func TestSidebarRowsShowTheirLabelAsATooltip(t *testing.T) {
	const longFolder = "Quarterly Infrastructure Renewals and Contracts"
	svc := newMockVaultService(state.StatusUnlocked)
	svc.folders = append(svc.folders, state.Folder{ID: "f-long", Name: longFolder})
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m := NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.sidebar-tooltip-test"})
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 720), nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}))

	for _, c := range []struct{ row, label string }{
		{"id:sidebar-health", "Vault Health"},
		{"id:sidebar-archive", "Archive"},
		{"id:sidebar-type-note", "Secure Notes"},
		{"id:sidebar-folder >> text:Quarterly", longFolder},
	} {
		row := app.Find(c.row)
		for row.Props.TestID == "" {
			row = row.Parent
		}
		if w := row.Frame.Size.Width; w < 200 {
			t.Fatalf("%s is %v wide, want the width of the sidebar", c.row, w)
		}
		before := len(app.Query("text:" + c.label))
		app.Hover(c.row)
		app.Advance(600 * time.Millisecond)
		app.WaitUntil(time.Second, func() bool { return len(app.Query("text:"+c.label)) > before })
		app.HoverOut()
		app.Advance(300 * time.Millisecond)
	}
}
