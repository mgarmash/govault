package ui

import (
	"fmt"
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

// TestSidebarRowsNameThemselvesOnce has screen readers read each row as one
// element named by its label, its count as the description, rather than the
// tooltip repeating the label as a description.
func TestSidebarRowsNameThemselvesOnce(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var m *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{PrefsKey: "govault.sidebar-a11y-test"})
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 720), nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}))

	for _, c := range []struct{ id, label, description string }{
		{"id:sidebar-all", "All Items", fmt.Sprint(m.AllCounts.Get().All)},
		{"id:sidebar-generator", "Generator", ""},
		{"id:sidebar-settings", "Settings", ""},
		{"id:sidebar-folder", svc.folders[0].Name, fmt.Sprint(m.AllCounts.Get().ByFolder[svc.folders[0].ID])},
	} {
		row := app.Find(c.id)
		p := row.Props
		if p.Label != c.label || p.Description != c.description || p.Accessible != core.AccessibleYes {
			t.Errorf("%s: label %q, description %q, one element %v; want %q, %q, true", c.id, p.Label, p.Description, p.Accessible, c.label, c.description)
		}
	}

	app.AccessibilityAction("id:sidebar-folder", "rename")
	app.WaitFor("id:folder-name-input", 2*time.Second)
	if d := m.FolderDialog.Get(); !d.Open || d.FolderID != svc.folders[0].ID {
		t.Fatalf("the rename action opened %+v", d)
	}
}
