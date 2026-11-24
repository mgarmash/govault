package ui

import (
	"slices"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// selectionApp is the vault with four logins, the second read-only.
func selectionApp(t *testing.T) (*nsgotest.App, *AppModel, *mockVaultService) {
	t.Helper()
	svc := newMockVaultService(state.StatusUnlocked)
	for _, c := range []*state.Cipher{
		{ID: "c-alpha", Type: api.CipherTypeLogin, Name: "Alpha", Login: &state.Login{Username: "a"}},
		{ID: "c-bravo", Type: api.CipherTypeLogin, Name: "Bravo", Login: &state.Login{Username: "b"}, ReadOnly: true},
		{ID: "c-charlie", Type: api.CipherTypeLogin, Name: "Charlie", Login: &state.Login{Username: "c"}},
		{ID: "c-delta", Type: api.CipherTypeLogin, Name: "Delta", Login: &state.Login{Username: "d"}},
	} {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SetListSort(SortDefault) })
	app.WaitFor("id:vault-item-list >> text:Delta", 2*time.Second)
	return app, m, svc
}

func row(name string) string { return "id:vault-item-list >> text:" + name }

func selected(m *AppModel) []string {
	ids := m.SelectedIDs()
	slices.Sort(ids)
	return ids
}

// Click selects one item and opens it; Cmd/Ctrl-click toggles, Shift-click
// takes the range in list order, Cmd/Ctrl-A takes every row and Esc clears
// a selection of several. Several selected show the count in the detail.
func TestListSelectionGestures(t *testing.T) {
	app, m, _ := selectionApp(t)
	app.Press(row("Alpha"))
	app.WaitUntil(2*time.Second, func() bool { return m.SelectedID.Get() == "c-alpha" })
	app.PressWith(row("Charlie"), core.Modifiers{Platform: true})
	app.WaitFor("id:selection-pane", 2*time.Second)
	if got := selected(m); !slices.Equal(got, []string{"c-alpha", "c-charlie"}) || m.ActiveCipher.Get() != nil {
		t.Fatalf("after Cmd-click: %v, active %v", got, m.ActiveCipher.Get())
	}
	app.Find("text:2 items selected")

	app.Press(row("Bravo"))
	app.PressWith(row("Delta"), core.Modifiers{Shift: true})
	app.WaitUntil(2*time.Second, func() bool { return len(m.SelectedIDs()) == 3 })
	if got := selected(m); !slices.Equal(got, []string{"c-bravo", "c-charlie", "c-delta"}) {
		t.Fatalf("Shift range: %v", got)
	}

	app.Press(row("Alpha"))
	app.Key("mod+a")
	app.WaitUntil(2*time.Second, func() bool { return m.ListSelection.Len() == m.FilteredItems.Len() })

	// Right-click inside the selection keeps it; outside selects that row.
	app.RightClick(row("Charlie"))
	if m.ListSelection.Len() != m.FilteredItems.Len() {
		t.Fatal("right-click in the selection replaced it")
	}
	app.Key("escape")
	app.WaitUntil(2*time.Second, func() bool { return m.ListSelection.Len() == 0 })
	app.PressWith(row("Alpha"), core.Modifiers{Platform: true})
	app.PressWith(row("Bravo"), core.Modifiers{Platform: true})
	app.RightClick(row("Delta"))
	app.WaitUntil(2*time.Second, func() bool { return m.SelectedID.Get() == "c-delta" && m.ListSelection.Len() == 1 })
}

// Delete asks before moving the selection to Trash, skipping read-only
// items; typing in a field keeps the key, and Trash ignores it.
func TestDeleteKeyTrashesTheSelection(t *testing.T) {
	app, m, svc := selectionApp(t)
	app.Press(row("Alpha"))
	app.PressWith(row("Bravo"), core.Modifiers{Platform: true})
	app.PressWith(row("Charlie"), core.Modifiers{Platform: true})

	app.Key("backspace")
	app.WaitFor("id:bulk-dialog", 2*time.Second)
	app.Find("text:Move 2 items to Trash?")
	app.Find("id:bulk-skipped")
	app.Press("id:bulk-confirm")
	app.WaitUntil(2*time.Second, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return svc.ciphers["c-alpha"].DeletedDate != nil && svc.ciphers["c-charlie"].DeletedDate != nil
	})
	svc.mu.RLock()
	bravo := svc.ciphers["c-bravo"].DeletedDate
	svc.mu.RUnlock()
	if bravo != nil {
		t.Fatal("a read-only item was moved to Trash")
	}
	app.WaitUntil(2*time.Second, func() bool { return m.ListSelection.Len() == 0 })

	// A field being typed in keeps the key.
	app.Press(row("Delta"))
	app.PressWith(row("Bravo"), core.Modifiers{Platform: true})
	app.Press("id:vault-search")
	app.Key("backspace")
	if m.BulkDialog.Get() != nil {
		t.Fatal("Backspace in the search field opened the confirmation")
	}

	app.Post(func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash}) })
	app.WaitFor(row("Alpha"), 2*time.Second)
	app.Press(row("Alpha"))
	app.Key("delete")
	if m.BulkDialog.Get() != nil {
		t.Fatal("Delete in Trash asked to move to Trash")
	}
}

// Move to Folder sends the items not already in the chosen folder.
func TestMoveSelectionToFolder(t *testing.T) {
	app, m, svc := selectionApp(t)
	work := "f-work"
	svc.mu.Lock()
	svc.ciphers["c-charlie"].FolderID = &work
	svc.mu.Unlock()
	app.Post(func() {
		m.Folders.Set([]state.Folder{{ID: work, Name: "Work"}})
		m.RefreshVaultData()
	})
	app.Press(row("Alpha"))
	app.PressWith(row("Charlie"), core.Modifiers{Platform: true})
	app.Press("id:selection-move")
	app.WaitFor("id:bulk-dialog", 2*time.Second)
	app.Post(func() { m.BulkFolder.Set(work) })
	app.WaitFor("id:bulk-unchanged", 2*time.Second)
	app.Press("id:bulk-confirm")
	app.WaitUntil(2*time.Second, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		f := svc.ciphers["c-alpha"].FolderID
		return f != nil && *f == work
	})
	app.WaitUntil(2*time.Second, func() bool { return m.ListSelection.Len() == 0 })
}

// A sync that removes selected items keeps the others selected, and opens
// the one left alone.
func TestSelectionPrunedAfterRefresh(t *testing.T) {
	app, m, svc := selectionApp(t)
	app.Press(row("Alpha"))
	app.PressWith(row("Charlie"), core.Modifiers{Platform: true})
	app.WaitFor("id:selection-pane", 2*time.Second)
	svc.mu.Lock()
	delete(svc.ciphers, "c-charlie")
	svc.mu.Unlock()
	app.Post(m.RefreshVaultData)
	app.WaitUntil(2*time.Second, func() bool { return m.SelectedID.Get() == "c-alpha" })
	if got := m.SelectedIDs(); !slices.Equal(got, []string{"c-alpha"}) {
		t.Fatalf("after the sync: %v", got)
	}
}
