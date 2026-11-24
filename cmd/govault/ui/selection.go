package ui

import (
	"context"
	"errors"
	"strings"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// The list's selection is one list-owned base.Selection keyed by cipher
// ID. One selected item is SelectedID and opens in the detail pane; two or
// more show the bulk actions there instead.

// SelectedIDs are the items chosen in the list, in the order chosen.
func (m *AppModel) SelectedIDs() []string {
	var ids []string
	for _, k := range m.ListSelection.Keys() {
		if id, ok := k.(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// MultiSelected reports a selection of two or more items.
func (m *AppModel) MultiSelected() bool { return m.ListSelection.Len() > 1 }

func anyKeys(ids []string) []any {
	keys := make([]any, len(ids))
	for i, id := range ids {
		keys[i] = id
	}
	return keys
}

// listSelectionChanged follows a press or key in the list. A change while
// a draft has unsaved edits waits for the user to discard it, and goes back
// if they keep editing.
func (m *AppModel) listSelectionChanged(cx *core.Scope, s *base.Selection) {
	ids := m.SelectedIDs()
	if m.EditMode.Get() && m.EditDirty.Get() {
		s.Set(anyKeys(m.shownIDs)...)
		m.GuardDirty(cx, func() {
			s.Set(anyKeys(ids)...)
			m.showSelection(cx, ids)
		})
		return
	}
	m.showSelection(cx, ids)
}

// showSelection opens one selected item, or clears the detail for none or
// several, and tells assistive technology how many are selected.
func (m *AppModel) showSelection(cx *core.Scope, ids []string) {
	m.ResetIdleTimer()
	before := len(m.shownIDs)
	m.shownIDs = ids
	if len(ids) == 1 {
		m.SelectCipher(cx, ids[0])
		return
	}
	m.EditMode.Set(false)
	m.SelectedID.Set("")
	m.ActiveCipher.Set(nil)
	m.RevealPW.Set(false)
	m.RevealCard.Set(false)
	m.TOTPRevealedID.Set("")
	if len(ids) > 1 && len(ids) != before {
		cx.Announce(locales.ItemsSelected(cx, len(ids)))
	}
}

// ClearSelection leaves the list with nothing selected.
func (m *AppModel) ClearSelection() {
	m.shownIDs = nil
	m.ListSelection.Clear()
	if m.SelectedID.Get() != "" {
		m.SelectedID.Set("")
		m.ActiveCipher.Set(nil)
	}
}

// clearMultiSelection drops a selection of several items, as a new view,
// search or section does; one opened item stays open.
func (m *AppModel) clearMultiSelection() {
	if m.MultiSelected() {
		m.ClearSelection()
	}
}

// pruneSelection keeps the selected items the list still shows, as after a
// sync, a new order or another view, opening the item that remains alone.
// An item being edited stays.
func (m *AppModel) pruneSelection() {
	if m.ListSelection.Len() == 0 || m.EditMode.Get() {
		return
	}
	shown := map[string]bool{}
	for _, it := range m.FilteredItems.Items() {
		shown[it.ID] = true
	}
	ids := m.SelectedIDs()
	var keep []string
	for _, id := range ids {
		if shown[id] {
			keep = append(keep, id)
		}
	}
	if len(keep) == len(ids) {
		return
	}
	if len(keep) == 0 {
		m.ClearSelection()
		return
	}
	m.ListSelection.Set(anyKeys(keep)...)
	m.showSelection(m.Scope, keep)
}

// bulkSet is what each action may change among the selected items, as
// the user may: items they cannot edit are skipped where writing needs
// edit rights.
type bulkSet struct {
	all                                       []*state.Cipher
	movable, trashable, restorable, deletable []*state.Cipher
	archivable, unarchivable                  []*state.Cipher
	inTrash                                   bool
}

func (m *AppModel) bulkSelection() bulkSet {
	var b bulkSet
	canArchive := m.Core.CanArchive()
	for _, id := range m.SelectedIDs() {
		c, err := m.Core.GetCipher(id)
		if err != nil {
			continue
		}
		b.all = append(b.all, c)
		ro := m.CipherReadOnly(c)
		switch {
		case c.DeletedDate != nil:
			b.inTrash = true
			if !ro {
				b.restorable = append(b.restorable, c)
				b.deletable = append(b.deletable, c)
			}
		default:
			b.movable = append(b.movable, c)
			if !ro {
				b.trashable = append(b.trashable, c)
			}
			if c.ArchivedDate == nil && canArchive {
				b.archivable = append(b.archivable, c)
			} else if c.ArchivedDate != nil {
				b.unarchivable = append(b.unarchivable, c)
			}
		}
	}
	return b
}

// writesAllowed: offline, signed out of the server or with only the local
// copy, the selection can be looked at, not changed.
func (m *AppModel) writesAllowed() bool {
	st := m.SyncState.Get()
	return st != SyncOffline && st != SyncAuthExpired && !m.LocalOnly.Get() && !m.BulkBusy.Get()
}

// BulkKind is an action a bulk dialog confirms.
type BulkKind int

const (
	BulkTrash BulkKind = iota + 1
	BulkDelete
	BulkMove
)

// BulkDialog is the confirmation or folder choice open for the selection.
type BulkDialog struct {
	Kind    BulkKind
	Items   []*state.Cipher
	Skipped int
	// Trash is what a permanent deletion covers, with the revisions the
	// user saw when the confirmation opened.
	Trash state.TrashSelection
}

// ConfirmTrashSelection asks before moving the selection to Trash; in
// Trash it does nothing.
func (m *AppModel) ConfirmTrashSelection() {
	b := m.bulkSelection()
	if b.inTrash || len(b.trashable) == 0 || !m.writesAllowed() {
		return
	}
	m.BulkDialog.Set(&BulkDialog{Kind: BulkTrash, Items: b.trashable, Skipped: len(b.all) - len(b.trashable)})
}

// ConfirmDeleteSelection asks before deleting the selected items in Trash
// for good.
func (m *AppModel) ConfirmDeleteSelection() {
	b := m.bulkSelection()
	if len(b.deletable) == 0 || !m.writesAllowed() {
		return
	}
	want := map[string]bool{}
	for _, c := range b.deletable {
		want[c.ID] = true
	}
	sel := m.Core.TrashSelection()
	sel.ReadOnly = 0
	var confirmed []state.TrashItem
	for _, it := range sel.Items {
		if want[it.ID] {
			confirmed = append(confirmed, it)
		}
	}
	sel.Items = confirmed
	m.BulkDialog.Set(&BulkDialog{Kind: BulkDelete, Items: b.deletable, Skipped: len(b.all) - len(b.deletable), Trash: sel})
}

// ChooseFolderForSelection opens the folder picker for the selection.
func (m *AppModel) ChooseFolderForSelection() {
	b := m.bulkSelection()
	if len(b.movable) == 0 || !m.writesAllowed() {
		return
	}
	m.BulkFolder.Set("")
	m.BulkDialog.Set(&BulkDialog{Kind: BulkMove, Items: b.movable, Skipped: len(b.all) - len(b.movable)})
}

// ConfirmBulkDialog runs the action the open dialog confirms.
func (m *AppModel) ConfirmBulkDialog() {
	d := m.BulkDialog.Get()
	m.BulkDialog.Set(nil)
	if d == nil {
		return
	}
	switch d.Kind {
	case BulkTrash:
		m.runBulk(d.Items, bulkTrashed, func(ctx context.Context, c *state.Cipher) error { return m.Core.SoftDeleteCipher(ctx, c.ID) })
	case BulkDelete:
		m.deleteSelection(d.Trash)
	case BulkMove:
		m.moveSelection(d.Items, m.BulkFolder.Get())
	}
}

// RestoreSelection brings the selected items back from Trash.
func (m *AppModel) RestoreSelection() {
	if b := m.bulkSelection(); len(b.restorable) > 0 && m.writesAllowed() {
		m.runBulk(b.restorable, bulkRestored, func(ctx context.Context, c *state.Cipher) error { return m.Core.RestoreCipher(ctx, c.ID) })
	}
}

// ArchiveSelection moves the selected items to the Archive, or back with
// archive false. When any of them is protected by a master password
// reprompt, the password is asked once, for the whole action.
func (m *AppModel) ArchiveSelection(cx *core.Scope, archive bool) {
	b := m.bulkSelection()
	items, action, kind := b.archivable, RepromptArchiveItem, bulkArchived
	if !archive {
		items, action, kind = b.unarchivable, RepromptUnarchiveItem, bulkUnarchived
	}
	if len(items) == 0 || !m.writesAllowed() {
		return
	}
	run := func() {
		m.runBulk(items, kind, func(ctx context.Context, c *state.Cipher) error {
			if archive {
				return m.Core.ArchiveCipher(ctx, c.ID)
			}
			return m.Core.UnarchiveCipher(ctx, c.ID)
		})
	}
	for _, c := range items {
		if c.Reprompt == 1 {
			m.GateReprompt(cx, c, action, run)
			return
		}
	}
	run()
}

// bulkOutcome is what an action did, for its one result message, which
// the UI thread words.
type bulkOutcome struct {
	done   int
	failed []bulkFailure
	// kept counts items Empty Trash kept as they changed meanwhile.
	kept int
	// err stopped the action, a move perhaps partway.
	err   error
	local bool
}

type bulkFailure struct {
	name string
	err  error
}

// stopsBulk reports a failure that every further item would meet too.
func stopsBulk(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, state.ErrLocked) || errors.Is(err, api.ErrNetworkOffline) ||
		errors.Is(err, state.ErrSignInRequired) || errors.Is(err, api.ErrUnauthorized) || errors.Is(err, state.ErrArchiveUnsupported)
}

// runBulk applies do to each item in turn, in the session, and reports
// once. A lost session or connection stops it. The selection clears.
func (m *AppModel) runBulk(items []*state.Cipher, kind bulkResult, do func(context.Context, *state.Cipher) error) {
	m.dispatch(func(ctx context.Context) bulkOutcome {
		var out bulkOutcome
		for _, c := range items {
			err := do(ctx, c)
			var lc *state.LocalCopyError
			switch {
			case err == nil:
				out.done++
			case errors.As(err, &lc):
				out.done++
				out.local = true
			default:
				out.failed = append(out.failed, bulkFailure{c.Name, err})
				if stopsBulk(ctx, err) {
					return out
				}
			}
		}
		return out
	}, kind)
}

// deleteSelection deletes the confirmed items in Trash for good through
// Empty Trash, which keeps each that is no longer in Trash at the revision
// the user saw.
func (m *AppModel) deleteSelection(sel state.TrashSelection) {
	m.dispatch(func(ctx context.Context) bulkOutcome {
		res, err := m.Core.EmptyTrash(ctx, sel)
		return bulkOutcome{done: res.Deleted, kept: res.Skipped, err: err}
	}, bulkDeleted)
}

// moveSelection puts the items in folderID, "" for No Folder, leaving out
// those already there.
func (m *AppModel) moveSelection(items []*state.Cipher, folderID string) {
	var dest *string
	if folderID != "" {
		dest = &folderID
	}
	var ids []string
	for _, c := range items {
		if !inFolder(c, folderID) {
			ids = append(ids, c.ID)
		}
	}
	m.dispatch(func(ctx context.Context) bulkOutcome {
		if len(ids) == 0 {
			return bulkOutcome{}
		}
		if err := m.Core.MoveCiphers(ctx, ids, dest); err != nil {
			return bulkOutcome{err: err}
		}
		return bulkOutcome{done: len(ids)}
	}, bulkMoved)
}

func inFolder(c *state.Cipher, folderID string) bool {
	if c.FolderID == nil || *c.FolderID == "" {
		return folderID == ""
	}
	return *c.FolderID == folderID
}

// bulkResult names what an action did, for its result message.
type bulkResult int

const (
	bulkTrashed bulkResult = iota
	bulkRestored
	bulkArchived
	bulkUnarchived
	bulkDeleted
	bulkMoved
)

// dispatch runs work in the session, then clears the selection, refreshes
// the vault and shows one result.
func (m *AppModel) dispatch(work func(context.Context) bulkOutcome, kind bulkResult) {
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	gen := m.LockGeneration()
	m.BulkBusy.Set(true)
	go func() {
		defer cancel()
		out := work(ctx)
		m.Scope.Post(func() {
			m.BulkBusy.Set(false)
			if !m.StillUnlocked(gen) {
				return
			}
			m.ClearSelection()
			m.RefreshVaultData()
			m.showBulkResult(kind, out)
		})
	}()
}

func (m *AppModel) showBulkResult(kind bulkResult, out bulkOutcome) {
	cx := m.Scope
	done := ""
	switch kind {
	case bulkTrashed:
		done = locales.BulkTrashedCount(cx, out.done)
	case bulkRestored:
		done = locales.BulkRestoredCount(cx, out.done)
	case bulkArchived:
		done = locales.BulkArchivedCount(cx, out.done)
	case bulkUnarchived:
		done = locales.BulkUnarchivedCount(cx, out.done)
	case bulkDeleted:
		done = locales.BulkDeletedCount(cx, out.done)
	case bulkMoved:
		done = locales.BulkMovedCount(cx, out.done)
	}
	var notDone []string
	for _, f := range out.failed {
		notDone = append(notDone, locales.BulkItemFailed(cx, f.name, m.errorText(f.err)))
	}
	if out.kept > 0 {
		notDone = append(notDone, locales.BulkDeleteKept(cx, out.kept))
	}
	switch {
	case out.err != nil && kind == bulkMoved:
		m.ShowToast(ui.ToastError, locales.BulkMoveStopped(cx), locales.BulkMoveMaybePartial(cx, m.errorText(out.err)))
	case out.err != nil:
		m.ShowToast(ui.ToastError, done, m.errorText(out.err))
	case len(notDone) > 0:
		m.ShowToast(ui.ToastError, done, locales.BulkNotDone(cx, len(notDone), strings.Join(notDone, "; ")))
	case out.local:
		m.ShowLocalCopyWarning(done)
	default:
		m.ShowToast(ui.ToastSuccess, done, "")
	}
}

// selectionMenu is the context menu of a selection of several items.
func selectionMenu(cx *core.Scope, m *AppModel, at core.Point) {
	b := m.bulkSelection()
	off := !m.writesAllowed()
	var items []desktop.MenuItem
	if b.inTrash {
		items = append(items,
			desktop.MenuItem{Label: locales.Restore(cx), Disabled: off || len(b.restorable) == 0, OnSelect: m.RestoreSelection},
			desktop.MenuItem{Label: locales.DeletePermanentlyMenu(cx), Disabled: off || len(b.deletable) == 0, OnSelect: m.ConfirmDeleteSelection},
		)
	} else {
		items = append(items,
			desktop.MenuItem{Label: locales.MoveToFolderMenu(cx), Disabled: off || len(b.movable) == 0, OnSelect: m.ChooseFolderForSelection},
			desktop.MenuItem{Label: locales.ArchiveAction(cx), Disabled: off || len(b.archivable) == 0, OnSelect: func() { m.ArchiveSelection(cx, true) }},
			desktop.MenuItem{Label: locales.UnarchiveAction(cx), Disabled: off || len(b.unarchivable) == 0, OnSelect: func() { m.ArchiveSelection(cx, false) }},
			desktop.MenuItem{Separator: true},
			desktop.MenuItem{Label: locales.MoveToTrashMenu(cx), Disabled: off || len(b.trashable) == 0, OnSelect: m.ConfirmTrashSelection},
		)
	}
	desktop.PopupMenu(cx, items, at, nil)
}

// SelectionPaneView replaces the detail with the count of selected items
// and what can be done to them: one column of equal buttons, the
// destructive action last.
func SelectionPaneView(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		b := m.bulkSelection()
		off := func() bool { return !m.writesAllowed() }
		button := func(testID, text string, icon func() *core.SVG, variant ui.ButtonVariant, n int, press func()) core.Node {
			return ui.Button{
				TestID: testID, Text: text, Icon: icon, Variant: variant,
				Style:    core.Style{Width: core.Pt(220)},
				Disabled: func() bool { return off() || n == 0 },
				OnPress:  press,
			}
		}
		var actions []core.Node
		if b.inTrash {
			actions = []core.Node{
				button("selection-restore", locales.Restore(cx), lucide.Undo2, ui.ButtonSecondary, len(b.restorable), m.RestoreSelection),
				button("selection-delete", locales.DeletePermanentlyMenu(cx), lucide.Trash, ui.ButtonDanger, len(b.deletable), m.ConfirmDeleteSelection),
			}
		} else {
			actions = []core.Node{
				button("selection-move", locales.MoveToFolderMenu(cx), lucide.FolderInput, ui.ButtonSecondary, len(b.movable), m.ChooseFolderForSelection),
			}
			if len(b.unarchivable) > 0 {
				actions = append(actions, button("selection-unarchive", locales.UnarchiveAction(cx), lucide.ArchiveRestore, ui.ButtonSecondary, len(b.unarchivable), func() { m.ArchiveSelection(cx, false) }))
			}
			if len(b.unarchivable) < len(b.all) {
				actions = append(actions, button("selection-archive", locales.ArchiveAction(cx), lucide.Archive, ui.ButtonSecondary, len(b.archivable), func() { m.ArchiveSelection(cx, true) }))
			}
			actions = append(actions, button("selection-trash", locales.MoveToTrashMenu(cx), lucide.Trash, ui.ButtonSecondary, len(b.trashable), m.ConfirmTrashSelection))
		}
		return core.View{
			TestID: "selection-pane",
			Class:  "flex-1 items-center justify-center p-8 gap-4",
			Children: []core.Node{
				core.View{
					Class:    "w-[56px] h-[56px] rounded-[14px] items-center justify-center bg-gv-accent-soft",
					Children: []core.Node{icon(lucide.ListChecks(), 26, "text-gv-accent")},
				},
				core.Text{TestID: "selection-count", Class: "text-[17px] font-semibold text-gv-fg", Content: locales.ItemsSelected(cx, len(b.all))},
				core.View{Class: "items-center gap-2 pt-1", Children: actions},
				core.Show{
					When: func() bool { return m.SyncState.Get() == SyncOffline },
					Then: func(cx *core.Scope) core.Node {
						return core.Text{Class: "text-[12px] text-gv-fg3", Content: locales.SelectionOffline(cx)}
					},
				},
			},
		}
	})
}

// bulkDialog confirms moving the selection to Trash or deleting it for
// good, or chooses the folder to move it to. Like the other dialogs it is
// always mounted and opens while BulkDialog is set.
func bulkDialog(cx *core.Scope, m *AppModel) core.Node {
	text := func(kind BulkKind, pick func(n int) string) string {
		if d := m.BulkDialog.Get(); d != nil && d.Kind == kind {
			return pick(len(d.Items))
		}
		return ""
	}
	return ui.Dialog{
		TestID: "bulk-dialog",
		Open:   func() bool { return m.BulkDialog.Get() != nil },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.BulkDialog.Set(nil)
			}
		},
		// Return confirms, except a permanent deletion, which only its
		// named button does.
		OnConfirm: func() {
			if d := m.BulkDialog.Get(); d != nil && d.Kind == BulkDelete {
				m.BulkDialog.Set(nil)
				return
			}
			m.ConfirmBulkDialog()
		},
		TitleFunc: func() string {
			return text(BulkTrash, func(n int) string { return locales.BulkTrashTitle(cx, n) }) +
				text(BulkDelete, func(n int) string { return locales.BulkDeleteTitle(cx, n) }) +
				text(BulkMove, func(n int) string { return locales.BulkMoveTitle(cx, n) })
		},
		DescriptionFunc: func() string {
			return text(BulkTrash, func(int) string { return locales.BulkTrashMessage(cx) }) +
				text(BulkDelete, func(int) string { return locales.BulkDeleteMessage(cx) })
		},
		Children: []core.Node{core.Dynamic(func(cx *core.Scope) core.Node {
			d := m.BulkDialog.Get()
			if d == nil {
				return nil
			}
			var body []core.Node
			if d.Kind == BulkMove {
				opts := []ui.Option[string]{{Value: "", Label: locales.NoFolder(cx)}}
				for _, f := range m.Folders.Get() {
					opts = append(opts, ui.Option[string]{Value: f.ID, Label: f.Name})
				}
				body = append(body, ui.Select[string]{
					TestID:   "bulk-folder",
					Label:    locales.Folder(cx),
					Style:    core.Style{Width: core.Pct(100)},
					Options:  opts,
					Value:    m.BulkFolder.Get,
					OnChange: m.BulkFolder.Set,
				}, core.Dynamic(func(cx *core.Scope) core.Node {
					already := 0
					for _, c := range d.Items {
						if inFolder(c, m.BulkFolder.Get()) {
							already++
						}
					}
					if already == 0 {
						return nil
					}
					return core.Text{TestID: "bulk-unchanged", Class: "text-[12px] text-gv-fg2", Content: locales.BulkAlreadyInFolder(cx, already)}
				}))
			}
			if d.Skipped > 0 {
				body = append(body, core.Text{TestID: "bulk-skipped", Class: "text-[12px] text-gv-fg2", Content: locales.BulkSkipped(cx, d.Skipped)})
			}
			return core.View{Class: "gap-2", Children: body}
		})},
		Footer: []core.Node{
			ui.Button{TestID: "bulk-cancel", Text: locales.Cancel(cx), Variant: ui.ButtonSecondary, OnPress: func() { m.BulkDialog.Set(nil) }},
			core.Dynamic(func(cx *core.Scope) core.Node {
				d := m.BulkDialog.Get()
				confirm, variant := locales.Move(cx), ui.ButtonPrimary
				switch {
				case d == nil:
				case d.Kind == BulkTrash:
					confirm = locales.MoveToTrash(cx)
				case d.Kind == BulkDelete:
					confirm, variant = locales.DeletePermanently(cx), ui.ButtonDanger
				}
				return ui.Button{TestID: "bulk-confirm", Text: confirm, Variant: variant, OnPress: m.ConfirmBulkDialog}
			}),
		},
	}
}
