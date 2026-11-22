package ui

import (
	"context"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// TrashDeletable counts the items in Trash the user may delete permanently.
func (m *AppModel) TrashDeletable() int {
	return len(m.Core.TrashSelection().Items)
}

func (m *AppModel) EmptyTrash(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncOffline || m.TrashBusy.Get() {
		return
	}
	sel := m.Core.TrashSelection()
	n := len(sel.Items)
	if n == 0 {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   locales.EmptyTrashTitle(cx),
		Message: locales.EmptyTrashMessage(cx, n),
		Actions: []core.AlertAction{
			{Label: locales.Cancel(cx), Role: core.AlertCancel},
			{Label: locales.EmptyTrash(cx), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.TrashBusy.Set(true)
		gen := m.LockGeneration()
		go func() {
			res, err := m.Core.EmptyTrash(context.Background(), sel)
			m.Scope.Post(func() {
				m.TrashBusy.Set(false)
				if !m.StillUnlocked(gen) {
					return
				}
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
				m.RefreshVaultData()
				var notes []string
				if res.ReadOnly > 0 {
					notes = append(notes, locales.TrashReadOnlyKept(cx, res.ReadOnly))
				}
				if res.Skipped > 0 {
					notes = append(notes, locales.TrashChangedKept(cx, res.Skipped))
				}
				desc := strings.Join(notes, " ")
				switch {
				case err != nil && res.Deleted == 0:
					m.ShowToast(ui.ToastError, locales.EmptyTrashFailed(cx), m.errorText(err))
				case err != nil:
					m.ShowToast(ui.ToastWarning, locales.TrashPartlyDeleted(cx, res.Deleted), locales.TrashSomeNotDeleted(cx, m.errorText(err)))
				default:
					m.ShowToast(ui.ToastInfo, locales.TrashEmptied(cx), desc)
				}
			})
		}()
	})
}

// CanClone reports whether c may be copied into a new personal item: its
// secrets must be visible to the user.
func (m *AppModel) CanClone(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && !m.PasswordHidden(c) && m.SyncState.Get() != SyncOffline
}

// CloneActive opens the editor on a new personal copy of the selected item.
// Organization membership, attachments and history are not copied.
func (m *AppModel) CloneActive(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if !m.CanClone(c) || m.EditMode.Get() {
		return
	}
	m.ResetIdleTimer()
	m.GateReprompt(cx, c, RepromptCloneItem, func() {
		if cur := m.ActiveCipher.Get(); cur == nil || cur.ID != c.ID {
			return
		}
		src := *c
		src.ID = ""
		src.OrganizationID = nil
		src.CollectionIDs = nil
		src.Attachments = nil
		src.PasswordHistory = nil
		src.RevisionDate = nil
		src.CreationDate = nil
		src.DeletedDate = nil
		src.ArchivedDate = nil
		src.Key = nil
		src.Data = nil
		src.EncryptedFor = nil
		src.EncryptedByKeyID = nil
		src.ReadOnly = false
		src.HidePassword = false
		src.Name = locales.CloneName(cx, c.Name)
		// A passkey belongs to one item; Bitwarden does not copy it either.
		hadPasskey := false
		if c.Login != nil {
			login := *c.Login
			hadPasskey = len(login.Fido2Credentials) > 0
			login.Fido2Credentials = nil
			src.Login = &login
		}
		draft := draftFromCipher(&src)
		draft.IsNew = true
		draft.Revision = nil
		m.openDraft(draft)
		m.EditDirty.Set(true)
		m.EditError.Set("")
		m.EditMode.Set(true)
		if hadPasskey {
			m.ShowToast(ui.ToastInfo, locales.PasskeysNotCopied(cx), locales.PasskeysNotCopiedDetail(cx))
		}
	})
}
