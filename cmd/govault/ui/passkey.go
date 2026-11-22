package ui

import (
	"fmt"
	"slices"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// passkeyText describes a passkey without any of its secret material: its
// relying party and when it was created.
func passkeyText(cx *core.Scope, f *state.Fido2Credential) string {
	site := f.RpID
	if site == "" {
		site = f.RpName
	}
	created, err := time.Parse(time.RFC3339Nano, f.CreationDate)
	dated := err == nil
	switch {
	case site != "" && dated:
		return locales.PasskeySiteCreated(cx, site, created.Local())
	case site != "":
		return site
	case dated:
		return locales.PasskeyCreated(cx, created.Local())
	}
	return locales.PasskeyStored(cx)
}

func passkeyTestID(base string, i int) string {
	if i == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, i)
}

// detailPasskeyRows shows every passkey of a login, read-only.
func detailPasskeyRows(cx *core.Scope, c *state.Cipher) []core.Node {
	if c.Login == nil {
		return nil
	}
	var rows []core.Node
	for i := range c.Login.Fido2Credentials {
		rows = append(rows, fieldRow(locales.Passkey(cx), fieldOpts{
			testID: passkeyTestID("detail-passkey", i),
			value:  staticValue(passkeyText(cx, &c.Login.Fido2Credentials[i])),
		}))
	}
	return rows
}

// ConfirmRemovePasskey asks before marking passkey i of the item being
// edited for removal. It goes only when the user saves.
func (m *AppModel) ConfirmRemovePasskey(cx *core.Scope, i int) {
	d := m.EditDraft.Get()
	if i < 0 || i >= len(d.DraftPasskeys()) || d.PasskeyRemoved(i) {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   locales.RemovePasskeyTitle(cx),
		Message: locales.RemovePasskeyMessage(cx),
		Actions: []core.AlertAction{
			{Label: locales.Cancel(cx), Role: core.AlertCancel},
			{Label: locales.Remove(cx), Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx == 1 {
			m.MutateDraft(func(d *EditDraft) {
				if !d.PasskeyRemoved(i) {
					d.RemovedPasskeys = append(d.RemovedPasskeys, i)
				}
			})
		}
	})
}

func hasDraftPasskeys(m *AppModel) bool {
	return len(m.EditDraft.Get().DraftPasskeys()) > 0
}

// editorPasskeyRows lists the passkeys of the item being edited, each with
// its own remove button, or Undo once removed.
func editorPasskeyRows(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		d := m.EditDraft.Get()
		passkeys := d.DraftPasskeys()
		var rows []core.Node
		for i := range passkeys {
			if d.PasskeyRemoved(i) {
				rows = append(rows, formRow(locales.Passkey(cx), core.View{
					Class: "flex-1 flex-row items-center gap-2",
					Children: []core.Node{
						core.Text{TestID: passkeyTestID("editor-passkey-removed", i), Class: "flex-1 text-[13px] text-gv-fg2", Content: locales.RemovedWhenSaved(cx)},
						ui.Button{
							Disabled: m.EditBusy.Get,
							TestID:   passkeyTestID("editor-passkey-undo", i),
							Text:     locales.Undo(cx),
							Variant:  ui.ButtonGhost,
							Size:     ui.SizeSmall,
							OnPress: func() {
								m.MutateDraft(func(d *EditDraft) {
									d.RemovedPasskeys = slices.DeleteFunc(d.RemovedPasskeys, func(x int) bool { return x == i })
								})
							},
						},
					},
				}))
				continue
			}
			rows = append(rows, formRow(locales.Passkey(cx), core.View{
				Class: "flex-1 flex-row items-center gap-2",
				Children: []core.Node{
					core.Text{TestID: passkeyTestID("editor-passkey", i), MaxLines: 1, Class: "flex-1 text-[13px] text-gv-fg", Content: passkeyText(cx, &passkeys[i])},
					ui.Button{
						Disabled: m.EditBusy.Get,
						TestID:   passkeyTestID("editor-passkey-remove", i),
						Icon:     lucide.Trash,
						Label:    locales.RemovePasskey(cx),
						Variant:  ui.ButtonGhost,
						Side:     24,
						IconSize: 13,
						Tint:     func() core.Color { return themeColor(cx, "gv-danger") },
						OnPress:  func() { m.ConfirmRemovePasskey(cx, i) },
					},
				},
			}))
		}
		if len(rows) == 0 {
			return nil
		}
		return card(rows...)
	})
}
