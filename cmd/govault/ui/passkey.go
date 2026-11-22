package ui

import (
	"fmt"
	"slices"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// passkeyText describes a passkey without any of its secret material: its
// relying party and when it was created.
func passkeyText(f *state.Fido2Credential) string {
	site := f.RpID
	if site == "" {
		site = f.RpName
	}
	created := ""
	if t, err := time.Parse(time.RFC3339Nano, f.CreationDate); err == nil {
		created = "Created " + t.Local().Format("Jan 2, 2006")
	}
	switch {
	case site != "" && created != "":
		return site + " · " + created
	case site != "":
		return site
	case created != "":
		return created
	}
	return "Stored in this item"
}

func passkeyTestID(base string, i int) string {
	if i == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, i)
}

// detailPasskeyRows shows every passkey of a login, read-only.
func detailPasskeyRows(c *state.Cipher) []core.Node {
	if c.Login == nil {
		return nil
	}
	var rows []core.Node
	for i := range c.Login.Fido2Credentials {
		rows = append(rows, fieldRow("Passkey", fieldOpts{
			testID: passkeyTestID("detail-passkey", i),
			value:  staticValue(passkeyText(&c.Login.Fido2Credentials[i])),
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
		Title:   "Remove passkey?",
		Message: "You will no longer be able to sign in with this passkey.",
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Remove", Role: core.AlertDestructive},
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
				rows = append(rows, formRow("Passkey", core.View{
					Class: "flex-1 flex-row items-center gap-2",
					Children: []core.Node{
						core.Text{TestID: passkeyTestID("editor-passkey-removed", i), Class: "flex-1 text-[13px] text-gv-fg2", Content: "Removed when you save"},
						ui.Button{
							Disabled: m.EditBusy.Get,
							TestID:   passkeyTestID("editor-passkey-undo", i),
							Text:     "Undo",
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
			rows = append(rows, formRow("Passkey", core.View{
				Class: "flex-1 flex-row items-center gap-2",
				Children: []core.Node{
					core.Text{TestID: passkeyTestID("editor-passkey", i), MaxLines: 1, Class: "flex-1 text-[13px] text-gv-fg", Content: passkeyText(&passkeys[i])},
					ui.Button{
						Disabled: m.EditBusy.Get,
						TestID:   passkeyTestID("editor-passkey-remove", i),
						Icon:     lucide.Trash,
						Label:    "Remove passkey",
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
