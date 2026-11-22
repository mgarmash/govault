package ui

import (
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
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

func detailPasskeyRow(c *state.Cipher) core.Node {
	if c.Login == nil || len(c.Login.Fido2Credentials) == 0 {
		return nil
	}
	return fieldRow("Passkey", fieldOpts{
		testID: "detail-passkey",
		value:  staticValue(passkeyText(&c.Login.Fido2Credentials[0])),
	})
}

// ConfirmRemovePasskey asks before marking the passkey of the item being
// edited for removal. It goes only when the user saves.
func (m *AppModel) ConfirmRemovePasskey(cx *core.Scope) {
	if m.EditDraft.Get().DraftPasskey() == nil {
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
			m.MutateDraft(func(d *EditDraft) { d.RemovePasskey = true })
		}
	})
}

func editorPasskeyRow(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		d := m.EditDraft.Get()
		if d == nil || d.Source == nil || d.Source.Login == nil || len(d.Source.Login.Fido2Credentials) == 0 || d.Type != api.CipherTypeLogin {
			return nil
		}
		if d.RemovePasskey {
			return formRow("Passkey", core.View{
				Class: "flex-1 flex-row items-center gap-2",
				Children: []core.Node{
					core.Text{TestID: "editor-passkey-removed", Class: "flex-1 text-[13px] text-gv-fg2", Content: "Removed when you save"},
					ui.Button{
						TestID:  "editor-passkey-undo",
						Text:    "Undo",
						Variant: ui.ButtonGhost,
						Size:    ui.SizeSmall,
						OnPress: func() { m.MutateDraft(func(d *EditDraft) { d.RemovePasskey = false }) },
					},
				},
			})
		}
		p := d.DraftPasskey()
		if p == nil {
			return nil
		}
		return formRow("Passkey", core.View{
			Class: "flex-1 flex-row items-center gap-2",
			Children: []core.Node{
				core.Text{TestID: "editor-passkey", MaxLines: 1, Class: "flex-1 text-[13px] text-gv-fg", Content: passkeyText(p)},
				ui.Button{
					TestID:   "editor-passkey-remove",
					Icon:     lucide.Trash,
					Label:    "Remove passkey",
					Variant:  ui.ButtonGhost,
					Side:     24,
					IconSize: 13,
					Tint:     func() core.Color { return themeColor(cx, "gv-danger") },
					OnPress:  func() { m.ConfirmRemovePasskey(cx) },
				},
			},
		})
	})
}
