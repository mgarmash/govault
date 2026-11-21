package ui

import (
	"strings"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func MainWindowView(cx *core.Scope, m *AppModel) core.Node {
	cx.SetTheme(GovaultTheme())
	if cx.Env().OS() == core.OSMacOS {
		desktop.SetTitleBar(cx, desktop.TitleBarHidden, titleBarHeight)
	}
	bindMainWindowShortcuts(cx, m)

	return core.View{
		TestID: "main-window-root",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				switch m.LockState.Get() {
				case state.StatusUnlocked:
					return UnlockedShellView(cx, m)
				case state.StatusLocked:
					return LockView(cx, m)
				default:
					return LoginView(cx, m)
				}
			}),
			repromptDialog(m),
			folderDialog(m),
			ui.Toasts{
				Toaster:   m.Toaster,
				Placement: ui.ToastBottomEnd,
			},
		},
	}
}

func bindMainWindowShortcuts(cx *core.Scope, m *AppModel) {
	cx.OnKeyWith("mod+f", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		m.ResetIdleTimer()
		m.Route.Set(RouteVault)
		m.SearchRef.Focus()
	})
	cx.OnKeyWith("mod+n", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.SyncState.Get() != SyncOffline {
			m.StartCreateCipher(cx)
		}
	})
	cx.OnKeyWith("mod+e", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() && m.SyncState.Get() != SyncOffline {
			m.StartEditCipher(cx)
		}
	})
	cx.OnKeyWith("mod+s", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.EditMode.Get() {
			m.SaveDraft(cx)
		}
	})
	cx.OnKeyWith("escape", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.EditMode.Get() {
			m.CancelEdit(cx)
		}
	})
	cx.OnKeyWith("mod+c", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c == nil || c.Login == nil || c.Login.Password == "" {
			return
		}
		m.GateReprompt(cx, c, "copy password", func() {
			m.CopySecretValue("Password", c.Login.Password)
		})
	})
	cx.OnKeyWith("mod+shift+u", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c != nil && c.Login != nil && c.Login.Username != "" {
			m.CopyPlainValue("Username", c.Login.Username)
		}
	})
	cx.OnKeyWith("mod+shift+t", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked || m.Route.Get() != RouteVault || m.EditMode.Get() {
			return
		}
		c := m.ActiveCipher.Get()
		if c == nil || c.Login == nil || strings.TrimSpace(c.Login.TOTP) == "" {
			return
		}
		m.GateReprompt(cx, c, "copy TOTP code", func() {
			if code := m.TOTPCode.Get(); code != "" {
				m.CopySecretValue("TOTP code", code)
			}
		})
	})
	cx.OnKeyWith("mod+l", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.Lock()
		}
	})
	cx.OnKeyWith("mod+r", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.SyncNow(false)
		}
	})
	cx.OnKeyWith("mod+,", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			m.GuardDirty(cx, func() { m.Route.Set(RouteSettings) })
		}
	})
	cx.OnKeyWith("down", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() {
			m.MoveListSelection(cx, 1)
		}
	})
	cx.OnKeyWith("up", core.KeyOptions{When: core.KeyNotEditing}, func() {
		if m.LockState.Get() == state.StatusUnlocked && m.Route.Get() == RouteVault && !m.EditMode.Get() {
			m.MoveListSelection(cx, -1)
		}
	})
}

func repromptDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "reprompt-dialog",
		Open:   func() bool { return m.Reprompt.Get().Open },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.RepromptPW.Set("")
				m.RepromptError.Set("")
				m.Reprompt.Set(RepromptModal{})
			}
		},
		OnConfirm: m.SubmitReprompt,
		Title:     "Master Password Verification",
		DescriptionFunc: func() string {
			act := m.Reprompt.Get().Action
			if act == "" {
				return "Enter your master password to continue."
			}
			return "Enter your master password to " + act + "."
		},
		Children: []core.Node{
			ui.Input{
				TestID:        "reprompt-password",
				Placeholder:   "Master Password",
				Masked:        true,
				AutoFocus:     true,
				NoAutoCorrect: true,
				Value:         m.RepromptPW.Get,
				OnChange:      m.RepromptPW.Set,
				OnSubmit:      func(string) { m.SubmitReprompt() },
			},
			core.Show{
				When: func() bool { return m.RepromptError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class:       "text-[12px] text-gv-danger",
						ContentFunc: m.RepromptError.Get,
					}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				Text:    "Cancel",
				Variant: ui.ButtonSecondary,
				OnPress: func() {
					m.RepromptPW.Set("")
					m.RepromptError.Set("")
					m.Reprompt.Set(RepromptModal{})
				},
			},
			ui.Button{
				TestID:  "reprompt-confirm",
				Text:    "Verify",
				Variant: ui.ButtonPrimary,
				Busy:    m.RepromptBusy.Get,
				OnPress: m.SubmitReprompt,
			},
		},
	}
}

func folderDialog(m *AppModel) core.Node {
	return ui.Dialog{
		TestID: "folder-dialog",
		Open:   func() bool { return m.FolderDialog.Get().Open },
		OnOpenChange: func(open bool, _ base.Reason) {
			if !open {
				m.FolderError.Set("")
				m.FolderDialog.Set(FolderModal{})
			}
		},
		OnConfirm: m.SaveFolderModal,
		TitleFunc: func() string {
			if m.FolderDialog.Get().FolderID == "" {
				return "New Folder"
			}
			return "Rename Folder"
		},
		Children: []core.Node{
			ui.Input{
				TestID:      "folder-name-input",
				Placeholder: "Folder name",
				AutoFocus:   true,
				Value:       func() string { return m.FolderDialog.Get().Name },
				OnChange: func(v string) {
					dlg := m.FolderDialog.Get()
					dlg.Name = v
					m.FolderDialog.Set(dlg)
				},
				OnSubmit: func(string) { m.SaveFolderModal() },
			},
			core.Show{
				When: func() bool { return m.FolderError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class:       "text-[12px] text-gv-danger",
						ContentFunc: m.FolderError.Get,
					}
				},
			},
		},
		Footer: []core.Node{
			ui.Button{
				Text:    "Cancel",
				Variant: ui.ButtonSecondary,
				OnPress: func() {
					m.FolderError.Set("")
					m.FolderDialog.Set(FolderModal{})
				},
			},
			ui.Button{
				TestID:  "folder-save-btn",
				Text:    "Save",
				Variant: ui.ButtonPrimary,
				Busy:    m.FolderBusy.Get,
				OnPress: m.SaveFolderModal,
			},
		},
	}
}
