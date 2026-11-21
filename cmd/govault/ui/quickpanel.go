package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

func QuickPanelView(cx *core.Scope, m *AppModel) core.Node {
	dismiss := func() {
		if m.Hooks.HideQuickPanel != nil {
			m.Hooks.HideQuickPanel()
		}
	}

	selectedCipher := func() *state.Cipher {
		items := m.QuickItems.Get()
		idx := m.QuickSelectedIdx.Get()
		if idx < 0 || idx >= len(items) {
			return nil
		}
		c, err := m.Core.GetCipher(items[idx].ID)
		if err != nil {
			return nil
		}
		return c
	}

	copySelectedPassword := func() {
		c := selectedCipher()
		if c == nil || c.Login == nil || c.Login.Password == "" {
			return
		}
		m.GateReprompt(cx, c, "copy password", func() {
			m.CopySecretValue("Password", c.Login.Password)
			dismiss()
		})
	}

	copySelectedUsername := func() {
		c := selectedCipher()
		if c == nil || c.Login == nil || c.Login.Username == "" {
			return
		}
		m.CopyPlainValue("Username", c.Login.Username)
		dismiss()
	}

	copySelectedTOTP := func() {
		c := selectedCipher()
		if c == nil || c.Login == nil || strings.TrimSpace(c.Login.TOTP) == "" {
			return
		}
		cfg, err := totp.ParseTOTP(c.Login.TOTP)
		if err != nil {
			return
		}
		code, _, _, err := totp.Generate(cfg, time.Now())
		if err != nil {
			return
		}
		m.GateReprompt(cx, c, "copy TOTP code", func() {
			m.CopySecretValue("TOTP code", code)
			dismiss()
		})
	}

	openSelectedInMain := func() {
		items := m.QuickItems.Get()
		idx := m.QuickSelectedIdx.Get()
		if idx >= 0 && idx < len(items) {
			m.Route.Set(RouteVault)
			m.SelectCipher(cx, items[idx].ID)
		}
		dismiss()
		if m.Hooks.OpenMainWindow != nil {
			m.Hooks.OpenMainWindow()
		}
	}

	cx.OnKeyWith("escape", core.KeyOptions{When: core.KeyAlways}, dismiss)
	cx.OnKeyWith("down", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		n := len(m.QuickItems.Get())
		if n == 0 {
			return
		}
		idx := m.QuickSelectedIdx.Get() + 1
		if idx >= n {
			idx = 0
		}
		m.QuickSelectedIdx.Set(idx)
	})
	cx.OnKeyWith("up", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		n := len(m.QuickItems.Get())
		if n == 0 {
			return
		}
		idx := m.QuickSelectedIdx.Get() - 1
		if idx < 0 {
			idx = n - 1
		}
		m.QuickSelectedIdx.Set(idx)
	})
	cx.OnKeyWith("mod+enter", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			copySelectedUsername()
		}
	})
	cx.OnKeyWith("mod+t", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			copySelectedTOTP()
		}
	})
	cx.OnKeyWith("mod+o", core.KeyOptions{When: core.KeyAlways}, func() {
		if m.LockState.Get() == state.StatusUnlocked {
			openSelectedInMain()
		}
	})

	return core.View{
		TestID: "quick-panel",
		Class:  "flex-1 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-xl overflow-hidden",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				switch m.LockState.Get() {
				case state.StatusUnlocked:
					return quickPanelUnlocked(cx, m, copySelectedPassword, copySelectedUsername, copySelectedTOTP, openSelectedInMain, dismiss)
				case state.StatusLocked:
					return quickPanelLocked(cx, m)
				default:
					return quickPanelLoggedOut(m, dismiss)
				}
			}),
		},
	}
}

func quickPanelUnlocked(
	cx *core.Scope,
	m *AppModel,
	copyPW, copyUser, copyTOTP, openMain, dismiss func(),
) core.Node {
	return core.View{
		Class: "flex-1",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-2 px-3 py-2.5 border-b border-neutral-200 dark:border-neutral-800",
				Children: []core.Node{
					core.Icon{
						SVG:   lucide.Search(),
						Style: core.Style{Width: core.Pt(15), Height: core.Pt(15), Color: core.RGB(0x6b7280)},
					},
					base.Input{
						TestID:        "quick-search",
						Ref:           &m.QuickSearchRef,
						Class:         "flex-1 text-sm text-neutral-900 dark:text-white",
						Placeholder:   "Search logins, notes, cards...",
						AutoFocus:     true,
						NoAutoCorrect: true,
						Value:         m.QuickQuery.Get,
						OnChange: func(v string) {
							m.ResetIdleTimer()
							m.QuickQuery.Set(v)
							m.QuickSelectedIdx.Set(0)
							m.RefreshQuickItems()
						},
						OnSubmit: func(string) { copyPW() },
					},
					ui.Button{
						Text:    "Esc",
						Variant: ui.ButtonGhost,
						Size:    ui.SizeSmall,
						OnPress: dismiss,
					},
				},
			},
			core.Scroll{
				Class: "flex-1 p-1.5",
				Children: []core.Node{
					core.Dynamic(func(cx *core.Scope) core.Node {
						items := m.QuickItems.Get()
						if len(items) == 0 {
							return core.View{
								Class: "py-8 items-center justify-center",
								Children: []core.Node{
									core.Text{
										Class:   "text-xs text-neutral-400",
										Content: "No matching items",
									},
								},
							}
						}
						rows := make([]core.Node, 0, len(items))
						for i, it := range items {
							idx := i
							item := it
							selected := func() bool { return m.QuickSelectedIdx.Get() == idx }
							rows = append(rows, core.View{
								TestID: fmt.Sprintf("quick-row-%d", idx),
								ClassFunc: func() string {
									if selected() {
										return "flex-row items-center justify-between px-2.5 py-2 rounded-md bg-blue-600/15"
									}
									return "flex-row items-center justify-between px-2.5 py-2 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800"
								},
								OnPress: func(core.PressEvent) {
									m.QuickSelectedIdx.Set(idx)
									copyPW()
								},
								Children: []core.Node{
									core.View{
										Class: "flex-row items-center gap-2 flex-1 overflow-hidden",
										Children: []core.Node{
											core.Text{
												MaxLines: 1,
												ClassFunc: func() string {
													if selected() {
														return "text-sm font-semibold text-blue-700 dark:text-blue-400"
													}
													return "text-sm font-medium text-neutral-900 dark:text-white"
												},
												Content: item.Name,
											},
											core.Show{
												When: func() bool { return item.Subtitle != "" },
												Then: func(cx *core.Scope) core.Node {
													return core.Text{
														MaxLines: 1,
														Class:    "text-xs text-neutral-500 dark:text-neutral-400 flex-1",
														Content:  "· " + item.Subtitle,
													}
												},
											},
										},
									},
									core.View{
										Class: "flex-row items-center gap-1.5",
										Children: []core.Node{
											core.Show{
												When: func() bool { return item.HasTOTP },
												Then: func(cx *core.Scope) core.Node {
													return ui.Badge{Text: "TOTP", Variant: ui.BadgeInfo}
												},
											},
										},
									},
								},
							})
						}
						return core.View{Class: "gap-0.5", Children: rows}
					}),
				},
			},
			core.View{
				Class: "flex-row items-center justify-between px-3 py-2 border-t border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950",
				Children: []core.Node{
					core.Text{
						Class:   "text-[11px] text-neutral-500 dark:text-neutral-400",
						Content: "Enter Copy Password · " + cx.KeyLabel("mod+enter") + " Copy User · " + cx.KeyLabel("mod+t") + " Copy TOTP · " + cx.KeyLabel("mod+o") + " Open",
					},
					core.View{
						Class: "flex-row items-center gap-1",
						Children: []core.Node{
							ui.Button{Text: "User", Variant: ui.ButtonGhost, Size: ui.SizeSmall, OnPress: copyUser},
							ui.Button{Text: "TOTP", Variant: ui.ButtonGhost, Size: ui.SizeSmall, OnPress: copyTOTP},
							ui.Button{Text: "Open", Variant: ui.ButtonGhost, Size: ui.SizeSmall, OnPress: openMain},
						},
					},
				},
			},
		},
	}
}

func quickPanelLocked(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "quick-panel-locked",
		Class:  "p-4 gap-3",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-2",
				Children: []core.Node{
					core.Icon{
						SVG:   lucide.Lock(),
						Style: core.Style{Width: core.Pt(16), Height: core.Pt(16), Color: core.RGB(0x2563eb)},
					},
					core.Text{
						Class:   "text-sm font-medium text-neutral-900 dark:text-white",
						Content: "GoVault is locked",
					},
				},
			},
			core.View{
				Class: "flex-row items-center gap-2",
				Children: []core.Node{
					base.Input{
						TestID:        "quick-unlock-password",
						Class:         inputClass + " flex-1",
						Placeholder:   "Master Password...",
						Masked:        true,
						AutoFocus:     true,
						NoAutoCorrect: true,
						Value:         m.QuickPassword.Get,
						OnChange:      m.QuickPassword.Set,
						OnSubmit:      func(string) { m.UnlockWithPassword(true) },
						Disabled:      m.QuickUnlockBusy.Get,
					},
					ui.Button{
						TestID:  "quick-unlock-submit",
						Text:    "Unlock",
						Variant: ui.ButtonPrimary,
						Size:    ui.SizeSmall,
						Busy:    m.QuickUnlockBusy.Get,
						OnPress: func() { m.UnlockWithPassword(true) },
					},
					core.Show{
						When: func() bool { return m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled },
						Then: func(cx *core.Scope) core.Node {
							return ui.Button{
								TestID:  "quick-unlock-biometric",
								Text:    m.BiometricLabel(),
								Icon:    lucide.KeyRound,
								Variant: ui.ButtonSecondary,
								Size:    ui.SizeSmall,
								Busy:    m.QuickUnlockBusy.Get,
								OnPress: func() { m.UnlockWithBiometric(cx, true) },
							}
						},
					},
				},
			},
			core.Show{
				When: func() bool { return m.QuickUnlockError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class:       "text-xs text-red-600 dark:text-red-400",
						ContentFunc: m.QuickUnlockError.Get,
					}
				},
			},
		},
	}
}

func quickPanelLoggedOut(m *AppModel, dismiss func()) core.Node {
	return core.View{
		Class: "p-4 flex-row items-center justify-between gap-3",
		Children: []core.Node{
			core.Text{
				Class:   "text-sm text-neutral-700 dark:text-neutral-300",
				Content: "Sign in to GoVault to use Quick Access.",
			},
			ui.Button{
				Text:    "Open GoVault",
				Variant: ui.ButtonPrimary,
				Size:    ui.SizeSmall,
				OnPress: func() {
					dismiss()
					if m.Hooks.OpenMainWindow != nil {
						m.Hooks.OpenMainWindow()
					}
				},
			},
		},
	}
}
