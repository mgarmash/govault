package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
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

	cx.SetTheme(GovaultTheme())
	transparent := core.NewMemo(cx, func() bool { return desktop.Transparent(cx) })

	return core.View{
		ClassFunc: func() string {
			if transparent.Get() {
				return "flex-1 p-[18px]"
			}
			return "flex-1"
		},
		Children: []core.Node{
			core.View{
				TestID: "quick-panel",
				ClassFunc: func() string {
					if transparent.Get() {
						return "w-[620px] flex-1 bg-gv-panel border border-gv-line rounded-[14px] overflow-hidden"
					}
					return "flex-1 bg-gv-panel overflow-hidden"
				},
				StyleFunc: func() core.Style {
					if !transparent.Get() {
						return core.Style{}
					}
					return core.Style{
						BorderCurve: core.BorderCurveContinuous,
						Shadows:     []core.BoxShadow{ui.Shadow(0, 14, 34, -10, core.RGBA(0x000000, 0.42)), ui.Shadow(0, 1, 3, 0, core.RGBA(0x000000, 0.08))},
					}
				},
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
			},
		},
	}
}

func quickPanelUnlocked(
	cx *core.Scope,
	m *AppModel,
	copyPW, copyUser, copyTOTP, openMain, dismiss func(),
) core.Node {
	hint := func(keys, label string, onPress func()) core.Node {
		return core.View{
			Role:    core.RoleButton,
			Label:   label,
			Class:   "flex-row items-center gap-1.5 h-[24px] px-1.5 rounded-[6px] active:bg-gv-fill-strong",
			OnPress: func(core.PressEvent) { onPress() },
			Children: []core.Node{
				keycap(keys),
				core.Text{Class: "text-[11.5px] text-gv-fg2", Content: label},
			},
		}
	}
	return core.View{
		Class: "flex-1",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-3 px-4 h-[58px] border-b border-gv-line",
				Children: []core.Node{
					icon(lucide.Search(), 19, "text-gv-fg3"),
					base.Input{
						TestID:        "quick-search",
						Ref:           &m.QuickSearchRef,
						Class:         "flex-1 h-full text-[19px] text-gv-fg",
						Placeholder:   "Search GoVault",
						AutoFocus:     true,
						NoAutoCorrect: true,
						StyleFunc: func() core.Style {
							return core.Style{PlaceholderColor: themeColor(cx, "gv-fg3"), CaretColor: themeColor(cx, "gv-accent"), Background: core.Transparent, BorderWidth: 0}
						},
						Value: m.QuickQuery.Get,
						OnChange: func(v string) {
							m.ResetIdleTimer()
							m.QuickQuery.Set(v)
							m.QuickSelectedIdx.Set(0)
							m.RefreshQuickItems()
						},
						OnSubmit: func(string) { copyPW() },
					},
					core.View{
						Role:     core.RoleButton,
						Label:    "Close",
						OnPress:  func(core.PressEvent) { dismiss() },
						Children: []core.Node{keycap("esc")},
					},
				},
			},
			core.View{
				Class: "px-4 pt-2.5 pb-1",
				Children: []core.Node{
					core.Text{
						Class: "text-[11px] font-semibold text-gv-fg3",
						ContentFunc: func() string {
							if m.QuickQuery.Get() != "" {
								return "Top Matches"
							}
							return "Vault Items"
						},
					},
				},
			},
			core.Scroll{
				Class: "flex-1 max-h-[316px] px-2 pb-2",
				Children: []core.Node{
					core.Dynamic(func(cx *core.Scope) core.Node {
						items := m.QuickItems.Get()
						if len(items) == 0 {
							return core.View{
								Class: "py-10 items-center justify-center gap-1.5",
								Children: []core.Node{
									icon(lucide.Search(), 20, "text-gv-fg3"),
									core.Text{Class: "text-[12.5px] text-gv-fg2", Content: "No matching items"},
								},
							}
						}
						rows := make([]core.Node, 0, len(items))
						for i, it := range items {
							rows = append(rows, quickRow(cx, m, i, it, copyPW))
						}
						return core.View{Class: "gap-0.5", Children: rows}
					}),
				},
			},
			core.View{
				Class: "flex-row items-center gap-1 pl-3 pr-2 h-[40px] border-t border-gv-line bg-gv-fill",
				Children: []core.Node{
					core.View{
						Class: "flex-row items-center gap-1.5 flex-1",
						Children: []core.Node{
							icon(ShieldMark(), 13, "text-gv-accent"),
							core.Text{Class: "text-[11.5px] font-semibold text-gv-fg2", Content: "GoVault"},
						},
					},
					hint("↵", "Password", copyPW),
					hint(cx.KeyLabel("mod+enter"), "Username", copyUser),
					hint(cx.KeyLabel("mod+t"), "Code", copyTOTP),
					hint(cx.KeyLabel("mod+o"), "Open", openMain),
				},
			},
		},
	}
}

func quickRow(cx *core.Scope, m *AppModel, idx int, item state.CipherSummary, copyPW func()) core.Node {
	selected := func() bool { return m.QuickSelectedIdx.Get() == idx }
	return core.View{
		TestID: fmt.Sprintf("quick-row-%d", idx),
		ClassFunc: func() string {
			if selected() {
				return "flex-row items-center gap-3 h-[46px] px-2.5 rounded-[9px] bg-gv-accent"
			}
			return "flex-row items-center gap-3 h-[46px] px-2.5 rounded-[9px]"
		},
		OnPress: func(core.PressEvent) {
			m.QuickSelectedIdx.Set(idx)
			copyPW()
		},
		Children: []core.Node{
			itemEmblem(item.Name, item.Type, item.Subtitle, 28),
			core.View{
				Class: "flex-1 flex-row items-baseline gap-2 overflow-hidden",
				Children: []core.Node{
					core.Text{
						MaxLines: 1,
						ClassFunc: func() string {
							if selected() {
								return "text-[13.5px] font-semibold text-white"
							}
							return "text-[13.5px] font-medium text-gv-fg"
						},
						Content: item.Name,
					},
					core.Text{
						MaxLines: 1,
						ClassFunc: func() string {
							if selected() {
								return "flex-1 text-[12px] text-white/75"
							}
							return "flex-1 text-[12px] text-gv-fg3"
						},
						Content: item.Subtitle,
					},
				},
			},
			core.Show{
				When: func() bool { return selected() && item.HasTOTP && m.TOTPCode.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "flex-row items-center gap-1.5 h-[24px] px-2 rounded-[6px] bg-white/20",
						Children: []core.Node{
							ui.ProgressRing{
								Size: 12,
								Value: func() float32 {
									period := m.TOTPPeriod.Get()
									if period <= 0 {
										return 0
									}
									return float32(m.TOTPRemaining.Get()) * 100 / float32(period)
								},
								Tint: func() core.Color { return core.RGB(0xffffff) },
							},
							core.Text{
								Class:       "text-[12.5px] font-mono font-semibold text-white tracking-[1px]",
								ContentFunc: func() string { return FormatTOTPCode(m.TOTPCode.Get()) },
							},
						},
					}
				},
				Else: func(cx *core.Scope) core.Node {
					return core.Show{
						When: func() bool { return item.HasTOTP },
						Then: func(cx *core.Scope) core.Node { return icon(lucide.Timer(), 13, "text-gv-fg3") },
					}
				},
			},
			core.Show{
				When: selected,
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "h-[20px] w-[22px] rounded-[5px] items-center justify-center bg-white/20",
						Children: []core.Node{
							icon(lucide.CornerDownLeft(), 12, "text-white"),
						},
					}
				},
			},
		},
	}
}

func quickPanelLocked(cx *core.Scope, m *AppModel) core.Node {
	show := core.NewSignal(cx, false)
	biometric := func() bool { return m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled }
	return core.View{
		TestID: "quick-panel-locked",
		Class:  "p-5 gap-4",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-3",
				Children: []core.Node{
					brandEmblem(38),
					core.View{
						Class: "flex-1 gap-[1px]",
						Children: []core.Node{
							core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: "GoVault is Locked"},
							core.Text{
								MaxLines:    1,
								Class:       "text-[12px] text-gv-fg2",
								ContentFunc: func() string { return m.Prefs.Get().Email },
							},
						},
					},
					core.Show{
						When: biometric,
						Then: func(cx *core.Scope) core.Node {
							return ui.Button{
								TestID:  "quick-unlock-biometric",
								Text:    m.BiometricLabel(),
								Icon:    lucide.FingerprintPattern,
								Variant: ui.ButtonSecondary,
								Busy:    m.QuickUnlockBusy.Get,
								OnPress: func() { m.UnlockWithBiometric(cx, true) },
							}
						},
					},
				},
			},
			passwordField(cx, base.Input{
				TestID:        "quick-unlock-password",
				Placeholder:   "Master password",
				AutoFocus:     true,
				NoAutoCorrect: true,
				Value:         m.QuickPassword.Get,
				OnChange:      m.QuickPassword.Set,
				OnSubmit:      func(string) { m.UnlockWithPassword(true) },
				Disabled:      m.QuickUnlockBusy.Get,
			}, authFieldHeight, show, "quick-toggle-pw", ui.Button{
				TestID:   "quick-unlock-submit",
				Icon:     lucide.ArrowRight,
				Label:    "Unlock",
				Variant:  ui.ButtonPrimary,
				Side:     authFieldHeight - 10,
				IconSize: 13,
				Busy:     m.QuickUnlockBusy.Get,
				Style:    core.Style{CornerRadius: (authFieldHeight - 10) / 2},
				OnPress:  func() { m.UnlockWithPassword(true) },
			}),
			core.Show{
				When: func() bool { return m.QuickUnlockError.Get() != "" },
				Then: func(cx *core.Scope) core.Node { return errorBanner("quick-unlock-error", m.QuickUnlockError.Get) },
			},
		},
	}
}

func quickPanelLoggedOut(m *AppModel, dismiss func()) core.Node {
	return core.View{
		Class: "p-5 flex-row items-center gap-3",
		Children: []core.Node{
			brandEmblem(38),
			core.View{
				Class: "flex-1 gap-[1px]",
				Children: []core.Node{
					core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: "Quick Access"},
					core.Text{Class: "text-[12px] text-gv-fg2", Content: "Sign in to GoVault to search your vault from anywhere."},
				},
			},
			ui.Button{
				Text:    "Open GoVault",
				Variant: ui.ButtonPrimary,
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
