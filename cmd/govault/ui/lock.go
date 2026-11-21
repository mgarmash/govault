package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

func LockView(cx *core.Scope, m *AppModel) core.Node {
	cx.Effect(func() {
		if m.MainWinVisible.Get() && !m.LockAutoFired && m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled && m.Prefs.Get().AutoPromptBiometric {
			m.LockAutoFired = true
			m.UnlockWithBiometric(cx, false)
		}
	})

	return core.View{
		Class:  "flex-1 items-center justify-center p-8 bg-neutral-50 dark:bg-neutral-950",
		TestID: "lock-screen",
		Children: []core.Node{
			core.View{
				Class: "w-[400px] p-6 gap-4 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900",
				Children: []core.Node{
					core.View{
						Class: "items-center gap-1.5 pb-1",
						Children: []core.Node{
							core.View{
								Class: "w-11 h-11 rounded-full items-center justify-center bg-neutral-100 dark:bg-neutral-800",
								Children: []core.Node{
									core.Icon{
										SVG:   lucide.Lock(),
										Style: core.Style{Width: core.Pt(20), Height: core.Pt(20), Color: core.RGB(0x2563eb)},
									},
								},
							},
							core.Text{
								Class:   "text-lg font-semibold text-neutral-900 dark:text-white",
								Content: "Vault is Locked",
							},
							core.Text{
								Class:       "text-sm font-medium text-neutral-700 dark:text-neutral-300",
								ContentFunc: func() string { return m.Prefs.Get().Email },
							},
							core.Text{
								Class:       "text-xs text-neutral-500 dark:text-neutral-400",
								ContentFunc: func() string { return m.Prefs.Get().ServerURL },
							},
						},
					},
					core.Show{
						When: func() bool { return m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled },
						Then: func(cx *core.Scope) core.Node {
							return core.View{
								Class: "gap-3",
								Children: []core.Node{
									ui.Button{
										TestID:  "lock-biometric",
										Text:    "Unlock with " + m.BiometricLabel(),
										Icon:    lucide.KeyRound,
										Variant: ui.ButtonPrimary,
										Size:    ui.SizeLarge,
										Busy:    m.LockBusy.Get,
										Style:   core.Style{Width: core.Pct(100)},
										OnPress: func() { m.UnlockWithBiometric(cx, false) },
									},
									core.View{
										Class: "flex-row items-center gap-2",
										Children: []core.Node{
											core.View{Class: "flex-1 h-px bg-neutral-200 dark:bg-neutral-800"},
											core.Text{Class: "text-xs text-neutral-400", Content: "or master password"},
											core.View{Class: "flex-1 h-px bg-neutral-200 dark:bg-neutral-800"},
										},
									},
								},
							}
						},
					},
					labeledField("Master Password", core.View{
						Class: "flex-row items-center gap-2",
						Children: []core.Node{
							core.Dynamic(func(cx *core.Scope) core.Node {
								masked := !m.LockShowPW.Get()
								return base.Input{
									TestID:        "lock-password",
									Ref:           &m.LockPasswordRef,
									Class:         inputClass + " flex-1",
									Placeholder:   "Enter master password",
									Masked:        masked,
									AutoFocus:     !(m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled),
									NoAutoCorrect: true,
									Value:         m.LockPassword.Get,
									OnChange:      m.LockPassword.Set,
									OnSubmit:      func(string) { m.UnlockWithPassword(false) },
									Disabled:      m.LockBusy.Get,
								}
							}),
							ui.Button{
								TestID:  "lock-toggle-pw",
								Variant: ui.ButtonGhost,
								Icon:    func() *core.SVG { return eyeIcon(m.LockShowPW.Get()) },
								Label:   "Toggle password visibility",
								OnPress: func() { m.LockShowPW.Set(!m.LockShowPW.Get()) },
							},
						},
					}),
					core.Show{
						When: func() bool { return m.LockError.Get() != "" },
						Then: func(cx *core.Scope) core.Node {
							return core.View{
								TestID: "lock-error",
								Class:  "px-3 py-2 rounded-md bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800",
								Children: []core.Node{
									core.Text{
										Class:       "text-xs text-red-700 dark:text-red-300",
										ContentFunc: m.LockError.Get,
									},
								},
							}
						},
					},
					ui.Button{
						TestID:  "lock-submit",
						Text:    "Unlock",
						Variant: ui.ButtonPrimary,
						Size:    ui.SizeLarge,
						Busy:    m.LockBusy.Get,
						Style:   core.Style{Width: core.Pct(100)},
						OnPress: func() { m.UnlockWithPassword(false) },
					},
					core.View{
						Class: "items-center pt-1",
						Children: []core.Node{
							ui.Button{
								TestID:  "lock-logout",
								Text:    "Switch Account / Log Out",
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() { m.Logout(cx) },
							},
						},
					},
				},
			},
		},
	}
}
