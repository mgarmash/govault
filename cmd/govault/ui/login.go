package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

func LoginView(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		Class:  "flex-1 items-center justify-center p-8 bg-neutral-50 dark:bg-neutral-950",
		TestID: "login-screen",
		Children: []core.Node{
			core.View{
				Class: "w-[420px] p-6 gap-4 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900",
				Children: []core.Node{
					core.View{
						Class: "items-center gap-2 pb-2",
						Children: []core.Node{
							core.View{
								Class: "w-10 h-10 rounded-lg items-center justify-center bg-blue-600",
								Children: []core.Node{
									core.Icon{
										SVG:   lucide.ShieldCheck(),
										Style: core.Style{Width: core.Pt(20), Height: core.Pt(20), Color: core.RGB(0xffffff)},
									},
								},
							},
							core.Text{
								Class:   "text-xl font-semibold text-neutral-900 dark:text-white",
								Content: "GoVault",
							},
							core.Text{
								Class:   "text-sm text-neutral-500 dark:text-neutral-400",
								Content: "Sign in to Vaultwarden",
							},
						},
					},
					labeledField("Server URL", base.Input{
						TestID:        "login-server",
						Class:         inputClass,
						Placeholder:   "https://vault.example.com",
						NoAutoCorrect: true,
						Value:         m.LoginServer.Get,
						OnChange:      m.LoginServer.Set,
						Disabled:      m.LoginBusy.Get,
					}),
					labeledField("Email", base.Input{
						TestID:        "login-email",
						Class:         inputClass,
						Placeholder:   "alice@example.com",
						NoAutoCorrect: true,
						Value:         m.LoginEmail.Get,
						OnChange:      m.LoginEmail.Set,
						Disabled:      m.LoginBusy.Get,
					}),
					labeledField("Master Password", core.View{
						Class: "flex-row items-center gap-2",
						Children: []core.Node{
							core.Dynamic(func(cx *core.Scope) core.Node {
								masked := !m.LoginShowPW.Get()
								return base.Input{
									TestID:        "login-password",
									Class:         inputClass + " flex-1",
									Placeholder:   "Master Password",
									Masked:        masked,
									NoAutoCorrect: true,
									Value:         m.LoginPassword.Get,
									OnChange:      m.LoginPassword.Set,
									OnSubmit:      func(string) { m.Login() },
									Disabled:      m.LoginBusy.Get,
								}
							}),
							ui.Button{
								TestID:  "login-toggle-pw",
								Variant: ui.ButtonGhost,
								Icon:    func() *core.SVG { return eyeIcon(m.LoginShowPW.Get()) },
								Label:   "Toggle password visibility",
								OnPress: func() { m.LoginShowPW.Set(!m.LoginShowPW.Get()) },
							},
						},
					}),
					core.Show{
						When: func() bool { return m.LoginError.Get() != "" },
						Then: func(cx *core.Scope) core.Node {
							return core.View{
								TestID: "login-error",
								Class:  "px-3 py-2 rounded-md bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800",
								Children: []core.Node{
									core.Text{
										Class:       "text-xs text-red-700 dark:text-red-300",
										ContentFunc: m.LoginError.Get,
									},
								},
							}
						},
					},
					ui.Button{
						TestID:  "login-submit",
						Text:    "Sign In",
						Variant: ui.ButtonPrimary,
						Size:    ui.SizeLarge,
						Busy:    m.LoginBusy.Get,
						Style:   core.Style{Width: core.Pct(100)},
						OnPress: m.Login,
					},
				},
			},
		},
	}
}

const inputClass = "px-3 py-2 rounded-md border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-sm text-neutral-900 dark:text-white"

func labeledField(label string, field core.Node) core.Node {
	return core.View{
		Class: "gap-1",
		Children: []core.Node{
			core.Text{
				Class:   "text-xs font-medium text-neutral-600 dark:text-neutral-400",
				Content: label,
			},
			field,
		},
	}
}

func eyeIcon(visible bool) *core.SVG {
	if visible {
		return lucide.EyeOff()
	}
	return lucide.Eye()
}
