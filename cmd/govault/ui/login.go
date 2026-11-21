package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

const authFieldHeight core.Points = 34

func LoginView(cx *core.Scope, m *AppModel) core.Node {
	return authScreen("login-screen", []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				brandEmblem(56),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: "Sign in to GoVault"},
				core.Text{
					Class:   "text-[12.5px] text-gv-fg2 text-center",
					Content: "Connect to your Bitwarden or Vaultwarden server.",
				},
			},
		},
		core.View{
			Class: "gap-3.5",
			Children: []core.Node{
				formField("Server URL", authInput(base.Input{
					TestID:        "login-server",
					Placeholder:   "https://vault.example.com",
					NoAutoCorrect: true,
					Value:         m.LoginServer.Get,
					OnChange:      m.LoginServer.Set,
					Disabled:      m.LoginBusy.Get,
				})),
				formField("Email", authInput(base.Input{
					TestID:        "login-email",
					Placeholder:   "name@example.com",
					NoAutoCorrect: true,
					Value:         m.LoginEmail.Get,
					OnChange:      m.LoginEmail.Set,
					Disabled:      m.LoginBusy.Get,
				})),
				formField("Master Password", passwordField(cx, base.Input{
					TestID:        "login-password",
					Placeholder:   "Required",
					NoAutoCorrect: true,
					Value:         m.LoginPassword.Get,
					OnChange:      m.LoginPassword.Set,
					OnSubmit:      func(string) { m.Login() },
					Disabled:      m.LoginBusy.Get,
				}, authFieldHeight, m.LoginShowPW, "login-toggle-pw")),
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("login-error", m.LoginError.Get) },
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
	}, "End-to-end encrypted. Your master password never leaves this device.")
}

func authScreen(testID string, body []core.Node, footnote string) core.Node {
	return core.View{
		TestID: testID,
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{Style: core.Style{Height: core.Pt(titleBarHeight)}, Desktop: dragRegion()},
			core.View{
				Class: "flex-1 items-center justify-center px-8 pb-[52px] gap-5",
				Children: []core.Node{
					core.View{
						Class: "w-[380px] px-8 pt-8 pb-7 gap-5 rounded-[16px] bg-gv-card border border-gv-line",
						Style: core.Style{
							BorderCurve: core.BorderCurveContinuous,
							Shadows: []core.BoxShadow{
								ui.Shadow(0, 1, 3, 0, core.RGBA(0x000000, 0.05)),
								ui.Shadow(0, 18, 40, -16, core.RGBA(0x000000, 0.22)),
							},
						},
						Children: body,
					},
					core.View{
						Class: "flex-row items-center gap-1.5",
						Children: []core.Node{
							icon(lucide.LockKeyhole(), 11, "text-gv-fg3"),
							core.Text{Class: "text-[11.5px] text-gv-fg3", Content: footnote},
						},
					},
				},
			},
		},
	}
}

func formField(label string, field core.Node) core.Node {
	return core.View{
		Class: "gap-1.5",
		Children: []core.Node{
			core.Text{Class: "text-[12px] font-medium text-gv-fg2", Content: label},
			field,
		},
	}
}

func labeledField(label string, field core.Node) core.Node { return formField(label, field) }

func sizedInput(in base.Input, height core.Points) ui.Input {
	in.Style = core.Style{Height: core.Pt(height), FontSize: 13, CornerRadius: 7}.Merge(in.Style)
	return ui.Input(in)
}

func authInput(in base.Input) core.Node { return sizedInput(in, authFieldHeight) }

// passwordField is a masked input with a reveal toggle and optional trailing controls inside its rim.
func passwordField(cx *core.Scope, in base.Input, height core.Points, show *core.Signal[bool], toggleTestID string, trailing ...core.Node) core.Node {
	inset := core.Points(34 + 28*len(trailing))
	controls := []core.Node{
		ui.Button{
			TestID:   toggleTestID,
			Variant:  ui.ButtonGhost,
			Icon:     func() *core.SVG { return eyeIcon(show.Get()) },
			Label:    "Toggle password visibility",
			Side:     height - 8,
			IconSize: 14,
			Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
			OnPress:  func() { show.Set(!show.Get()) },
		},
	}
	controls = append(controls, trailing...)
	return core.View{
		Class: "relative",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				field := in
				field.Masked = !show.Get()
				field.OnBlur = settleSecureInput
				field.Style = core.Style{Padding: core.Edges{Left: 10, Right: inset}}.Merge(field.Style)
				return sizedInput(field, height)
			}),
			core.View{
				Class:    "absolute right-1 top-0 bottom-0 flex-row items-center gap-0.5",
				Children: controls,
			},
		},
	}
}

func eyeIcon(visible bool) *core.SVG {
	if visible {
		return lucide.EyeOff()
	}
	return lucide.Eye()
}
