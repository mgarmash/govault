package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/api"
)

func TwoFactorView(cx *core.Scope, m *AppModel, prompt *TwoFactorPrompt) core.Node {
	emailSelected := func() bool { return m.TwoFactorProvider.Get() == api.TwoFactorEmail }
	yubiKeySelected := func() bool { return m.TwoFactorProvider.Get() == api.TwoFactorYubiKey }
	busy := m.LoginBusy.Get

	body := []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				twoFactorEmblem(),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: locales.TwoFactorTitle(cx)},
				core.Text{
					Class: "text-[12.5px] text-gv-fg2 text-center",
					ContentFunc: func() string {
						if yubiKeySelected() {
							return locales.TwoFactorEnterYubiKey(cx)
						}
						if emailSelected() {
							if prompt.EmailHint != "" {
								return locales.TwoFactorEnterEmailCodeTo(cx, prompt.EmailHint)
							}
							return locales.TwoFactorEnterEmailCode(cx)
						}
						return locales.TwoFactorEnterAuthenticatorCode(cx)
					},
				},
			},
		},
	}

	if len(prompt.Providers) > 1 {
		var toggles []core.Node
		for _, p := range prompt.Providers {
			switch p {
			case api.TwoFactorAuthenticator:
				toggles = append(toggles, providerToggle(m, "twofactor-provider-authenticator", p, lucide.Smartphone))
			case api.TwoFactorEmail:
				toggles = append(toggles, providerToggle(m, "twofactor-provider-email", p, lucide.Mail))
			case api.TwoFactorYubiKey:
				toggles = append(toggles, providerToggle(m, "twofactor-provider-yubikey", p, lucide.Usb))
			}
		}
		body = append(body, core.View{
			Class: "items-center",
			Children: []core.Node{
				ui.ToggleGroup{
					TestID:   "twofactor-providers",
					Label:    locales.TwoFactorMethod(cx),
					Disabled: busy,
					Children: toggles,
				},
			},
		})
	}

	body = append(body,
		core.View{
			Class: "gap-3",
			Children: []core.Node{
				core.Dynamic(func(cx *core.Scope) core.Node {
					if yubiKeySelected() {
						return formField(locales.VerificationCode(cx), yubiKeyInput(m))
					}
					return formField(locales.VerificationCode(cx), authInput(base.Input{
						TestID:        "twofactor-code",
						Class:         "font-mono",
						Placeholder:   "123456",
						NoAutoCorrect: true,
						AutoFocus:     true,
						MaxLength:     12,
						Value:         m.TwoFactorCode.Get,
						OnChange:      m.TwoFactorCode.Set,
						OnSubmit:      func(string) { m.VerifyTwoFactor() },
						Disabled:      busy,
						Style:         core.Style{FontSize: 15, LetterSpacing: 2},
					}))
				}),
				core.Show{
					When: emailSelected,
					Then: func(cx *core.Scope) core.Node { return emailCodeRow(m) },
				},
				ui.Checkbox{
					TestID:   "twofactor-remember",
					Text:     locales.RememberDevice(cx),
					Checked:  m.TwoFactorRemember.Get,
					OnChange: m.TwoFactorRemember.Set,
					Disabled: busy,
				},
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("twofactor-error", m.LoginError.Get) },
		},
		core.View{
			Class: "gap-2",
			Children: []core.Node{
				ui.Button{
					TestID:  "twofactor-verify",
					Text:    locales.Verify(cx),
					Variant: ui.ButtonPrimary,
					Size:    ui.SizeLarge,
					Busy:    busy,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.VerifyTwoFactor,
				},
				ui.Button{
					TestID:   "twofactor-back",
					Text:     locales.BackToSignIn(cx),
					Variant:  ui.ButtonGhost,
					Disabled: busy,
					Style:    core.Style{Width: core.Pct(100)},
					OnPress:  m.CancelTwoFactor,
				},
			},
		},
	)
	return authScreen("twofactor-screen", body, locales.TwoFactorFootnote(cx))
}

// yubiKeyInput takes the OTP a YubiKey types when touched. The key ends
// it with Enter, which submits. As in Bitwarden's clients the field is
// masked, so macOS holds Secure Event Input while it has the focus; it is
// released on blur, submit and Back to Sign In, as for the master password.
func yubiKeyInput(m *AppModel) core.Node {
	return authInput(base.Input{
		TestID:         "twofactor-code",
		Class:          "font-mono",
		Masked:         true,
		NoAutoCorrect:  true,
		AutoCapitalize: core.AutoCapitalizeNone,
		AutoFocus:      true,
		MaxLength:      64,
		Value:          m.TwoFactorCode.Get,
		OnChange:       m.TwoFactorCode.Set,
		OnSubmit:       func(string) { m.VerifyTwoFactor() },
		OnBlur:         settleSecureInput,
		Disabled:       m.LoginBusy.Get,
	})
}

func providerToggle(m *AppModel, testID string, p api.TwoFactorProvider, glyph func() *core.SVG) core.Node {
	return ui.ToggleButton{
		TestID:   testID,
		Text:     twoFactorProviderName(m.Scope, p),
		Icon:     glyph,
		On:       func() bool { return m.TwoFactorProvider.Get() == p },
		OnChange: func(bool) { m.SelectTwoFactorProvider(p) },
	}
}

func emailCodeRow(m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-2",
		Children: []core.Node{
			core.Text{
				Class:       "flex-1 text-[11.5px] text-gv-fg2",
				ContentFunc: func() string { return m.TwoFactorNotice.Get() },
			},
			core.Dynamic(func(cx *core.Scope) core.Node {
				text := locales.SendCode(cx)
				if m.TwoFactorNotice.Get() != "" {
					text = locales.ResendCode(cx)
				}
				return ui.Button{
					TestID:   "twofactor-send-email",
					Text:     text,
					Variant:  ui.ButtonOutline,
					Icon:     lucide.Send,
					Busy:     m.TwoFactorSending.Get,
					Disabled: m.LoginBusy.Get,
					OnPress:  m.SendTwoFactorEmail,
				}
			}),
		},
	}
}

func twoFactorEmblem() core.Node {
	const size core.Points = 56
	return core.View{
		Style: core.Style{
			Width: core.Pt(size), Height: core.Pt(size),
			CornerRadius: size * 0.28, BorderCurve: core.BorderCurveContinuous,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Gradients: []core.Gradient{core.LinearGradient(160, core.RGB(0x3f7dff), core.RGB(0x1748b8))},
			Shadows: []core.BoxShadow{
				ui.Shadow(0, size*0.12, size*0.36, -size*0.12, core.RGBA(0x1748b8, 0.55)),
				core.Ring(0.5, core.RGBA(0x000000, 0.08)),
			},
		},
		Children: []core.Node{
			core.Icon{SVG: lucide.ShieldCheck(), Style: core.Style{Width: core.Pt(size * 0.5), Height: core.Pt(size * 0.5), Color: core.RGB(0xffffff)}},
		},
	}
}
