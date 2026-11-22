package ui

import (
	"math"

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
		body = append(body, core.View{
			Class:    "items-center",
			Children: []core.Node{twoFactorMethodPicker(cx, m, prompt.Providers)},
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

// twoFactorMethod is how the method picker shows one method.
type twoFactorMethod struct {
	provider api.TwoFactorProvider
	id       string
	glyph    func() *core.SVG
}

func twoFactorMethodOf(p api.TwoFactorProvider) (twoFactorMethod, bool) {
	switch p {
	case api.TwoFactorAuthenticator:
		return twoFactorMethod{p, "authenticator", lucide.Smartphone}, true
	case api.TwoFactorEmail:
		return twoFactorMethod{p, "email", lucide.Mail}, true
	case api.TwoFactorYubiKey:
		return twoFactorMethod{p, "yubikey", lucide.Usb}, true
	}
	return twoFactorMethod{}, false
}

// authCardContentWidth is the width inside the sign-in card: its
// w-[380px] less px-8 on each side and the 1 pt border (authScreen).
const authCardContentWidth core.Points = 380 - 2*32 - 2*1

// ToggleButton's metrics (nsgo ui/togglebutton.go): 14 pt padding on each
// side, a 1 pt border, a 14 pt icon and a 6 pt gap before 13 pt text; a
// ToggleGroup puts 4 pt between its buttons.
const (
	toggleButtonChrome core.Points = 2*14 + 2*1 + 14 + 6
	toggleGroupGap     core.Points = 4
	toggleButtonText   core.Points = 13
)

// segmentedWidth is how wide a ToggleGroup of labels lays out.
func segmentedWidth(cx *core.Scope, labels []string) core.Points {
	var w core.Points
	for i, label := range labels {
		if i > 0 {
			w += toggleGroupGap
		}
		text := cx.MeasureText(label, core.Font{Size: toggleButtonText, Weight: ui.Regular}).Width
		w += core.Points(math.Ceil(float64(text))) + toggleButtonChrome
	}
	return w
}

// twoFactorMethodPicker chooses between the methods offered: a segmented
// control while its buttons fit the card in the current language, and a
// popup menu, full width, when they would not. Both are one keyboard stop
// that screen readers name "Verification method".
func twoFactorMethodPicker(cx *core.Scope, m *AppModel, providers []api.TwoFactorProvider) core.Node {
	var methods []twoFactorMethod
	var labels []string
	for _, p := range providers {
		if meth, ok := twoFactorMethodOf(p); ok {
			methods = append(methods, meth)
			labels = append(labels, twoFactorProviderName(cx, p))
		}
	}
	if segmentedWidth(cx, labels) <= authCardContentWidth {
		toggles := make([]core.Node, len(methods))
		for i, meth := range methods {
			toggles[i] = providerToggle(m, "twofactor-provider-"+meth.id, labels[i], meth.provider, meth.glyph)
		}
		return ui.ToggleGroup{
			TestID:   "twofactor-providers",
			Label:    locales.TwoFactorMethod(cx),
			Disabled: m.LoginBusy.Get,
			Children: toggles,
		}
	}
	options := make([]ui.Option[api.TwoFactorProvider], len(methods))
	for i, meth := range methods {
		options[i] = ui.Option[api.TwoFactorProvider]{
			Value:   meth.provider,
			Label:   labels[i],
			Leading: icon(meth.glyph(), 14, "text-gv-fg2"),
		}
	}
	return ui.Select[api.TwoFactorProvider]{
		TestID:   "twofactor-method",
		Label:    locales.TwoFactorMethod(cx),
		Options:  options,
		Value:    m.TwoFactorProvider.Get,
		OnChange: m.SelectTwoFactorProvider,
		Disabled: m.LoginBusy.Get,
		Style:    core.Style{Width: core.Pct(100), Height: core.Pt(authFieldHeight)},
	}
}

func providerToggle(m *AppModel, testID, text string, p api.TwoFactorProvider, glyph func() *core.SVG) core.Node {
	return ui.ToggleButton{
		TestID:   testID,
		Text:     text,
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
