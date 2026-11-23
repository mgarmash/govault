package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
)

// NewDeviceView asks for the code Bitwarden emails when a password login
// comes from a device it does not recognize, for an account without
// two-step login. The server sent the first code with its refusal, so the
// step offers only Resend Code. The code field is not masked, as for an
// emailed two-step code.
func NewDeviceView(cx *core.Scope, m *AppModel, prompt *NewDevicePrompt) core.Node {
	busy := m.LoginBusy.Get
	body := []core.Node{
		core.View{
			Class: "items-center gap-2.5 pb-1",
			Children: []core.Node{
				codeEmblem(lucide.MailCheck),
				core.Text{Class: "mt-1.5 text-[19px] font-semibold text-gv-fg", Content: locales.NewDeviceTitle(cx)},
				core.Text{
					Class:   "text-[12.5px] text-gv-fg2 text-center",
					Content: locales.NewDeviceEnterCodeTo(cx, prompt.Email),
				},
			},
		},
		core.View{
			Class: "gap-3",
			Children: []core.Node{
				formField(locales.VerificationCode(cx), authInput(base.Input{
					TestID:         "newdevice-code",
					Class:          "font-mono",
					Placeholder:    "123456",
					NoAutoCorrect:  true,
					AutoCapitalize: core.AutoCapitalizeNone,
					AutoFocus:      true,
					MaxLength:      12,
					Value:          m.TwoFactorCode.Get,
					OnChange:       m.TwoFactorCode.Set,
					OnSubmit:       func(string) { m.VerifyNewDevice() },
					Disabled:       busy,
					Style:          core.Style{FontSize: 15, LetterSpacing: 2},
				})),
				core.View{
					Class: "flex-row items-center justify-between gap-2",
					Children: []core.Node{
						core.Text{
							Class:       "flex-1 text-[11.5px] text-gv-fg2",
							ContentFunc: m.TwoFactorNotice.Get,
						},
						ui.Button{
							TestID:   "newdevice-resend",
							Text:     locales.ResendCode(cx),
							Variant:  ui.ButtonOutline,
							Icon:     lucide.Send,
							Busy:     m.TwoFactorSending.Get,
							Disabled: busy,
							OnPress:  m.ResendNewDeviceCode,
						},
					},
				},
			},
		},
		core.Show{
			When: func() bool { return m.LoginError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("newdevice-error", m.LoginError.Get) },
		},
		core.View{
			Class: "gap-2",
			Children: []core.Node{
				ui.Button{
					TestID:  "newdevice-verify",
					Text:    locales.Verify(cx),
					Variant: ui.ButtonPrimary,
					Size:    ui.SizeLarge,
					Busy:    busy,
					Style:   core.Style{Width: core.Pct(100)},
					OnPress: m.VerifyNewDevice,
				},
				ui.Button{
					TestID:   "newdevice-back",
					Text:     locales.BackToSignIn(cx),
					Variant:  ui.ButtonGhost,
					Disabled: busy,
					Style:    core.Style{Width: core.Pct(100)},
					OnPress:  m.CancelNewDevice,
				},
			},
		},
	}
	return authScreen("newdevice-screen", body, locales.NewDeviceFootnote(cx))
}
