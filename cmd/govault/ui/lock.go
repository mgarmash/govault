package ui

import (
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
)

func LockView(cx *core.Scope, m *AppModel) core.Node {
	cx.Effect(func() {
		if m.MainWinVisible.Get() && !m.LockAutoFired && m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled && m.Prefs.Get().AutoPromptBiometric {
			m.LockAutoFired = true
			m.UnlockWithBiometric(cx)
		}
	})
	biometric := func() bool { return m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled }

	passwordInput := func(trailing ...core.Node) core.Node {
		return passwordField(cx, base.Input{
			TestID:        "lock-password",
			Ref:           &m.LockPasswordRef,
			Placeholder:   locales.MasterPasswordPlaceholder(cx),
			AutoFocus:     !biometric(),
			NoAutoCorrect: true,
			Value:         m.LockPassword.Get,
			OnChange:      m.LockPassword.Set,
			OnSubmit:      func(string) { m.UnlockWithPassword() },
			Disabled:      m.LockBusy.Get,
		}, authFieldHeight, m.LockShowPW, "lock-toggle-pw", trailing...)
	}

	return authScreen("lock-screen", []core.Node{
		core.View{
			Class: "items-center gap-1 pb-1",
			Children: []core.Node{
				core.View{
					Class: "relative mb-2.5",
					Children: []core.Node{
						avatar(func() string { return m.Prefs.Get().Email }, 64),
						core.View{
							Class: "absolute -right-1 -bottom-1 w-[26px] h-[26px] rounded-full items-center justify-center bg-gv-accent border-[2.5px] border-gv-card",
							Children: []core.Node{
								icon(lucide.Lock(), 12, "text-white"),
							},
						},
					},
				},
				core.Text{Class: "text-[18px] font-semibold text-gv-fg", Content: locales.LockedTitle(cx)},
				core.Text{
					MaxLines:    1,
					Class:       "text-[13px] text-gv-fg2",
					ContentFunc: func() string { return m.Prefs.Get().Email },
				},
				core.Text{
					MaxLines:    1,
					Class:       "text-[11.5px] text-gv-fg3",
					ContentFunc: func() string { return m.Prefs.Get().ServerURL },
				},
			},
		},
		core.Show{
			When: biometric,
			Then: func(cx *core.Scope) core.Node {
				return core.View{
					Class: "gap-4",
					Children: []core.Node{
						ui.Button{
							TestID:  "lock-biometric",
							Text:    locales.UnlockWith(cx, m.BiometricLabel()),
							Icon:    lucide.FingerprintPattern,
							Variant: ui.ButtonPrimary,
							Size:    ui.SizeLarge,
							Busy:    m.LockBusy.Get,
							Style:   core.Style{Width: core.Pct(100)},
							OnPress: func() { m.UnlockWithBiometric(cx) },
						},
						core.View{
							Class: "flex-row items-center gap-2.5",
							Children: []core.Node{
								core.View{Class: "flex-1 h-px bg-gv-line"},
								core.Text{Class: "text-[11px] text-gv-fg3", Content: locales.OrUseMasterPassword(cx)},
								core.View{Class: "flex-1 h-px bg-gv-line"},
							},
						},
						passwordInput(ui.Button{
							TestID:   "lock-submit",
							Icon:     lucide.ArrowRight,
							Label:    locales.Unlock(cx),
							Variant:  ui.ButtonPrimary,
							Side:     authFieldHeight - 10,
							IconSize: 13,
							Busy:     m.LockBusy.Get,
							Style:    core.Style{CornerRadius: (authFieldHeight - 10) / 2},
							OnPress:  func() { m.UnlockWithPassword() },
						}),
					},
				}
			},
			Else: func(cx *core.Scope) core.Node {
				return core.View{
					Class: "gap-4",
					Children: []core.Node{
						formField(locales.MasterPassword(cx), passwordInput()),
						ui.Button{
							TestID:  "lock-submit",
							Text:    locales.Unlock(cx),
							Variant: ui.ButtonPrimary,
							Size:    ui.SizeLarge,
							Busy:    m.LockBusy.Get,
							Style:   core.Style{Width: core.Pct(100)},
							OnPress: func() { m.UnlockWithPassword() },
						},
					},
				}
			},
		},
		core.Show{
			When: func() bool { return m.LockError.Get() != "" },
			Then: func(cx *core.Scope) core.Node { return errorBanner("lock-error", m.LockError.Get) },
		},
		core.View{
			Class: "items-center",
			Children: []core.Node{
				core.View{
					TestID:  "lock-logout",
					Role:    core.RoleButton,
					Label:   locales.LogOutOrSwitchAccountLabel(cx),
					Class:   "h-[24px] px-2 rounded-[6px] justify-center active:bg-gv-fill",
					OnPress: func(core.PressEvent) { m.Logout(cx) },
					Children: []core.Node{
						core.Text{Class: "text-[12px] font-medium text-gv-fg2", Content: locales.LogOutOrSwitchAccount(cx)},
					},
				},
			},
		},
	}, locales.LockFootnote(cx))
}
