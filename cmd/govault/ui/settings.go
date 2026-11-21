package ui

import (
	"runtime"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/nsgo-dev/nsgo/updater"
)

func SettingsView(cx *core.Scope, m *AppModel) core.Node {
	var recorderRef core.Ref
	canBio := core.NewMemo(cx, m.CanUseBiometric)
	bioOn := core.NewMemo(cx, func() bool { return m.Prefs.Get().BiometricEnabled })
	hasHotKey := core.NewMemo(cx, func() bool { return m.Prefs.Get().QuickAccessHotKey != "" })

	return core.Scroll{
		TestID: "settings-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[620px] self-center px-7 pt-6 pb-10 gap-6",
				Children: []core.Node{
					section("Account", card(
						core.View{
							Class: "flex-row items-center gap-3 px-4 py-3.5",
							Children: []core.Node{
								avatar(func() string { return m.Prefs.Get().Email }, 40),
								core.View{
									Class: "flex-1 gap-[2px] overflow-hidden",
									Children: []core.Node{
										core.Text{MaxLines: 1, Class: "text-[14px] font-semibold text-gv-fg", ContentFunc: func() string { return m.Prefs.Get().Email }},
										core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2", ContentFunc: func() string { return m.Prefs.Get().ServerURL }},
									},
								},
								ui.Button{
									TestID:  "settings-sync-now",
									Text:    "Sync Now",
									Icon:    lucide.RefreshCw,
									Variant: ui.ButtonSecondary,
									Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
									OnPress: func() { m.SyncNow(false) },
								},
							},
						},
						settingsMetaRow("Key derivation", func() string {
							if s := m.Prefs.Get().KDFSummary; s != "" {
								return s
							}
							return "—"
						}),
						settingsMetaRow("Last sync", func() string {
							ts := m.LastSync.Get()
							if ts.IsZero() {
								return "Not yet synced"
							}
							return ts.Local().Format("Jan 2, 2006 at 3:04 PM")
						}),
						core.View{
							Class: "flex-row items-center justify-between pl-4 pr-1.5 py-2",
							Children: []core.Node{
								core.Text{Class: "text-[12px] text-gv-fg3", Content: "Logging out removes the local vault cache."},
								core.View{
									TestID:  "settings-logout",
									Role:    core.RoleButton,
									Label:   "Log Out",
									Class:   "flex-row items-center gap-1.5 h-[26px] px-2.5 rounded-[6px] active:bg-gv-danger/10",
									OnPress: func(core.PressEvent) { m.Logout(cx) },
									Children: []core.Node{
										icon(lucide.LogOut(), 13, "text-gv-danger"),
										core.Text{Class: "text-[12.5px] font-medium text-gv-danger", Content: "Log Out"},
									},
								},
							},
						},
					)),
					section("Security", core.Dynamic(func(cx *core.Scope) core.Node {
						var rows []core.Node
						if canBio.Get() {
							rows = append(rows, settingsRow(
								"Unlock with "+m.BiometricLabel(),
								"Keeps a wrapped key in the system keychain for fast unlock.",
								ui.Switch{
									TestID:   "settings-biometric-toggle",
									Label:    "Unlock with " + m.BiometricLabel(),
									Checked:  func() bool { return m.Prefs.Get().BiometricEnabled },
									OnChange: func(on bool) { m.ToggleBiometric(cx, on) },
								},
							))
							if bioOn.Get() {
								rows = append(rows, settingsRow(
									"Prompt automatically",
									"Ask for "+m.BiometricLabel()+" as soon as the locked window opens.",
									ui.Switch{
										TestID:  "settings-biometric-autoprompt",
										Label:   "Prompt automatically",
										Checked: func() bool { return m.Prefs.Get().AutoPromptBiometric },
										OnChange: func(on bool) {
											m.UpdatePrefs(func(p UserPrefs) UserPrefs {
												p.AutoPromptBiometric = on
												return p
											})
										},
									},
								))
							}
						}
						rows = append(rows, settingsRow(
							"Auto-lock",
							"Lock the vault after a period of inactivity.",
							ui.Select[int]{
								TestID: "settings-autolock",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 1, Label: "After 1 minute"},
									{Value: 5, Label: "After 5 minutes"},
									{Value: 15, Label: "After 15 minutes"},
									{Value: 60, Label: "After 1 hour"},
									{Value: 0, Label: "Never"},
								},
								Value: func() int { return m.Prefs.Get().AutoLockMinutes },
								OnChange: func(mins int) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.AutoLockMinutes = mins
										return p
									})
									m.ResetIdleTimer()
								},
							},
						))
						return card(rows...)
					})),
					section("Clipboard", card(
						settingsRow(
							"Clear copied secrets",
							"Clears the clipboard if it still holds the copied value.",
							ui.Select[int]{
								TestID: "settings-clipboard-clear",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 15, Label: "After 15 seconds"},
									{Value: 30, Label: "After 30 seconds"},
									{Value: 60, Label: "After 60 seconds"},
									{Value: 0, Label: "Never"},
								},
								Value: func() int { return m.Prefs.Get().ClipboardClearSeconds },
								OnChange: func(secs int) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.ClipboardClearSeconds = secs
										return p
									})
								},
							},
						),
						settingsRow(
							"Concealed clipboard",
							"Marks secrets so clipboard managers skip them.",
							ui.Badge{
								TextFunc: func() string {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return "Active"
									}
									return "macOS only"
								},
								VariantFunc: func() ui.BadgeVariant {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return ui.BadgeUp
									}
									return ui.BadgeNeutral
								},
							},
						),
					)),
					section("Quick Access", core.Dynamic(func(cx *core.Scope) core.Node {
						rows := []core.Node{settingsRow(
							"Global shortcut",
							"Opens the quick search panel from any app.",
							core.View{
								Class: "flex-row items-center gap-1.5",
								Children: []core.Node{
									core.View{
										TestID:    "settings-hotkey-recorder",
										Ref:       &recorderRef,
										Role:      core.RoleButton,
										Label:     "Record shortcut",
										Focusable: func() bool { return true },
										ClassFunc: func() string {
											if m.RecordingHotKey.Get() {
												return "min-w-[120px] h-[28px] px-3 rounded-[7px] items-center justify-center border border-gv-accent bg-gv-accent-soft"
											}
											return "min-w-[120px] h-[28px] px-3 rounded-[7px] items-center justify-center border border-gv-line bg-gv-fill"
										},
										OnPress: func(core.PressEvent) {
											m.RecordingHotKey.Set(true)
											recorderRef.Focus()
										},
										OnBlur: func() {
											m.RecordingHotKey.Set(false)
										},
										OnKeyDown: func(ev core.KeyEvent) bool {
											if !m.RecordingHotKey.Get() {
												return false
											}
											if ev.Key == "escape" {
												m.RecordingHotKey.Set(false)
												return true
											}
											if isModifierOnlyKey(ev.Key) {
												return true
											}
											shortcut := ev.Shortcut()
											if !strings.Contains(shortcut, "+") {
												return true
											}
											m.RecordingHotKey.Set(false)
											m.SetQuickAccessHotKey(shortcut)
											return true
										},
										Children: []core.Node{
											core.Text{
												TestID: "settings-hotkey-value",
												ClassFunc: func() string {
													if m.RecordingHotKey.Get() {
														return "text-[12px] font-medium text-gv-accent"
													}
													if m.Prefs.Get().QuickAccessHotKey == "" {
														return "text-[12px] text-gv-fg3"
													}
													return "text-[12.5px] font-semibold text-gv-fg tracking-[1px]"
												},
												ContentFunc: func() string {
													if m.RecordingHotKey.Get() {
														return "Type shortcut…"
													}
													hk := m.Prefs.Get().QuickAccessHotKey
													if hk == "" {
														return "Click to record"
													}
													return cx.KeyLabel(hk)
												},
											},
										},
									},
									ui.Button{
										TestID:   "settings-hotkey-clear",
										Icon:     lucide.X,
										Label:    "Clear shortcut",
										Variant:  ui.ButtonGhost,
										Side:     24,
										IconSize: 12,
										Tint:     func() core.Color { return themeColor(cx, "gv-fg3") },
										Disabled: func() bool {
											return m.Prefs.Get().QuickAccessHotKey == "" && !m.RecordingHotKey.Get()
										},
										OnPress: func() {
											m.RecordingHotKey.Set(false)
											m.SetQuickAccessHotKey("")
										},
									},
								},
							},
						)}
						if hasHotKey.Get() {
							rows = append(rows, core.View{
								Class: "flex-row items-center gap-1.5 px-4 py-2",
								Children: []core.Node{
									core.View{ClassFunc: func() string {
										if m.HotKeyStatus.Get() == "Active" {
											return "w-[6px] h-[6px] rounded-full bg-gv-success"
										}
										return "w-[6px] h-[6px] rounded-full bg-gv-warn"
									}},
									core.Text{
										TestID: "settings-hotkey-status",
										Class:  "text-[11.5px] text-gv-fg2",
										ContentFunc: func() string {
											return "Shortcut status: " + m.HotKeyStatus.Get()
										},
									},
								},
							})
						}
						rows = append(rows, settingsRow(
							"Launch at login",
							"Start GoVault in the menu bar when you sign in.",
							ui.Switch{
								TestID:  "settings-launch-at-login",
								Label:   "Launch at login",
								Checked: func() bool { return m.Prefs.Get().LaunchAtLogin },
								OnChange: func(on bool) {
									m.UpdatePrefs(func(p UserPrefs) UserPrefs {
										p.LaunchAtLogin = on
										return p
									})
									if m.Hooks.SetLaunchAtLogin != nil {
										m.Hooks.SetLaunchAtLogin(on)
									}
								},
							},
						))
						if runtime.GOOS == "darwin" {
							rows = append(rows, settingsRow(
								"Hide Dock icon",
								"Keep GoVault in the menu bar only.",
								ui.Switch{
									TestID:  "settings-hide-dock",
									Label:   "Hide Dock icon",
									Checked: func() bool { return m.Prefs.Get().HideDockIcon },
									OnChange: func(on bool) {
										m.UpdatePrefs(func(p UserPrefs) UserPrefs {
											p.HideDockIcon = on
											return p
										})
										if m.Hooks.SetDockVisible != nil {
											m.Hooks.SetDockVisible(!on)
										}
									},
								},
							))
						}
						return card(rows...)
					})),
					section("About", card(
						settingsRow(
							"GoVault "+appVersionLabel(),
							"Updates are signed and installed automatically.",
							ui.Button{
								TestID:  "settings-check-updates",
								Text:    "Check for Updates",
								Icon:    lucide.RefreshCw,
								Variant: ui.ButtonSecondary,
								OnPress: func() { updater.Check(cx) },
							},
						),
					)),
				},
			},
		},
	}
}

func appVersionLabel() string {
	info := core.App()
	if info.Version == "" {
		return "(development)"
	}
	if info.Development {
		return info.Version + " (development)"
	}
	return info.Version
}

func settingsRow(title, desc string, control core.Node) core.Node {
	return optionRow(title, desc, control)
}

func settingsMetaRow(label string, value func() string) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-4 px-4 py-2.5",
		Children: []core.Node{
			core.Text{Class: "text-[13px] text-gv-fg", Content: label},
			core.Text{MaxLines: 1, Class: "flex-shrink text-[12.5px] text-gv-fg2 text-right", ContentFunc: value},
		},
	}
}

func isModifierOnlyKey(key string) bool {
	switch strings.ToLower(key) {
	case "shift", "ctrl", "control", "alt", "option", "meta", "command", "super":
		return true
	default:
		return false
	}
}
