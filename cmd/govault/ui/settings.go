package ui

import (
	"runtime"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

func SettingsView(cx *core.Scope, m *AppModel) core.Node {
	var recorderRef core.Ref

	return core.Scroll{
		TestID: "settings-view",
		Class:  "flex-1 p-6 bg-white dark:bg-neutral-950",
		Children: []core.Node{
			core.View{
				Class: "max-w-[580px] gap-6",
				Children: []core.Node{
					core.Text{
						Class:   "text-lg font-semibold text-neutral-900 dark:text-white",
						Content: "Settings",
					},
					settingsSection("Security", []core.Node{
						core.Show{
							When: m.CanUseBiometric,
							Then: func(cx *core.Scope) core.Node {
								return core.View{
									Class: "gap-3",
									Children: []core.Node{
										settingsRow(
											"Unlock with "+m.BiometricLabel(),
											"Store wrapped user key in system keychain for fast unlock.",
											ui.Switch{
												TestID:   "settings-biometric-toggle",
												Checked:  func() bool { return m.Prefs.Get().BiometricEnabled },
												OnChange: func(on bool) { m.ToggleBiometric(cx, on) },
											},
										),
										core.Show{
											When: func() bool { return m.Prefs.Get().BiometricEnabled },
											Then: func(cx *core.Scope) core.Node {
												return settingsRow(
													"Auto-prompt "+m.BiometricLabel()+" on lock screen",
													"Prompt automatically when opening the locked window.",
													ui.Switch{
														TestID:  "settings-biometric-autoprompt",
														Checked: func() bool { return m.Prefs.Get().AutoPromptBiometric },
														OnChange: func(on bool) {
															m.UpdatePrefs(func(p UserPrefs) UserPrefs {
																p.AutoPromptBiometric = on
																return p
															})
														},
													},
												)
											},
										},
									},
								}
							},
						},
						settingsRow(
							"Auto-lock timeout",
							"Lock vault automatically after inactivity.",
							ui.Select[int]{
								TestID: "settings-autolock",
								Style:  core.Style{Width: core.Pt(150)},
								Options: []ui.Option[int]{
									{Value: 1, Label: "1 minute"},
									{Value: 5, Label: "5 minutes"},
									{Value: 15, Label: "15 minutes"},
									{Value: 60, Label: "1 hour"},
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
						),
					}),
					settingsSection("Clipboard", []core.Node{
						settingsRow(
							"Clear clipboard after",
							"Automatically clear copied secrets if clipboard is unchanged.",
							ui.Select[int]{
								TestID: "settings-clipboard-clear",
								Style:  core.Style{Width: core.Pt(150)},
								Options: []ui.Option[int]{
									{Value: 15, Label: "15 seconds"},
									{Value: 30, Label: "30 seconds"},
									{Value: 60, Label: "60 seconds"},
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
							"Concealed clipboard (macOS)",
							"Marks copied secrets with org.nspasteboard.ConcealedType.",
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
					}),
					settingsSection("Quick Access & Tray", []core.Node{
						settingsRow(
							"Quick Access global shortcut",
							"Unset by default. Click Record and press a modifier + key combination.",
							core.View{
								Class: "flex-row items-center gap-2",
								Children: []core.Node{
									core.View{
										TestID:    "settings-hotkey-recorder",
										Ref:       &recorderRef,
										Focusable: func() bool { return true },
										ClassFunc: func() string {
											if m.RecordingHotKey.Get() {
												return "px-3 py-1.5 rounded-md border-2 border-blue-500 bg-blue-50 dark:bg-blue-950"
											}
											return "px-3 py-1.5 rounded-md border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900"
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
												Class:  "text-xs font-mono text-neutral-800 dark:text-neutral-200",
												ContentFunc: func() string {
													if m.RecordingHotKey.Get() {
														return "Press shortcut..."
													}
													hk := m.Prefs.Get().QuickAccessHotKey
													if hk == "" {
														return "None (Disabled)"
													}
													return cx.KeyLabel(hk)
												},
											},
										},
									},
									ui.Button{
										TestID:  "settings-hotkey-clear",
										Text:    "Clear",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
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
						),
						core.Show{
							When: func() bool { return m.Prefs.Get().QuickAccessHotKey != "" },
							Then: func(cx *core.Scope) core.Node {
								return core.Text{
									TestID: "settings-hotkey-status",
									Class:  "text-xs text-neutral-500 dark:text-neutral-400",
									ContentFunc: func() string {
										return "Shortcut status: " + m.HotKeyStatus.Get()
									},
								}
							},
						},
						settingsRow(
							"Launch at login",
							"Start GoVault in the tray when you sign in.",
							ui.Switch{
								TestID:  "settings-launch-at-login",
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
						),
						core.Show{
							When: func() bool { return runtime.GOOS == "darwin" },
							Then: func(cx *core.Scope) core.Node {
								return settingsRow(
									"Hide Dock icon (menu bar only)",
									"Keep GoVault exclusively in the macOS menu bar.",
									ui.Switch{
										TestID:  "settings-hide-dock",
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
								)
							},
						},
					}),
					settingsSection("Account & Sync", []core.Node{
						settingsMetaRow("Server", func() string { return m.Prefs.Get().ServerURL }),
						settingsMetaRow("Email", func() string { return m.Prefs.Get().Email }),
						settingsMetaRow("KDF", func() string {
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
							return ts.Local().Format("2006-01-02 15:04:05")
						}),
						core.View{
							Class: "flex-row items-center gap-2 pt-2",
							Children: []core.Node{
								ui.Button{
									TestID:  "settings-sync-now",
									Text:    "Sync Now",
									Icon:    lucide.RefreshCw,
									Variant: ui.ButtonSecondary,
									Size:    ui.SizeSmall,
									Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
									OnPress: func() { m.SyncNow(false) },
								},
								ui.Button{
									TestID:  "settings-logout",
									Text:    "Log Out",
									Icon:    lucide.LogOut,
									Variant: ui.ButtonGhost,
									Size:    ui.SizeSmall,
									OnPress: func() { m.Logout(cx) },
								},
							},
						},
					}),
				},
			},
		},
	}
}

func settingsSection(title string, children []core.Node) core.Node {
	return core.View{
		Class: "gap-3 p-4 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-900/40",
		Children: append([]core.Node{
			core.Text{
				Class:   "text-sm font-semibold text-neutral-900 dark:text-white",
				Content: title,
			},
		}, children...),
	}
}

func settingsRow(title, desc string, control core.Node) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-4 py-1",
		Children: []core.Node{
			core.View{
				Class: "flex-1 gap-0.5",
				Children: []core.Node{
					core.Text{Class: "text-sm font-medium text-neutral-800 dark:text-neutral-200", Content: title},
					core.Text{Class: "text-xs text-neutral-500 dark:text-neutral-400", Content: desc},
				},
			},
			control,
		},
	}
}

func settingsMetaRow(label string, value func() string) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between py-1 border-b border-neutral-100 dark:border-neutral-800",
		Children: []core.Node{
			core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: label},
			core.Text{Class: "text-xs text-neutral-900 dark:text-white", ContentFunc: value},
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
