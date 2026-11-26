package ui

import (
	"runtime"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
)

func SettingsView(cx *core.Scope, m *AppModel) core.Node {
	m.RefreshBiometricAvailability()
	m.RefreshBiometricProtection()
	showBio := runtime.GOOS == "darwin" || m.CanUseBiometric()
	canBio := core.NewMemo(cx, m.CanUseBiometric)
	bioOn := core.NewMemo(cx, func() bool { return m.Prefs.Get().BiometricEnabled })
	showTray := core.NewMemo(cx, func() bool { return m.Prefs.Get().ShowTrayIcon })

	return core.Scroll{
		TestID: "settings-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[620px] self-center px-7 pt-6 pb-10 gap-6",
				Children: []core.Node{
					section(locales.General(cx), card(languageRow(cx, m), appearanceRow(cx, m))),
					core.Show{
						When: func() bool { return m.QuickAccessRegistration != nil },
						Then: func(cx *core.Scope) core.Node { return quickAccessSettings(cx, m) },
					},
					section(locales.Account(cx), card(
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
									Text:    locales.SyncNow(cx),
									Icon:    lucide.RefreshCw,
									Variant: ui.ButtonSecondary,
									Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
									OnPress: func() { m.SyncNow(false) },
								},
							},
						},
						settingsMetaRow(locales.KeyDerivation(cx), func() string {
							if kdf := m.Prefs.Get().KDF; kdf != nil {
								return KDFSummary(cx, *kdf)
							}
							return locales.NotAvailable(cx)
						}),
						settingsMetaRow(locales.LastSync(cx), func() string {
							ts := m.LastSync.Get()
							if ts.IsZero() {
								return locales.NotYetSynced(cx)
							}
							return locales.LastSyncAt(cx, ts.Local())
						}),
						core.View{
							Class: "flex-row items-center justify-between pl-4 pr-1.5 py-2",
							Children: []core.Node{
								core.Text{Class: "text-[12px] text-gv-fg3", Content: locales.LogOutHint(cx)},
								core.View{
									TestID:  "settings-logout",
									Role:    core.RoleButton,
									Label:   locales.LogOut(cx),
									Class:   "flex-row items-center gap-1.5 h-[26px] px-2.5 rounded-[6px] active:bg-gv-danger/10",
									OnPress: func(core.PressEvent) { m.Logout(cx) },
									Children: []core.Node{
										icon(lucide.LogOut(), 13, "text-gv-danger"),
										core.Text{Class: "text-[12.5px] font-medium text-gv-danger", Content: locales.LogOut(cx)},
									},
								},
							},
						},
					)),
					section(locales.Security(cx), core.Dynamic(func(cx *core.Scope) core.Node {
						var rows []core.Node
						if showBio {
							rows = append(rows, biometricRows(cx, m, canBio.Get(), bioOn.Get())...)
						}
						rows = append(rows, settingsRow(
							locales.AutoLock(cx),
							locales.AutoLockDetail(cx),
							ui.Select[int]{
								TestID: "settings-autolock",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 1, Label: locales.AfterMinutes(cx, 1)},
									{Value: 5, Label: locales.AfterMinutes(cx, 5)},
									{Value: 15, Label: locales.AfterMinutes(cx, 15)},
									{Value: 60, Label: locales.AfterHours(cx, 1)},
									{Value: 0, Label: locales.Never(cx)},
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
						if m.Hooks.SleepLockSupported {
							rows = append(rows, settingsRow(
								locales.LockOnSleep(cx),
								locales.LockOnSleepDetail(cx),
								ui.Switch{
									TestID:  "settings-lock-on-sleep",
									Label:   locales.LockOnSleep(cx),
									Checked: func() bool { return m.Prefs.Get().LockOnSleep },
									OnChange: func(on bool) {
										m.UpdatePrefs(func(p UserPrefs) UserPrefs {
											p.LockOnSleep = on
											return p
										})
									},
								},
							))
						}
						return card(rows...)
					})),
					core.Show{
						When: func() bool { return m.Hooks.SSHAgent != nil },
						Then: func(cx *core.Scope) core.Node { return sshAgentSection(m) },
					},
					core.Show{
						When: func() bool { return m.Hooks.CommandLineTool != nil },
						Then: func(cx *core.Scope) core.Node { return commandLineSection(m) },
					},
					section(locales.Backup(cx), card(
						settingsRow(
							locales.ExportBackup(cx),
							locales.ExportBackupDetail(cx),
							ui.Button{
								TestID:  "settings-export",
								Text:    locales.ExportEllipsis(cx),
								Icon:    lucide.FileOutput,
								Variant: ui.ButtonSecondary,
								OnPress: m.StartExport,
							},
						),
						settingsRow(
							locales.ImportBackup(cx),
							locales.ImportBackupDetail(cx),
							ui.Button{
								TestID:   "settings-import",
								Text:     locales.ImportEllipsis(cx),
								Icon:     lucide.FileInput,
								Variant:  ui.ButtonSecondary,
								Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
								OnPress:  func() { m.StartImport(cx) },
							},
						),
					)),
					section(locales.Privacy(cx), card(
						settingsRow(
							locales.ShowWebsiteIcons(cx),
							locales.ShowWebsiteIconsDetail(cx),
							ui.Switch{
								TestID:   "settings-show-favicons",
								Label:    locales.ShowWebsiteIcons(cx),
								Checked:  func() bool { return m.Prefs.Get().FaviconsEnabled() },
								OnChange: m.SetShowFavicons,
							},
						),
						settingsRow(
							locales.IconCache(cx),
							locales.IconCacheDetail(cx),
							ui.Button{
								TestID:  "settings-clear-icon-cache",
								Text:    locales.ClearIconCache(cx),
								Variant: ui.ButtonSecondary,
								OnPress: m.ClearIconCache,
							},
						),
					)),
					section(locales.Clipboard(cx), card(
						settingsRow(
							locales.ClearCopiedSecrets(cx),
							locales.ClearCopiedSecretsDetail(cx),
							ui.Select[int]{
								TestID: "settings-clipboard-clear",
								Style:  core.Style{Width: core.Pt(172)},
								Options: []ui.Option[int]{
									{Value: 15, Label: locales.AfterSeconds(cx, 15)},
									{Value: 30, Label: locales.AfterSeconds(cx, 30)},
									{Value: 60, Label: locales.AfterSeconds(cx, 60)},
									{Value: 0, Label: locales.Never(cx)},
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
							locales.ConcealedClipboard(cx),
							locales.ConcealedClipboardDetail(cx),
							ui.Badge{
								TextFunc: func() string {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return locales.ConcealedActive(cx)
									}
									return locales.MacOSOnly(cx)
								},
								VariantFunc: func() ui.BadgeVariant {
									if m.Hooks.IsClipboardConcealed != nil && m.Hooks.IsClipboardConcealed() {
										return ui.BadgeSuccess
									}
									return ui.BadgeNeutral
								},
							},
						),
					)),
					section(trayLabel(cx), core.Dynamic(func(cx *core.Scope) core.Node {
						trayOn := showTray.Get()
						showIcon, iconDetail := locales.ShowTrayIcon(cx), locales.TrayIconDetail(cx)
						if runtime.GOOS == "darwin" {
							showIcon, iconDetail = locales.ShowMenuBarIcon(cx), locales.MenuBarIconDetail(cx)
						}
						rows := []core.Node{settingsRow(
							showIcon,
							iconDetail,
							ui.Switch{
								TestID:   "settings-show-tray",
								Label:    showIcon,
								Checked:  func() bool { return m.Prefs.Get().ShowTrayIcon },
								OnChange: m.SetShowTrayIcon,
							},
						)}
						rows = append(rows, settingsRow(
							locales.LaunchAtLogin(cx),
							locales.LaunchAtLoginDetail(cx),
							ui.Switch{
								TestID:  "settings-launch-at-login",
								Label:   locales.LaunchAtLogin(cx),
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
							desc := locales.HideDockIconDetail(cx)
							if !trayOn {
								desc = locales.HideDockIconNeedsMenuBar(cx)
							}
							rows = append(rows, settingsRow(
								locales.HideDockIcon(cx),
								desc,
								ui.Switch{
									TestID:   "settings-hide-dock",
									Label:    locales.HideDockIcon(cx),
									Disabled: func() bool { return !m.Prefs.Get().ShowTrayIcon },
									Checked:  func() bool { return m.Prefs.Get().ShowTrayIcon && m.Prefs.Get().HideDockIcon },
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
					section(locales.About(cx), card(
						settingsMetaRow(locales.AppVersion(cx, appVersionLabel(cx)), nil),
					)),
				},
			},
		},
	}
}

func sshAgentSection(m *AppModel) core.Node {
	return section(locales.SshAgent(m.Scope), core.Dynamic(func(cx *core.Scope) core.Node {
		rows := []core.Node{settingsRow(
			locales.EnableSSHAgent(cx),
			locales.EnableSSHAgentDetail(cx),
			ui.Switch{
				TestID:   "settings-ssh-agent",
				Label:    locales.EnableSSHAgent(cx),
				Checked:  func() bool { return m.Prefs.Get().SSHAgentEnabled },
				OnChange: m.SetSSHAgentEnabled,
			},
		)}
		if !m.Prefs.Get().SSHAgentEnabled {
			return card(rows...)
		}
		rows = append(rows, core.View{
			Class: "flex-row items-center gap-3 pl-4 pr-2.5 py-2.5",
			Children: []core.Node{
				core.View{
					Class: "flex-1 gap-[3px] overflow-hidden",
					Children: []core.Node{
						core.Text{Class: "text-[13px] text-gv-fg", Content: locales.Socket(cx)},
						core.Text{
							TestID:     "settings-ssh-agent-socket",
							Class:      "text-[12px] font-mono text-gv-fg2",
							Selectable: core.SelectableOn,
							Content:    m.SSHAgentSocketPath(),
						},
					},
				},
				ui.Button{
					TestID:  "settings-ssh-agent-copy",
					Text:    locales.CopySSHAuthSock(cx),
					Icon:    lucide.Copy,
					Variant: ui.ButtonSecondary,
					OnPress: m.CopySSHAuthSock,
				},
			},
		})
		if msg := m.SSHAgentError.Get(); msg != "" {
			rows = append(rows, core.View{
				Class: "flex-row items-center gap-2 px-4 py-2.5",
				Children: []core.Node{
					icon(lucide.TriangleAlert(), 13, "text-gv-warn"),
					core.Text{TestID: "settings-ssh-agent-error", Class: "flex-1 text-[12px] text-gv-fg2", Content: locales.SshAgentUnavailable(cx, msg)},
				},
			})
		}
		return card(rows...)
	}))
}

func appVersionLabel(cx *core.Scope) string {
	info := core.App()
	if info.Version == "" {
		return locales.Development(cx)
	}
	if info.Development {
		return locales.DevelopmentVersion(cx, info.Version)
	}
	return info.Version
}

func trayLabel(cx *core.Scope) string {
	if runtime.GOOS == "darwin" {
		return locales.MenuBar(cx)
	}
	return locales.Tray(cx)
}

// languageRow chooses the language GoVault shows: the system's, or one of
// Languages, each named in itself.
func languageRow(cx *core.Scope, m *AppModel) core.Node {
	opts := []ui.Option[string]{{Value: "", Label: locales.SystemDefault(cx)}}
	for _, lang := range Languages {
		opts = append(opts, ui.Option[string]{Value: lang.Tag, Label: lang.Name})
	}
	return settingsRow(
		locales.Language(cx),
		locales.LanguageDetail(cx),
		ui.Select[string]{
			TestID:   "settings-language",
			Label:    locales.Language(cx),
			Style:    core.Style{Width: core.Pt(172)},
			Options:  opts,
			Value:    func() string { return m.Prefs.Get().Language },
			OnChange: m.SetLanguage,
		},
	)
}

// appearanceRow shows GoVault light, dark, or as the system does.
func appearanceRow(cx *core.Scope, m *AppModel) core.Node {
	return settingsRow(
		locales.Appearance(cx),
		locales.AppearanceDetail(cx),
		ui.Select[string]{
			TestID: "settings-appearance",
			Label:  locales.Appearance(cx),
			Style:  core.Style{Width: core.Pt(172)},
			Options: []ui.Option[string]{
				{Value: "", Label: locales.AppearanceSystem(cx)},
				{Value: "light", Label: locales.AppearanceLight(cx)},
				{Value: "dark", Label: locales.AppearanceDark(cx)},
			},
			Value:    func() string { return m.Prefs.Get().Appearance },
			OnChange: m.SetAppearance,
		},
	)
}

func biometricRows(cx *core.Scope, m *AppModel, available, enabled bool) []core.Node {
	label := locales.UnlockWith(cx, m.BiometricLabel())
	if !available {
		label = locales.UnlockWith(cx, "Touch ID")
		return []core.Node{settingsRow(
			label,
			locales.BiometricUnavailable(cx),
			ui.Switch{
				TestID:   "settings-biometric-toggle",
				Label:    label,
				Disabled: func() bool { return true },
				Checked:  func() bool { return false },
			},
		)}
	}
	rows := []core.Node{settingsRow(
		label,
		locales.BiometricDetail(cx),
		ui.Switch{
			TestID:   "settings-biometric-toggle",
			Label:    label,
			Checked:  func() bool { return m.Prefs.Get().BiometricEnabled },
			OnChange: func(on bool) { m.ToggleBiometric(cx, on) },
		},
	)}
	if enabled && runtime.GOOS == "darwin" {
		rows = append(rows, core.View{
			Class: "flex-row items-center gap-2 px-4 py-2.5",
			Children: []core.Node{
				iconFunc(func() *core.SVG {
					if m.BiometricHardware.Get() {
						return lucide.ShieldCheck()
					}
					return lucide.KeyRound()
				}, 13, func() string { return "text-gv-fg3" }),
				core.Text{
					TestID: "settings-biometric-protection",
					Class:  "flex-1 text-[12px] text-gv-fg2",
					ContentFunc: func() string {
						if m.BiometricHardware.Get() {
							return locales.BiometricHardware(cx)
						}
						return locales.BiometricAppGated(cx, m.BiometricLabel())
					},
				},
			},
		})
	}
	if enabled {
		rows = append(rows, settingsRow(
			locales.PromptAutomatically(cx),
			locales.PromptAutomaticallyDetail(cx, m.BiometricLabel()),
			ui.Switch{
				TestID:  "settings-biometric-autoprompt",
				Label:   locales.PromptAutomatically(cx),
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
	return rows
}

func settingsRow(title, desc string, control core.Node) core.Node {
	return optionRow(title, desc, control)
}

func settingsMetaRow(label string, value func() string) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between gap-4 px-4 py-2.5",
		Children: []core.Node{
			core.Text{Class: "text-[13px] text-gv-fg", Content: label},
			core.Text{MaxLines: 1, Class: "shrink text-[12.5px] text-gv-fg2 text-right", ContentFunc: value},
		},
	}
}
