package ui

import (
	"fmt"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

func GeneratorView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "generator-view",
		Class:  "flex-1 p-6 bg-white dark:bg-neutral-950",
		Children: []core.Node{
			core.View{
				Class: "max-w-[540px] gap-5",
				Children: []core.Node{
					core.Text{
						Class:   "text-lg font-semibold text-neutral-900 dark:text-white",
						Content: "Password & Passphrase Generator",
					},
					core.View{
						Class: "p-4 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 gap-3",
						Children: []core.Node{
							core.Text{
								TestID:      "generator-output",
								Class:       "text-base font-mono font-medium text-neutral-900 dark:text-white",
								Selectable:  core.SelectableOn,
								ContentFunc: m.GenResult.Get,
							},
							core.View{
								Class: "flex-row gap-2",
								Children: []core.Node{
									ui.Button{
										TestID:  "generator-copy",
										Text:    "Copy",
										Icon:    lucide.Copy,
										Variant: ui.ButtonPrimary,
										Size:    ui.SizeSmall,
										OnPress: func() { m.CopySecretValue("Generated secret", m.GenResult.Get()) },
									},
									ui.Button{
										TestID:  "generator-regenerate",
										Text:    "Regenerate",
										Icon:    lucide.RefreshCw,
										Variant: ui.ButtonSecondary,
										Size:    ui.SizeSmall,
										OnPress: m.RegenerateSecret,
									},
								},
							},
						},
					},
					ui.Tabs[string]{
						TestID: "generator-mode-tabs",
						Equal:  true,
						Options: []ui.Option[string]{
							{Value: "password", Label: "Password"},
							{Value: "passphrase", Label: "Passphrase"},
						},
						Value: func() string {
							mode := m.Prefs.Get().GeneratorMode
							if mode == "passphrase" {
								return "passphrase"
							}
							return "password"
						},
						OnChange: func(mode string) {
							m.UpdatePrefs(func(p UserPrefs) UserPrefs {
								p.GeneratorMode = mode
								return p
							})
							m.RegenerateSecret()
						},
					},
					core.Show{
						When: func() bool { return m.Prefs.Get().GeneratorMode == "passphrase" },
						Then: func(cx *core.Scope) core.Node { return passphraseOptionsView(m) },
						Else: func(cx *core.Scope) core.Node { return passwordOptionsView(m) },
					},
				},
			},
		},
	}
}

func passwordOptionsView(m *AppModel) core.Node {
	adjustLength := func(delta int) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			n := p.PasswordOpts.Length + delta
			if n < 8 {
				n = 8
			}
			if n > 128 {
				n = 128
			}
			p.PasswordOpts.Length = n
			return p
		})
		m.RegenerateSecret()
	}

	return core.View{
		Class: "gap-3 p-4 rounded-xl border border-neutral-200 dark:border-neutral-800",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center justify-between",
				Children: []core.Node{
					core.Text{
						Class: "text-sm font-medium text-neutral-800 dark:text-neutral-200",
						ContentFunc: func() string {
							return fmt.Sprintf("Length: %d", m.Prefs.Get().PasswordOpts.Length)
						},
					},
					core.View{
						Class: "flex-row items-center gap-1.5",
						Children: []core.Node{
							ui.Button{Text: "-4", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustLength(-4) }},
							ui.Button{Text: "-1", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustLength(-1) }},
							ui.Button{Text: "+1", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustLength(1) }},
							ui.Button{Text: "+4", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustLength(4) }},
						},
					},
				},
			},
			ui.Checkbox{
				Text:    "Uppercase (A-Z)",
				Checked: func() bool { return m.Prefs.Get().PasswordOpts.Uppercase },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PasswordOpts.Uppercase = v; return p })
					m.RegenerateSecret()
				},
			},
			ui.Checkbox{
				Text:    "Lowercase (a-z)",
				Checked: func() bool { return m.Prefs.Get().PasswordOpts.Lowercase },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PasswordOpts.Lowercase = v; return p })
					m.RegenerateSecret()
				},
			},
			ui.Checkbox{
				Text:    "Numbers (0-9)",
				Checked: func() bool { return m.Prefs.Get().PasswordOpts.Numbers },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs {
						p.PasswordOpts.Numbers = v
						if !v {
							p.PasswordOpts.MinNumbers = 0
						} else if p.PasswordOpts.MinNumbers == 0 {
							p.PasswordOpts.MinNumbers = 1
						}
						return p
					})
					m.RegenerateSecret()
				},
			},
			ui.Checkbox{
				Text:    "Special characters (!@#$%^&*)",
				Checked: func() bool { return m.Prefs.Get().PasswordOpts.Special },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs {
						p.PasswordOpts.Special = v
						if !v {
							p.PasswordOpts.MinSpecial = 0
						} else if p.PasswordOpts.MinSpecial == 0 {
							p.PasswordOpts.MinSpecial = 1
						}
						return p
					})
					m.RegenerateSecret()
				},
			},
			ui.Checkbox{
				Text:    "Avoid ambiguous characters (l, 1, I, O, 0)",
				Checked: func() bool { return m.Prefs.Get().PasswordOpts.AvoidAmbiguous },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PasswordOpts.AvoidAmbiguous = v; return p })
					m.RegenerateSecret()
				},
			},
		},
	}
}

func passphraseOptionsView(m *AppModel) core.Node {
	adjustWords := func(delta int) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			n := p.PassphraseOpts.NumWords + delta
			if n < 3 {
				n = 3
			}
			if n > 12 {
				n = 12
			}
			p.PassphraseOpts.NumWords = n
			return p
		})
		m.RegenerateSecret()
	}

	return core.View{
		Class: "gap-3 p-4 rounded-xl border border-neutral-200 dark:border-neutral-800",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center justify-between",
				Children: []core.Node{
					core.Text{
						Class: "text-sm font-medium text-neutral-800 dark:text-neutral-200",
						ContentFunc: func() string {
							return fmt.Sprintf("Words: %d", m.Prefs.Get().PassphraseOpts.NumWords)
						},
					},
					core.View{
						Class: "flex-row items-center gap-1.5",
						Children: []core.Node{
							ui.Button{Text: "-1", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustWords(-1) }},
							ui.Button{Text: "+1", Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: func() { adjustWords(1) }},
						},
					},
				},
			},
			labeledField("Word Separator", base.Input{
				Class:       inputClass,
				Placeholder: "-",
				Value:       func() string { return m.Prefs.Get().PassphraseOpts.Separator },
				OnChange: func(v string) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.Separator = v; return p })
					m.RegenerateSecret()
				},
			}),
			ui.Checkbox{
				Text:    "Capitalize words",
				Checked: func() bool { return m.Prefs.Get().PassphraseOpts.Capitalize },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.Capitalize = v; return p })
					m.RegenerateSecret()
				},
			},
			ui.Checkbox{
				Text:    "Include number",
				Checked: func() bool { return m.Prefs.Get().PassphraseOpts.IncludeNum },
				OnChange: func(v bool) {
					m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.IncludeNum = v; return p })
					m.RegenerateSecret()
				},
			},
		},
	}
}
