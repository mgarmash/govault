package ui

import (
	"fmt"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"math"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
)

func GeneratorView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "generator-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.View{
				Class: "w-full max-w-[600px] self-center px-7 pt-6 pb-10 gap-5",
				Children: []core.Node{
					generatorOutput(cx, m),
					ui.Tabs[string]{
						TestID: "generator-mode-tabs",
						Equal:  true,
						Options: []ui.Option[string]{
							{Value: "password", Label: locales.PasswordMode(cx)},
							{Value: "passphrase", Label: locales.PassphraseMode(cx)},
						},
						Value: func() string {
							if m.Prefs.Get().GeneratorMode == "passphrase" {
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

type strength struct {
	bits  float64
	level int
}

func (s strength) label(cx *core.Scope) string {
	switch s.level {
	case 1:
		return locales.StrengthWeak(cx)
	case 2:
		return locales.StrengthFair(cx)
	case 3:
		return locales.StrengthStrong(cx)
	}
	return locales.StrengthVeryStrong(cx)
}

func (m *AppModel) generatorStrength() strength {
	p := m.Prefs.Get()
	var bits float64
	if p.GeneratorMode == "passphrase" {
		bits = gen.PassphraseBits(p.PassphraseOpts)
	} else {
		pool := 0
		o := p.PasswordOpts
		if o.Uppercase {
			pool += 26
		}
		if o.Lowercase {
			pool += 26
		}
		if o.Numbers {
			pool += 10
		}
		if o.Special {
			pool += 8
		}
		if o.AvoidAmbiguous && pool > 5 {
			pool -= 5
		}
		if pool > 1 {
			bits = float64(o.Length) * math.Log2(float64(pool))
		}
	}
	switch {
	case bits < 45:
		return strength{bits, 1}
	case bits < 64:
		return strength{bits, 2}
	case bits < 90:
		return strength{bits, 3}
	default:
		return strength{bits, 4}
	}
}

func generatorOutput(cx *core.Scope, m *AppModel) core.Node {
	levelColor := func(level int) string {
		switch level {
		case 1:
			return "bg-gv-danger"
		case 2:
			return "bg-gv-warn"
		default:
			return "bg-gv-success"
		}
	}
	segments := make([]core.Node, 4)
	for i := range segments {
		idx := i + 1
		segments[i] = core.View{
			ClassFunc: func() string {
				s := m.generatorStrength()
				if idx <= s.level {
					return "flex-1 h-[4px] rounded-full " + levelColor(s.level)
				}
				return "flex-1 h-[4px] rounded-full bg-gv-fill-strong"
			},
		}
	}
	return card(core.View{
		Class: "px-6 pt-7 pb-5 gap-5",
		Children: []core.Node{
			core.View{
				Class: "min-h-[56px] items-center justify-center",
				Children: []core.Node{
					core.Text{
						TestID:     "generator-output",
						Class:      "text-[20px] font-mono font-medium text-gv-fg text-center leading-[28px]",
						Selectable: core.SelectableOn,
						SpansFunc:  func() []core.Span { return passwordSpans(m.GenResult.Get()) },
					},
				},
			},
			core.View{
				Class: "gap-2",
				Children: []core.Node{
					core.View{Class: "flex-row gap-1", Children: segments},
					core.View{
						Class: "flex-row items-center justify-between",
						Children: []core.Node{
							core.Text{
								Class:       "text-[12px] font-semibold text-gv-fg",
								ContentFunc: func() string { return m.generatorStrength().label(cx) },
							},
							core.Text{
								Class: "text-[11.5px] text-gv-fg3 tabular-nums",
								ContentFunc: func() string {
									return locales.EntropyBits(cx, int(math.Round(m.generatorStrength().bits)))
								},
							},
						},
					},
				},
			},
			core.View{
				Class: "flex-row gap-2",
				Children: []core.Node{
					ui.Button{
						TestID:  "generator-regenerate",
						Text:    locales.Regenerate(cx),
						Icon:    lucide.RefreshCw,
						Variant: ui.ButtonSecondary,
						Flex:    1,
						OnPress: m.RegenerateSecret,
					},
					ui.Button{
						TestID:  "generator-copy",
						Text:    locales.Copy(cx),
						Icon:    lucide.Copy,
						Variant: ui.ButtonPrimary,
						Flex:    1,
						OnPress: func() { m.CopySecretValue(locales.GeneratedCopied(cx), m.GenResult.Get()) },
					},
				},
			},
		},
	})
}

func optionRow(title, desc string, control core.Node) core.Node {
	text := []core.Node{core.Text{Class: "text-[13px] text-gv-fg", Content: title}}
	if desc != "" {
		text = append(text, core.Text{Class: "text-[11.5px] text-gv-fg3", Content: desc})
	}
	return core.View{
		Class: "flex-row items-center gap-4 px-4 py-2.5 min-h-[46px]",
		Children: []core.Node{
			core.View{Class: "flex-1 gap-[2px]", Children: text},
			control,
		},
	}
}

func sliderRow(title string, value func() int, lo, hi int, onChange func(int)) core.Node {
	return core.View{
		Class: "flex-row items-center gap-4 px-4 py-3 min-h-[50px]",
		Children: []core.Node{
			core.Text{Class: "min-w-[70px] max-w-[160px] text-[13px] text-gv-fg", Content: title},
			ui.Slider{
				Label: title,
				Min:   float64(lo),
				Max:   float64(hi),
				Step:  1,
				Value: func() float64 { return float64(value()) },
				OnChange: func(v float64) {
					if n := int(math.Round(v)); n != value() {
						onChange(n)
					}
				},
				Style: core.Style{FlexGrow: 1, FlexShrink: 1},
			},
			core.View{
				Class: "w-[40px] h-[24px] rounded-[6px] items-center justify-center bg-gv-fill",
				Children: []core.Node{
					core.Text{
						Class:       "text-[12.5px] font-semibold text-gv-fg tabular-nums",
						ContentFunc: func() string { return fmt.Sprintf("%d", value()) },
					},
				},
			},
		},
	}
}

func passwordOptionsView(m *AppModel) core.Node {
	cx := m.Scope
	toggle := func(testID, title, desc string, get func(p UserPrefs) bool, set func(p *UserPrefs, v bool)) core.Node {
		return optionRow(title, desc, ui.Switch{
			TestID:  testID,
			Label:   title,
			Checked: func() bool { return get(m.Prefs.Get()) },
			OnChange: func(v bool) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { set(&p, v); return p })
				m.RegenerateSecret()
			},
		})
	}
	return core.View{
		Class: "gap-4",
		Children: []core.Node{
			card(sliderRow(locales.Length(cx), func() int { return m.Prefs.Get().PasswordOpts.Length }, 8, 128, func(n int) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PasswordOpts.Length = n; return p })
				m.RegenerateSecret()
			})),
			section(locales.Characters(cx), card(
				toggle("generator-upper", locales.Uppercase(cx), "A–Z", func(p UserPrefs) bool { return p.PasswordOpts.Uppercase }, func(p *UserPrefs, v bool) { p.PasswordOpts.Uppercase = v }),
				toggle("generator-lower", locales.Lowercase(cx), "a–z", func(p UserPrefs) bool { return p.PasswordOpts.Lowercase }, func(p *UserPrefs, v bool) { p.PasswordOpts.Lowercase = v }),
				toggle("generator-numbers", locales.Numbers(cx), "0–9", func(p UserPrefs) bool { return p.PasswordOpts.Numbers }, func(p *UserPrefs, v bool) {
					p.PasswordOpts.Numbers = v
					if !v {
						p.PasswordOpts.MinNumbers = 0
					} else if p.PasswordOpts.MinNumbers == 0 {
						p.PasswordOpts.MinNumbers = 1
					}
				}),
				toggle("generator-special", locales.Symbols(cx), "! @ # $ % ^ & *", func(p UserPrefs) bool { return p.PasswordOpts.Special }, func(p *UserPrefs, v bool) {
					p.PasswordOpts.Special = v
					if !v {
						p.PasswordOpts.MinSpecial = 0
					} else if p.PasswordOpts.MinSpecial == 0 {
						p.PasswordOpts.MinSpecial = 1
					}
				}),
				toggle("generator-ambiguous", locales.AvoidAmbiguous(cx), locales.AvoidAmbiguousDetail(cx), func(p UserPrefs) bool { return p.PasswordOpts.AvoidAmbiguous }, func(p *UserPrefs, v bool) { p.PasswordOpts.AvoidAmbiguous = v }),
			)),
		},
	}
}

func passphraseOptionsView(m *AppModel) core.Node {
	cx := m.Scope
	toggle := func(title, desc string, get func(p UserPrefs) bool, set func(p *UserPrefs, v bool)) core.Node {
		return optionRow(title, desc, ui.Switch{
			Label:   title,
			Checked: func() bool { return get(m.Prefs.Get()) },
			OnChange: func(v bool) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { set(&p, v); return p })
				m.RegenerateSecret()
			},
		})
	}
	return core.View{
		Class: "gap-4",
		Children: []core.Node{
			card(sliderRow(locales.Words(cx), func() int { return m.Prefs.Get().PassphraseOpts.NumWords }, 3, 12, func(n int) {
				m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.NumWords = n; return p })
				m.RegenerateSecret()
			})),
			section(locales.Options(cx), card(
				optionRow(locales.WordSeparator(cx), locales.WordSeparatorDetail(cx), sizedInput(base.Input{
					TestID:      "generator-separator",
					Placeholder: "-",
					Value:       func() string { return m.Prefs.Get().PassphraseOpts.Separator },
					OnChange: func(v string) {
						m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.PassphraseOpts.Separator = v; return p })
						m.RegenerateSecret()
					},
					Style: core.Style{Width: core.Pt(64), TextAlign: core.TextAlignCenter},
				}, 28)),
				toggle(locales.CapitalizeWords(cx), locales.CapitalizeWordsExample(cx), func(p UserPrefs) bool { return p.PassphraseOpts.Capitalize }, func(p *UserPrefs, v bool) { p.PassphraseOpts.Capitalize = v }),
				toggle(locales.IncludeNumber(cx), locales.IncludeNumberDetail(cx), func(p UserPrefs) bool { return p.PassphraseOpts.IncludeNum }, func(p *UserPrefs, v bool) { p.PassphraseOpts.IncludeNum = v }),
			)),
		},
	}
}
