package ui

import (
	"fmt"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/health"
)

func HealthView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "health-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				r := m.Health.Get()
				filter := m.HealthFilter.Get()
				show := func(c HealthCategory) bool { return filter == HealthAll || filter == c }
				tile := func(c HealthCategory, glyph func() *core.SVG, tint uint32, count int, label string) core.Node {
					return healthTile(m, c, glyph, tint, count, label, filter == c)
				}
				blocks := []core.Node{
					core.View{
						Class: "flex-row gap-3",
						Children: []core.Node{
							tile(HealthReused, lucide.Repeat, 0xf08a0a, r.ReusedItems(), locales.HealthReused(cx)),
							tile(HealthWeak, lucide.ShieldAlert, 0xe5484d, len(r.Weak), locales.HealthWeak(cx)),
							tile(HealthCards, lucide.CalendarClock, 0xa25ddc, len(r.Cards), locales.HealthExpiringCards(cx)),
							tile(HealthUnsecured, lucide.LockOpen, 0x0a84ff, len(r.Unsecured), locales.HealthUnsecured(cx)),
							tile(HealthDuplicates, lucide.Files, 0x12a594, len(r.Duplicates), locales.DuplicateLogins(cx)),
						},
					},
				}
				if filter != HealthAll && healthCount(r, filter) == 0 && r.TotalIssues() > 0 {
					blocks = append(blocks, core.Text{
						TestID:  "health-filter-empty",
						Class:   "px-1 text-[12.5px] text-gv-fg2",
						Content: locales.HealthFilterEmpty(cx),
					})
				}
				if r.TotalIssues() == 0 {
					blocks = append(blocks, card(core.View{
						TestID: "health-all-clear",
						Class:  "flex-row items-center gap-3 px-4 py-4",
						Children: []core.Node{
							icon(lucide.CircleCheck(), 22, "text-gv-success"),
							core.View{
								Class: "flex-1 gap-[2px]",
								Children: []core.Node{
									core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: locales.HealthAllClear(cx)},
									core.Text{Class: "text-[12px] text-gv-fg2", Content: locales.HealthAllClearDetail(cx)},
								},
							},
						},
					}))
				}
				for i, g := range r.Reused {
					if !show(HealthReused) {
						break
					}
					title := ""
					if i == 0 {
						title = locales.ReusedPasswords(cx)
					}
					blocks = append(blocks, section(title, healthList(cx, m, g.Items, func(_ int, it health.Issue) string { return locales.UsedInItems(cx, it.ReusedCount) })))
				}
				if len(r.Weak) > 0 && show(HealthWeak) {
					blocks = append(blocks, section(locales.WeakPasswords(cx), healthList(cx, m, r.Weak, weaknessText(cx))))
				}
				if len(r.Cards) > 0 && show(HealthCards) {
					items := make([]health.Issue, len(r.Cards))
					for i, c := range r.Cards {
						items[i] = c.Issue
					}
					blocks = append(blocks, section(locales.HealthExpiringCards(cx), healthList(cx, m, items, func(i int, it health.Issue) string {
						return cardExpiryText(cx, it, r.Cards[i].Expired)
					})))
				}
				if len(r.Unsecured) > 0 && show(HealthUnsecured) {
					blocks = append(blocks, section(locales.UnsecuredWebsites(cx), healthList(cx, m, r.Unsecured, func(_ int, it health.Issue) string { return it.URI })))
				}
				for i, g := range r.Duplicates {
					if !show(HealthDuplicates) {
						break
					}
					title := ""
					if i == 0 {
						title = locales.DuplicateLogins(cx)
					}
					header := locales.DuplicateGroup(cx, g.Site, g.Username, len(g.Items))
					if g.Username == "" {
						header = locales.DuplicateGroupNoUsername(cx, g.Site, len(g.Items))
					}
					blocks = append(blocks, section(title, core.View{
						TestID: "health-duplicate-group",
						Class:  "gap-1.5",
						Children: []core.Node{
							core.Text{MaxLines: 1, Class: "px-1 text-[12px] text-gv-fg2", Content: header},
							healthList(cx, m, g.Items, func(int, health.Issue) string { return "" }),
						},
					}))
				}
				blocks = append(blocks, core.Text{
					Class:   "px-1 text-[11.5px] text-gv-fg3",
					Content: locales.HealthLocalOnly(cx),
				})
				return core.View{
					Class:    "w-full max-w-[680px] self-center px-7 pt-6 pb-10 gap-5",
					Children: blocks,
				}
			}),
		},
	}
}

func healthCount(r health.Report, c HealthCategory) int {
	switch c {
	case HealthReused:
		return r.ReusedItems()
	case HealthWeak:
		return len(r.Weak)
	case HealthCards:
		return len(r.Cards)
	case HealthUnsecured:
		return len(r.Unsecured)
	case HealthDuplicates:
		return len(r.Duplicates)
	}
	return r.TotalIssues()
}

// SetHealthFilter shows only category c, or every category when c is the
// active one.
func (m *AppModel) SetHealthFilter(c HealthCategory) {
	m.ResetIdleTimer()
	if m.HealthFilter.Get() == c {
		c = HealthAll
	}
	m.HealthFilter.Set(c)
}

func healthTile(m *AppModel, c HealthCategory, glyph func() *core.SVG, tint uint32, count int, label string, selected bool) core.Node {
	countClass := "text-[22px] font-semibold text-gv-fg tabular-nums"
	if count == 0 {
		countClass = "text-[22px] font-semibold text-gv-fg3 tabular-nums"
	}
	frame := "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-card border border-gv-line"
	if selected {
		frame = "gap-1.5 px-3.5 py-3 rounded-[10px] bg-gv-accent-soft border border-gv-accent"
	}
	return core.View{
		TestID:   "health-count-" + string(c),
		Role:     core.RoleButton,
		Label:    label,
		Selected: func() bool { return selected },
		Class:    "flex-1",
		OnPress:  func(core.PressEvent) { m.SetHealthFilter(c) },
		Children: []core.Node{core.View{
			Class: frame,
			Style: core.Style{BorderCurve: core.BorderCurveContinuous},
			Children: []core.Node{
				core.View{
					Class: "w-[24px] h-[24px] rounded-[6px] items-center justify-center",
					Style: core.Style{Background: core.RGB(tint)},
					Children: []core.Node{
						core.Icon{SVG: glyph(), Style: core.Style{Width: core.Pt(13), Height: core.Pt(13), Color: core.RGB(0xffffff)}},
					},
				},
				core.Text{Class: countClass, Content: fmt.Sprintf("%d", count)},
				core.Text{MaxLines: 2, Class: "text-[12px] text-gv-fg2", Content: label},
			},
		}},
	}
}

// weaknessText says why a weak password is weak.
func weaknessText(cx *core.Scope) func(int, health.Issue) string {
	return func(_ int, it health.Issue) string {
		switch it.Weakness {
		case health.WeakCommon:
			return locales.WeakCommon(cx)
		case health.WeakShort:
			return locales.WeakShort(cx, health.MinPasswordLength)
		case health.WeakPattern:
			return locales.WeakPattern(cx)
		case health.WeakOneClass:
			return locales.WeakOneClass(cx)
		case health.WeakGuessable:
			return locales.WeakGuessable(cx)
		}
		return ""
	}
}

// cardExpiryText says when a card expired or expires, as MM/YYYY.
func cardExpiryText(cx *core.Scope, it health.Issue, expired bool) string {
	expiry := fmt.Sprintf("%02d/%d", it.ExpMonth, it.ExpYear)
	if expired {
		return locales.CardExpired(cx, expiry)
	}
	return locales.CardExpires(cx, expiry)
}

// healthList lists flagged items, each with what detail says of it.
func healthList(cx *core.Scope, m *AppModel, items []health.Issue, detail func(int, health.Issue) string) core.Node {
	rows := make([]core.Node, 0, len(items))
	for i, it := range items {
		issue := it
		rows = append(rows, core.View{
			TestID:  "health-item",
			Role:    core.RoleButton,
			Label:   locales.OpenItem(cx, issue.Name),
			Class:   "flex-row items-center gap-3 pl-3.5 pr-3 py-2 min-h-[48px] active:bg-gv-fill",
			OnPress: func(core.PressEvent) { m.OpenHealthItem(cx, issue.CipherID) },
			Children: []core.Node{
				itemEmblem(issue.Name, issue.Type, "", 28),
				core.View{
					Class: "flex-1 gap-[2px] overflow-hidden",
					Children: []core.Node{
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: issue.Name},
						core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: issue.Subtitle},
					},
				},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-right", Content: detail(i, issue)},
				icon(lucide.ChevronRight(), 12, "text-gv-fg3"),
			},
		})
	}
	return card(rows...)
}
