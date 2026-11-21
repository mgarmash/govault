package ui

import (
	"fmt"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/txchen/govault/internal/vaultcore/health"
)

func HealthView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "health-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				r := m.Health.Get()
				blocks := []core.Node{
					core.View{
						Class: "flex-row gap-3",
						Children: []core.Node{
							healthTile("health-count-reused", lucide.Repeat, 0xf08a0a, r.ReusedItems(), "Reused"),
							healthTile("health-count-weak", lucide.ShieldAlert, 0xe5484d, len(r.Weak), "Weak"),
							healthTile("health-count-cards", lucide.CalendarClock, 0xa25ddc, len(r.Cards), "Expiring Cards"),
							healthTile("health-count-unsecured", lucide.LockOpen, 0x0a84ff, len(r.Unsecured), "Unsecured HTTP"),
						},
					},
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
									core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: "All clear"},
									core.Text{Class: "text-[12px] text-gv-fg2", Content: "No reused or weak passwords, expiring cards or unsecured websites."},
								},
							},
						},
					}))
				}
				for i, g := range r.Reused {
					title := ""
					if i == 0 {
						title = "Reused Passwords"
					}
					blocks = append(blocks, section(title, healthList(cx, m, g.Items)))
				}
				if len(r.Weak) > 0 {
					blocks = append(blocks, section("Weak Passwords", healthList(cx, m, r.Weak)))
				}
				if len(r.Cards) > 0 {
					items := make([]health.Issue, len(r.Cards))
					for i, c := range r.Cards {
						items[i] = c.Issue
					}
					blocks = append(blocks, section("Expiring Cards", healthList(cx, m, items)))
				}
				if len(r.Unsecured) > 0 {
					blocks = append(blocks, section("Unsecured Websites", healthList(cx, m, r.Unsecured)))
				}
				blocks = append(blocks, core.Text{
					Class:   "px-1 text-[11.5px] text-gv-fg3",
					Content: "Checked on this device only. Nothing is sent to a server.",
				})
				return core.View{
					Class:    "w-full max-w-[680px] self-center px-7 pt-6 pb-10 gap-5",
					Children: blocks,
				}
			}),
		},
	}
}

func healthTile(testID string, glyph func() *core.SVG, tint uint32, count int, label string) core.Node {
	countClass := "text-[22px] font-semibold text-gv-fg tabular-nums"
	if count == 0 {
		countClass = "text-[22px] font-semibold text-gv-fg3 tabular-nums"
	}
	return core.View{
		TestID: testID,
		Class:  "flex-1",
		Children: []core.Node{card(core.View{
			Class: "gap-1.5 px-3.5 py-3",
			Children: []core.Node{
				core.View{
					Class: "w-[24px] h-[24px] rounded-[6px] items-center justify-center",
					Style: core.Style{Background: core.RGB(tint)},
					Children: []core.Node{
						core.Icon{SVG: glyph(), Style: core.Style{Width: core.Pt(13), Height: core.Pt(13), Color: core.RGB(0xffffff)}},
					},
				},
				core.Text{Class: countClass, Content: fmt.Sprintf("%d", count)},
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2", Content: label},
			},
		})},
	}
}

func healthList(cx *core.Scope, m *AppModel, items []health.Issue) core.Node {
	rows := make([]core.Node, 0, len(items))
	for _, it := range items {
		issue := it
		rows = append(rows, core.View{
			TestID:  "health-item",
			Role:    core.RoleButton,
			Label:   "Open " + issue.Name,
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
				core.Text{MaxLines: 1, Class: "text-[12px] text-gv-fg2 text-right", Content: issue.Detail},
				icon(lucide.ChevronRight(), 12, "text-gv-fg3"),
			},
		})
	}
	return card(rows...)
}
