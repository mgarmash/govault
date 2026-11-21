package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func UnlockedShellView(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "vault-shell",
		Class:  "flex-1 bg-white dark:bg-neutral-950",
		Children: []core.Node{
			topToolbar(cx, m),
			core.Show{
				When: func() bool { return m.SyncState.Get() == SyncAuthExpired },
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						Class: "flex-row items-center justify-between px-4 py-2 bg-amber-50 dark:bg-amber-950 border-b border-amber-200 dark:border-amber-800",
						Children: []core.Node{
							core.Text{
								Class:   "text-xs text-amber-800 dark:text-amber-200",
								Content: "Session expired — cached vault is readable offline. Sign in again to resume syncing.",
							},
							ui.Button{
								Text:    "Log Out & Sign In",
								Variant: ui.ButtonSecondary,
								Size:    ui.SizeSmall,
								OnPress: func() { m.Logout(cx) },
							},
						},
					}
				},
			},
			core.View{
				Class: "flex-1 flex-row overflow-hidden",
				Children: []core.Node{
					sidebarView(cx, m),
					core.Dynamic(func(cx *core.Scope) core.Node {
						switch m.Route.Get() {
						case RouteGenerator:
							return GeneratorView(cx, m)
						case RouteSettings:
							return SettingsView(cx, m)
						default:
							return vaultSplitPanes(cx, m)
						}
					}),
				},
			},
		},
	}
}

func topToolbar(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between px-4 h-12 border-b border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-2",
				Children: []core.Node{
					core.Icon{
						SVG:   lucide.ShieldCheck(),
						Style: core.Style{Width: core.Pt(18), Height: core.Pt(18), Color: core.RGB(0x2563eb)},
					},
					core.Text{
						Class:   "text-sm font-semibold text-neutral-900 dark:text-white",
						Content: "GoVault",
					},
					core.Show{
						When: func() bool { return m.SyncState.Get() == SyncOffline },
						Then: func(cx *core.Scope) core.Node {
							return ui.Badge{
								Text:    "Offline — cached vault",
								Variant: ui.BadgeWarn,
							}
						},
					},
				},
			},
			core.View{
				Class: "flex-row items-center gap-2",
				Children: []core.Node{
					ui.Button{
						TestID:  "toolbar-sync",
						Text:    "Sync",
						Icon:    lucide.RefreshCw,
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						Busy:    func() bool { return m.SyncState.Get() == SyncInProgress },
						OnPress: func() { m.SyncNow(false) },
					},
					ui.Button{
						TestID:  "toolbar-lock",
						Text:    "Lock",
						Icon:    lucide.Lock,
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						OnPress: m.Lock,
					},
					ui.Button{
						TestID:   "toolbar-new-item",
						Text:     "New Item",
						Icon:     lucide.Plus,
						Variant:  ui.ButtonPrimary,
						Size:     ui.SizeSmall,
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  func() { m.StartCreateCipher(cx) },
					},
				},
			},
		},
	}
}

func sidebarView(cx *core.Scope, m *AppModel) core.Node {
	loginType := api.CipherTypeLogin
	cardType := api.CipherTypeCard
	identType := api.CipherTypeIdentity
	noteType := api.CipherTypeSecureNote

	return core.View{
		TestID: "vault-sidebar",
		Class:  "w-[210px] border-r border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900",
		Children: []core.Node{
			core.Scroll{
				Class: "flex-1 p-2 gap-1",
				Children: []core.Node{
					sidebarSectionHeader("VAULT"),
					sidebarNavRow(m, "sidebar-all", "All Items", lucide.Key,
						func() int { return m.AllCounts.Get().All },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Category == state.FilterAll && f.FolderID == "" && f.Type == nil
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll}) },
					),
					sidebarNavRow(m, "sidebar-favorites", "Favorites", lucide.Star,
						func() int { return m.AllCounts.Get().Favorites },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Category == state.FilterFavorites
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterFavorites}) },
					),
					sidebarSectionHeader("TYPES"),
					sidebarNavRow(m, "sidebar-type-login", "Login", lucide.Globe,
						func() int { return m.AllCounts.Get().Login },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Type != nil && *f.Type == loginType
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &loginType}) },
					),
					sidebarNavRow(m, "sidebar-type-card", "Card", lucide.CreditCard,
						func() int { return m.AllCounts.Get().Card },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Type != nil && *f.Type == cardType
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &cardType}) },
					),
					sidebarNavRow(m, "sidebar-type-identity", "Identity", lucide.User,
						func() int { return m.AllCounts.Get().Identity },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Type != nil && *f.Type == identType
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &identType}) },
					),
					sidebarNavRow(m, "sidebar-type-note", "Secure Note", lucide.FileText,
						func() int { return m.AllCounts.Get().SecureNote },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Type != nil && *f.Type == noteType
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &noteType}) },
					),
					core.View{
						Class: "flex-row items-center justify-between pt-3 pb-1 px-2",
						Children: []core.Node{
							core.Text{
								Class:   "text-[11px] font-semibold tracking-wider text-neutral-400",
								Content: "FOLDERS",
							},
							ui.Button{
								TestID:   "sidebar-add-folder",
								Icon:     lucide.FolderPlus,
								Label:    "New Folder",
								Variant:  ui.ButtonGhost,
								Size:     ui.SizeSmall,
								Side:     22,
								IconSize: 13,
								Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
								OnPress:  m.OpenNewFolderModal,
							},
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						folders := m.Folders.Get()
						rows := make([]core.Node, 0, len(folders)+1)
						for _, f := range folders {
							folder := f
							rows = append(rows, folderRow(cx, m, folder))
						}
						rows = append(rows, sidebarNavRow(m, "sidebar-no-folder", "No Folder", lucide.Folder,
							func() int { return m.AllCounts.Get().NoFolder },
							func() bool {
								f := m.SidebarFilter.Get()
								return m.Route.Get() == RouteVault && f.Category == state.FilterNoFolder
							},
							func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterNoFolder}) },
						))
						return core.View{Class: "gap-0.5", Children: rows}
					}),
					core.View{Class: "h-px my-2 bg-neutral-200 dark:bg-neutral-800"},
					sidebarNavRow(m, "sidebar-trash", "Trash", lucide.RotateCcw,
						func() int { return m.AllCounts.Get().Trash },
						func() bool {
							f := m.SidebarFilter.Get()
							return m.Route.Get() == RouteVault && f.Category == state.FilterTrash
						},
						func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash}) },
					),
					core.View{Class: "h-px my-2 bg-neutral-200 dark:bg-neutral-800"},
					sidebarNavRow(m, "sidebar-generator", "Generator", lucide.Sparkles,
						nil,
						func() bool { return m.Route.Get() == RouteGenerator },
						func() {
							m.GuardDirty(cx, func() {
								m.ResetIdleTimer()
								m.Route.Set(RouteGenerator)
							})
						},
					),
					sidebarNavRow(m, "sidebar-settings", "Settings", lucide.Settings,
						nil,
						func() bool { return m.Route.Get() == RouteSettings },
						func() {
							m.GuardDirty(cx, func() {
								m.ResetIdleTimer()
								m.Route.Set(RouteSettings)
							})
						},
					),
				},
			},
			syncFooter(m),
		},
	}
}

func sidebarSectionHeader(title string) core.Node {
	return core.Text{
		Class:   "text-[11px] font-semibold tracking-wider text-neutral-400 pt-3 pb-1 px-2",
		Content: title,
	}
}

func sidebarNavRow(m *AppModel, testID, label string, icon func() *core.SVG, count func() int, active func() bool, onPress func()) core.Node {
	return core.View{
		TestID: testID,
		ClassFunc: func() string {
			if active() {
				return "flex-row items-center justify-between px-2 py-1.5 rounded-md bg-blue-600/15"
			}
			return "flex-row items-center justify-between px-2 py-1.5 rounded-md hover:bg-neutral-200/60 dark:hover:bg-neutral-800/60"
		},
		OnPress: func(core.PressEvent) { onPress() },
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-2 flex-1 overflow-hidden",
				Children: []core.Node{
					core.Icon{
						SVG: icon(),
						StyleFunc: func() core.Style {
							c := core.RGB(0x6b7280)
							if active() {
								c = core.RGB(0x2563eb)
							}
							return core.Style{Width: core.Pt(14), Height: core.Pt(14), Color: c}
						},
					},
					core.Text{
						MaxLines: 1,
						ClassFunc: func() string {
							if active() {
								return "text-xs font-semibold text-blue-700 dark:text-blue-400 flex-1"
							}
							return "text-xs text-neutral-700 dark:text-neutral-300 flex-1"
						},
						Content: label,
					},
				},
			},
			core.Show{
				When: func() bool { return count != nil },
				Then: func(cx *core.Scope) core.Node {
					return core.Text{
						Class: "text-[11px] text-neutral-400",
						ContentFunc: func() string {
							if count == nil {
								return ""
							}
							return fmt.Sprintf("%d", count())
						},
					}
				},
			},
		},
	}
}

func folderRow(cx *core.Scope, m *AppModel, folder state.Folder) core.Node {
	active := func() bool {
		f := m.SidebarFilter.Get()
		return m.Route.Get() == RouteVault && f.FolderID == folder.ID
	}
	return core.View{
		ClassFunc: func() string {
			if active() {
				return "flex-row items-center justify-between px-2 py-1 rounded-md bg-blue-600/15"
			}
			return "flex-row items-center justify-between px-2 py-1 rounded-md hover:bg-neutral-200/60 dark:hover:bg-neutral-800/60"
		},
		OnPress: func(core.PressEvent) {
			m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: folder.ID})
		},
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-2 flex-1 overflow-hidden",
				Children: []core.Node{
					core.Icon{
						SVG:   lucide.Folder(),
						Style: core.Style{Width: core.Pt(14), Height: core.Pt(14), Color: core.RGB(0x6b7280)},
					},
					core.Text{
						MaxLines: 1,
						ClassFunc: func() string {
							if active() {
								return "text-xs font-semibold text-blue-700 dark:text-blue-400 flex-1"
							}
							return "text-xs text-neutral-700 dark:text-neutral-300 flex-1"
						},
						Content: folder.Name,
					},
				},
			},
			core.View{
				Class: "flex-row items-center gap-0.5",
				Children: []core.Node{
					core.Text{
						Class: "text-[11px] text-neutral-400 pr-1",
						ContentFunc: func() string {
							return fmt.Sprintf("%d", m.AllCounts.Get().ByFolder[folder.ID])
						},
					},
					ui.Button{
						Icon:     lucide.Pencil,
						Label:    "Rename folder",
						Variant:  ui.ButtonGhost,
						Size:     ui.SizeSmall,
						Side:     20,
						IconSize: 11,
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  func() { m.OpenRenameFolderModal(folder) },
					},
					ui.Button{
						Icon:     lucide.X,
						Label:    "Delete folder",
						Variant:  ui.ButtonGhost,
						Size:     ui.SizeSmall,
						Side:     20,
						IconSize: 11,
						Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
						OnPress:  func() { m.DeleteFolder(cx, folder) },
					},
				},
			},
		},
	}
}

func syncFooter(m *AppModel) core.Node {
	return core.View{
		Class: "px-3 py-2 border-t border-neutral-200 dark:border-neutral-800 flex-row items-center gap-2",
		Children: []core.Node{
			core.View{
				ClassFunc: func() string {
					switch m.SyncState.Get() {
					case SyncInProgress:
						return "w-2 h-2 rounded-full bg-blue-500"
					case SyncOffline, SyncAuthExpired:
						return "w-2 h-2 rounded-full bg-amber-500"
					default:
						return "w-2 h-2 rounded-full bg-emerald-500"
					}
				},
			},
			core.Text{
				Class: "text-[11px] text-neutral-500 dark:text-neutral-400 flex-1",
				ContentFunc: func() string {
					switch m.SyncState.Get() {
					case SyncInProgress:
						return "Syncing..."
					case SyncOffline:
						return "Offline (cached)"
					case SyncAuthExpired:
						return "Session expired"
					default:
						ts := m.LastSync.Get()
						if ts.IsZero() {
							return "Synced"
						}
						return "Synced " + formatRelativeTime(ts)
					}
				},
			},
		},
	}
}

func vaultSplitPanes(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		Class: "flex-1 flex-row overflow-hidden",
		Children: []core.Node{
			itemListPane(cx, m),
			core.View{
				Class: "flex-1 bg-white dark:bg-neutral-950 overflow-hidden",
				Children: []core.Node{
					core.Show{
						When: m.EditMode.Get,
						Then: func(cx *core.Scope) core.Node {
							return EditorPaneView(cx, m)
						},
						Else: func(cx *core.Scope) core.Node {
							return DetailPaneView(cx, m)
						},
					},
				},
			},
		},
	}
}

func itemListPane(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "vault-list-pane",
		Class:  "w-[280px] border-r border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950",
		Children: []core.Node{
			core.View{
				Class: "p-2.5 border-b border-neutral-200 dark:border-neutral-800",
				Children: []core.Node{
					base.Input{
						TestID:        "vault-search",
						Ref:           &m.SearchRef,
						Class:         inputClass,
						Placeholder:   "Search vault...",
						NoAutoCorrect: true,
						Role:          core.RoleSearchField,
						Value:         m.SearchQuery.Get,
						OnChange:      m.SetSearchQuery,
					},
				},
			},
			core.List{
				TestID:        "vault-item-list",
				Class:         "flex-1 p-1.5",
				EstimatedSize: 56,
				Gap:           2,
				Count:         m.FilteredItems.Len,
				Key:           func(i int) any { return m.FilteredItems.KeyAt(i) },
				Empty: core.View{
					Class: "flex-1 items-center justify-center p-6 gap-2",
					Children: []core.Node{
						core.Text{
							Class: "text-sm font-medium text-neutral-500 dark:text-neutral-400",
							ContentFunc: func() string {
								if m.SearchQuery.Get() != "" {
									return "No matching items"
								}
								if m.SidebarFilter.Get().Category == state.FilterTrash {
									return "Trash is empty"
								}
								return "No items yet"
							},
						},
						core.Text{
							Class: "text-xs text-neutral-400 text-center",
							ContentFunc: func() string {
								if m.SearchQuery.Get() != "" {
									return "Try a different search term."
								}
								if m.SidebarFilter.Get().Category == state.FilterTrash {
									return "Deleted items appear here."
								}
								return "Press New Item to add your first entry."
							},
						},
					},
				},
				Row: func(cx *core.Scope, row core.ListRow) core.Node {
					itemAt := func() (state.CipherSummary, bool) {
						return m.FilteredItems.At(row.Index())
					}
					selected := func() bool {
						it, ok := itemAt()
						return ok && m.IsSelected(it.ID)
					}
					return core.View{
						TestID: "vault-row",
						ClassFunc: func() string {
							if selected() {
								return "flex-row items-center gap-2.5 px-2.5 py-2 rounded-md bg-blue-600/15"
							}
							return "flex-row items-center gap-2.5 px-2.5 py-2 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-900"
						},
						OnPress: func(core.PressEvent) {
							if it, ok := itemAt(); ok {
								m.SelectCipher(cx, it.ID)
							}
						},
						Children: []core.Node{
							core.View{
								Class: "flex-1 overflow-hidden gap-0.5",
								Children: []core.Node{
									core.View{
										Class: "flex-row items-center gap-1.5",
										Children: []core.Node{
											core.Show{
												When: func() bool {
													it, ok := itemAt()
													return ok && it.Favorite
												},
												Then: func(cx *core.Scope) core.Node {
													return core.Icon{
														SVG:   lucide.Star(),
														Style: core.Style{Width: core.Pt(11), Height: core.Pt(11), Color: core.RGB(0xd97706)},
													}
												},
											},
											core.Text{
												MaxLines: 1,
												ClassFunc: func() string {
													if selected() {
														return "text-sm font-semibold text-blue-700 dark:text-blue-400 flex-1"
													}
													return "text-sm font-medium text-neutral-900 dark:text-white flex-1"
												},
												ContentFunc: func() string {
													it, ok := itemAt()
													if !ok {
														return ""
													}
													return it.Name
												},
											},
										},
									},
									core.Text{
										MaxLines: 1,
										Class:    "text-xs text-neutral-500 dark:text-neutral-400",
										ContentFunc: func() string {
											it, ok := itemAt()
											if !ok {
												return ""
											}
											if it.Subtitle != "" {
												return it.Subtitle
											}
											return CipherTypeLabel(it.Type)
										},
									},
								},
							},
							core.Show{
								When: func() bool {
									it, ok := itemAt()
									return ok && it.HasTOTP
								},
								Then: func(cx *core.Scope) core.Node {
									return ui.Badge{Text: "TOTP", Variant: ui.BadgeInfo}
								},
							},
						},
					}
				},
			},
		},
	}
}

func DetailPaneView(cx *core.Scope, m *AppModel) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		c := m.ActiveCipher.Get()
		if c == nil {
			return core.View{
				TestID: "detail-empty",
				Class:  "flex-1 items-center justify-center p-8 gap-2",
				Children: []core.Node{
					core.Icon{
						SVG:   lucide.Shield(),
						Style: core.Style{Width: core.Pt(32), Height: core.Pt(32), Color: core.RGB(0x9ca3af)},
					},
					core.Text{
						Class:   "text-sm font-medium text-neutral-500 dark:text-neutral-400",
						Content: "Select an item to view details",
					},
				},
			}
		}

		isTrash := c.DeletedDate != nil
		subtitle := CipherTypeLabel(c.Type)
		if c.FolderID != nil && *c.FolderID != "" {
			for _, f := range m.Folders.Get() {
				if f.ID == *c.FolderID {
					subtitle += " · " + f.Name
					break
				}
			}
		}

		var sections []core.Node

		if c.Login != nil {
			if c.Login.Username != "" {
				sections = append(sections, detailCopyRow("Username", c.Login.Username, false, func() {
					m.CopyPlainValue("Username", c.Login.Username)
				}))
			}
			if c.Login.Password != "" {
				sections = append(sections, core.View{
					Class: "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
					Children: []core.Node{
						core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: "Password"},
						core.View{
							Class: "flex-row items-center justify-between gap-2",
							Children: []core.Node{
								core.Text{
									TestID: "detail-password-value",
									Class:  "text-sm font-mono text-neutral-900 dark:text-white flex-1",
									ContentFunc: func() string {
										if m.RevealPW.Get() {
											return c.Login.Password
										}
										return "••••••••••••••••"
									},
								},
								core.View{
									Class: "flex-row items-center gap-1",
									Children: []core.Node{
										ui.Button{
											TestID:  "detail-reveal-pw",
											Icon:    func() *core.SVG { return eyeIcon(m.RevealPW.Get()) },
											Label:   "Reveal password",
											Variant: ui.ButtonGhost,
											Size:    ui.SizeSmall,
											OnPress: func() {
												if m.RevealPW.Get() {
													m.RevealPW.Set(false)
													return
												}
												m.GateReprompt(cx, c, "reveal password", func() {
													m.RevealPW.Set(true)
												})
											},
										},
										ui.Button{
											TestID:  "detail-copy-pw",
											Text:    "Copy",
											Icon:    lucide.Copy,
											Variant: ui.ButtonSecondary,
											Size:    ui.SizeSmall,
											OnPress: func() {
												m.GateReprompt(cx, c, "copy password", func() {
													m.CopySecretValue("Password", c.Login.Password)
												})
											},
										},
									},
								},
							},
						},
					},
				})
			}
			if strings.TrimSpace(c.Login.TOTP) != "" {
				sections = append(sections, core.View{
					TestID: "detail-totp-section",
					Class:  "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
					Children: []core.Node{
						core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: "Verification Code (TOTP)"},
						core.View{
							Class: "flex-row items-center justify-between gap-2",
							Children: []core.Node{
								core.View{
									Class: "flex-row items-center gap-3",
									Children: []core.Node{
										core.Text{
											TestID: "detail-totp-code",
											Class:  "text-lg font-mono font-semibold text-blue-600 dark:text-blue-400",
											ContentFunc: func() string {
												code := m.TOTPCode.Get()
												if code == "" {
													return "--- ---"
												}
												return FormatTOTPCode(code)
											},
										},
										core.Text{
											Class: "text-xs text-neutral-500 dark:text-neutral-400",
											ContentFunc: func() string {
												rem := m.TOTPRemaining.Get()
												if rem <= 0 {
													return ""
												}
												return fmt.Sprintf("%ds", rem)
											},
										},
									},
								},
								ui.Button{
									TestID:  "detail-copy-totp",
									Text:    "Copy",
									Icon:    lucide.Copy,
									Variant: ui.ButtonSecondary,
									Size:    ui.SizeSmall,
									OnPress: func() {
										m.GateReprompt(cx, c, "copy TOTP code", func() {
											if code := m.TOTPCode.Get(); code != "" {
												m.CopySecretValue("TOTP code", code)
											}
										})
									},
								},
							},
						},
					},
				})
			}
			if len(c.Login.URIs) > 0 {
				var uriNodes []core.Node
				for _, u := range c.Login.URIs {
					uri := u.URI
					uriNodes = append(uriNodes, core.View{
						Class: "flex-row items-center justify-between gap-2 py-1",
						Children: []core.Node{
							core.Text{MaxLines: 1, Class: "text-sm text-blue-600 dark:text-blue-400 flex-1", Content: uri},
							core.View{
								Class: "flex-row items-center gap-1",
								Children: []core.Node{
									ui.Button{
										Icon:    lucide.ExternalLink,
										Label:   "Open URL",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
										OnPress: func() { cx.OpenURL(uri, nil) },
									},
									ui.Button{
										Icon:    lucide.Copy,
										Label:   "Copy URL",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
										OnPress: func() { m.CopyPlainValue("URL", uri) },
									},
								},
							},
						},
					})
				}
				sections = append(sections, core.View{
					Class: "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
					Children: append([]core.Node{
						core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: "Websites"},
					}, uriNodes...),
				})
			}
		}

		if c.Card != nil {
			if c.Card.CardholderName != "" {
				sections = append(sections, detailCopyRow("Cardholder Name", c.Card.CardholderName, false, func() {
					m.CopyPlainValue("Cardholder", c.Card.CardholderName)
				}))
			}
			if c.Card.Brand != "" {
				sections = append(sections, detailCopyRow("Brand", c.Card.Brand, false, func() {
					m.CopyPlainValue("Brand", c.Card.Brand)
				}))
			}
			if c.Card.Number != "" {
				sections = append(sections, core.View{
					Class: "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
					Children: []core.Node{
						core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: "Number"},
						core.View{
							Class: "flex-row items-center justify-between gap-2",
							Children: []core.Node{
								core.Text{
									Class: "text-sm font-mono text-neutral-900 dark:text-white flex-1",
									ContentFunc: func() string {
										if m.RevealCard.Get() {
											return c.Card.Number
										}
										return maskCardNumber(c.Card.Number)
									},
								},
								core.View{
									Class: "flex-row items-center gap-1",
									Children: []core.Node{
										ui.Button{
											Icon:    func() *core.SVG { return eyeIcon(m.RevealCard.Get()) },
											Label:   "Reveal card",
											Variant: ui.ButtonGhost,
											Size:    ui.SizeSmall,
											OnPress: func() {
												if m.RevealCard.Get() {
													m.RevealCard.Set(false)
													return
												}
												m.GateReprompt(cx, c, "reveal card", func() {
													m.RevealCard.Set(true)
												})
											},
										},
										ui.Button{
											Text:    "Copy",
											Icon:    lucide.Copy,
											Variant: ui.ButtonSecondary,
											Size:    ui.SizeSmall,
											OnPress: func() {
												m.GateReprompt(cx, c, "copy card number", func() {
													m.CopySecretValue("Card number", c.Card.Number)
												})
											},
										},
									},
								},
							},
						},
					},
				})
			}
			if c.Card.ExpMonth != "" || c.Card.ExpYear != "" {
				exp := strings.TrimSpace(c.Card.ExpMonth + "/" + c.Card.ExpYear)
				sections = append(sections, detailCopyRow("Expiration", exp, false, func() {
					m.CopyPlainValue("Expiration", exp)
				}))
			}
			if c.Card.Code != "" {
				sections = append(sections, detailCopyRow("Security Code", "•••", true, func() {
					m.GateReprompt(cx, c, "copy security code", func() {
						m.CopySecretValue("Security code", c.Card.Code)
					})
				}))
			}
		}

		if c.Identity != nil {
			fullName := strings.TrimSpace(strings.Join([]string{c.Identity.Title, c.Identity.FirstName, c.Identity.MiddleName, c.Identity.LastName}, " "))
			if fullName != "" {
				sections = append(sections, detailCopyRow("Full Name", fullName, false, func() { m.CopyPlainValue("Name", fullName) }))
			}
			if c.Identity.Company != "" {
				sections = append(sections, detailCopyRow("Company", c.Identity.Company, false, func() { m.CopyPlainValue("Company", c.Identity.Company) }))
			}
			if c.Identity.Email != "" {
				sections = append(sections, detailCopyRow("Email", c.Identity.Email, false, func() { m.CopyPlainValue("Email", c.Identity.Email) }))
			}
			if c.Identity.Phone != "" {
				sections = append(sections, detailCopyRow("Phone", c.Identity.Phone, false, func() { m.CopyPlainValue("Phone", c.Identity.Phone) }))
			}
			if c.Identity.Username != "" {
				sections = append(sections, detailCopyRow("Username", c.Identity.Username, false, func() { m.CopyPlainValue("Username", c.Identity.Username) }))
			}
			addr := strings.TrimSpace(strings.Join([]string{c.Identity.Address1, c.Identity.City, c.Identity.State, c.Identity.PostalCode, c.Identity.Country}, ", "))
			addr = strings.Trim(addr, ", ")
			if addr != "" {
				sections = append(sections, detailCopyRow("Address", addr, false, func() { m.CopyPlainValue("Address", addr) }))
			}
			if c.Identity.SSN != "" {
				sections = append(sections, detailCopyRow("SSN", "••••••••", true, func() {
					m.GateReprompt(cx, c, "copy SSN", func() { m.CopySecretValue("SSN", c.Identity.SSN) })
				}))
			}
			if c.Identity.PassportNumber != "" {
				sections = append(sections, detailCopyRow("Passport", c.Identity.PassportNumber, true, func() {
					m.CopySecretValue("Passport", c.Identity.PassportNumber)
				}))
			}
			if c.Identity.LicenseNumber != "" {
				sections = append(sections, detailCopyRow("License", c.Identity.LicenseNumber, true, func() {
					m.CopySecretValue("License", c.Identity.LicenseNumber)
				}))
			}
		}

		if len(c.Fields) > 0 {
			var fieldNodes []core.Node
			for _, f := range c.Fields {
				field := f
				display := field.Value
				isHidden := field.Type == 1
				if isHidden {
					display = "••••••••"
				}
				fieldNodes = append(fieldNodes, detailCopyRow(field.Name, display, isHidden, func() {
					if isHidden {
						m.GateReprompt(cx, c, "copy custom field", func() {
							m.CopySecretValue(field.Name, field.Value)
						})
					} else {
						m.CopyPlainValue(field.Name, field.Value)
					}
				}))
			}
			sections = append(sections, core.View{
				Class: "pt-2 gap-1",
				Children: append([]core.Node{
					core.Text{Class: "text-xs font-semibold uppercase tracking-wider text-neutral-400", Content: "Custom Fields"},
				}, fieldNodes...),
			})
		}

		if strings.TrimSpace(c.Notes) != "" {
			sections = append(sections, core.View{
				Class: "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
				Children: []core.Node{
					core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: "Notes"},
					core.Text{
						Class:      "text-sm text-neutral-800 dark:text-neutral-200",
						Selectable: core.SelectableOn,
						Content:    c.Notes,
					},
				},
			})
		}

		updatedText := ""
		if c.RevisionDate != nil {
			updatedText = "Updated " + c.RevisionDate.Local().Format("2006-01-02 15:04")
		}

		var headerActions []core.Node
		if isTrash {
			headerActions = []core.Node{
				ui.Button{
					TestID:   "detail-restore",
					Text:     "Restore",
					Icon:     lucide.RotateCcw,
					Variant:  ui.ButtonPrimary,
					Size:     ui.SizeSmall,
					Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
					OnPress:  m.RestoreActive,
				},
				ui.Button{
					TestID:   "detail-hard-delete",
					Text:     "Delete Permanently",
					Variant:  ui.ButtonSecondary,
					Size:     ui.SizeSmall,
					Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
					OnPress:  func() { m.HardDeleteActive(cx) },
				},
			}
		} else {
			headerActions = []core.Node{
				ui.Button{
					TestID:   "detail-favorite",
					Icon:     lucide.Star,
					Label:    "Toggle favorite",
					Variant:  ui.ButtonGhost,
					Size:     ui.SizeSmall,
					Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
					OnPress:  m.ToggleFavorite,
				},
				ui.Button{
					TestID:   "detail-edit",
					Text:     "Edit",
					Icon:     lucide.Pencil,
					Variant:  ui.ButtonSecondary,
					Size:     ui.SizeSmall,
					Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
					OnPress:  func() { m.StartEditCipher(cx) },
				},
			}
		}

		var footerActions []core.Node
		if !isTrash {
			footerActions = append(footerActions, ui.Button{
				TestID:   "detail-trash",
				Text:     "Move to Trash",
				Variant:  ui.ButtonGhost,
				Size:     ui.SizeSmall,
				Disabled: func() bool { return m.SyncState.Get() == SyncOffline },
				OnPress:  m.SoftDeleteActive,
			})
		}

		return core.View{
			TestID: "detail-view",
			Class:  "flex-1",
			Children: []core.Node{
				core.View{
					Class: "flex-row items-center justify-between px-6 py-4 border-b border-neutral-200 dark:border-neutral-800",
					Children: []core.Node{
						core.View{
							Class: "gap-0.5 flex-1 pr-4",
							Children: []core.Node{
								core.Text{
									TestID:   "detail-title",
									MaxLines: 1,
									Class:    "text-lg font-semibold text-neutral-900 dark:text-white",
									Content:  c.Name,
								},
								core.Text{
									Class:   "text-xs text-neutral-500 dark:text-neutral-400",
									Content: subtitle,
								},
							},
						},
						core.View{
							Class:    "flex-row items-center gap-2",
							Children: headerActions,
						},
					},
				},
				core.Scroll{
					Class:    "flex-1 px-6 py-3",
					Children: sections,
				},
				core.View{
					Class: "flex-row items-center justify-between px-6 py-3 border-t border-neutral-200 dark:border-neutral-800",
					Children: append([]core.Node{
						core.Text{Class: "text-xs text-neutral-400", Content: updatedText},
					}, footerActions...),
				},
			},
		}
	})
}

func detailCopyRow(label, value string, mono bool, onCopy func()) core.Node {
	valClass := "text-sm text-neutral-900 dark:text-white flex-1"
	if mono {
		valClass = "text-sm font-mono text-neutral-900 dark:text-white flex-1"
	}
	return core.View{
		Class: "py-2.5 border-b border-neutral-100 dark:border-neutral-800 gap-1",
		Children: []core.Node{
			core.Text{Class: "text-xs font-medium text-neutral-500 dark:text-neutral-400", Content: label},
			core.View{
				Class: "flex-row items-center justify-between gap-2",
				Children: []core.Node{
					core.Text{Class: valClass, Selectable: core.SelectableOn, Content: value},
					ui.Button{
						Text:    "Copy",
						Icon:    lucide.Copy,
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						OnPress: onCopy,
					},
				},
			},
		},
	}
}

func maskCardNumber(num string) string {
	digits := strings.ReplaceAll(num, " ", "")
	if len(digits) <= 4 {
		return "••••"
	}
	return "•••• •••• •••• " + digits[len(digits)-4:]
}

func formatRelativeTime(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Local().Format("Jan 2")
}
