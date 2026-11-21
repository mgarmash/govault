package ui

import (
	"fmt"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
)

func EditorPaneView(cx *core.Scope, m *AppModel) core.Node {
	showPW := core.NewSignal(cx, false)

	return core.View{
		TestID: "editor-pane",
		Class:  "flex-1 bg-white dark:bg-neutral-950",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center justify-between px-6 py-4 border-b border-neutral-200 dark:border-neutral-800",
				Children: []core.Node{
					core.Text{
						Class: "text-lg font-semibold text-neutral-900 dark:text-white",
						ContentFunc: func() string {
							d := m.EditDraft.Get()
							if d == nil {
								return ""
							}
							if d.IsNew {
								return "New " + CipherTypeLabel(d.Type)
							}
							return "Edit " + CipherTypeLabel(d.Type)
						},
					},
					core.View{
						Class: "flex-row items-center gap-2",
						Children: []core.Node{
							ui.Button{
								TestID:  "editor-cancel",
								Text:    "Cancel",
								Variant: ui.ButtonSecondary,
								Size:    ui.SizeSmall,
								OnPress: func() { m.CancelEdit(cx) },
							},
							ui.Button{
								TestID:  "editor-save",
								Text:    "Save",
								Variant: ui.ButtonPrimary,
								Size:    ui.SizeSmall,
								Busy:    m.EditBusy.Get,
								OnPress: func() { m.SaveDraft(cx) },
							},
						},
					},
				},
			},
			core.Show{
				When: func() bool { return m.EditError.Get() != "" },
				Then: func(cx *core.Scope) core.Node {
					return core.View{
						TestID: "editor-error",
						Class:  "mx-6 mt-3 px-3 py-2 rounded-md bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800",
						Children: []core.Node{
							core.Text{
								Class:       "text-xs text-red-700 dark:text-red-300",
								ContentFunc: m.EditError.Get,
							},
						},
					}
				},
			},
			core.Scroll{
				Class: "flex-1 px-6 py-4 gap-4",
				Children: []core.Node{
					core.Show{
						When: func() bool {
							d := m.EditDraft.Get()
							return d != nil && d.IsNew
						},
						Then: func(cx *core.Scope) core.Node {
							return labeledField("Item Type", ui.Select[api.CipherType]{
								TestID: "editor-type",
								Options: []ui.Option[api.CipherType]{
									{Value: api.CipherTypeLogin, Label: "Login"},
									{Value: api.CipherTypeSecureNote, Label: "Secure Note"},
									{Value: api.CipherTypeCard, Label: "Card"},
									{Value: api.CipherTypeIdentity, Label: "Identity"},
								},
								Value: func() api.CipherType {
									if d := m.EditDraft.Get(); d != nil {
										return d.Type
									}
									return api.CipherTypeLogin
								},
								OnChange: func(t api.CipherType) {
									m.MutateDraft(func(d *EditDraft) { d.Type = t })
								},
							})
						},
					},
					labeledField("Name *", base.Input{
						TestID:      "editor-name",
						Class:       inputClass,
						Placeholder: "Item name",
						Value: func() string {
							if d := m.EditDraft.Get(); d != nil {
								return d.Name
							}
							return ""
						},
						OnChange: func(v string) {
							m.MutateDraft(func(d *EditDraft) { d.Name = v })
						},
					}),
					core.View{
						Class: "flex-row items-end gap-4",
						Children: []core.Node{
							core.Dynamic(func(cx *core.Scope) core.Node {
								opts := []ui.Option[string]{{Value: "", Label: "No Folder"}}
								for _, f := range m.Folders.Get() {
									opts = append(opts, ui.Option[string]{Value: f.ID, Label: f.Name})
								}
								return labeledField("Folder", ui.Select[string]{
									TestID:  "editor-folder",
									Options: opts,
									Value: func() string {
										if d := m.EditDraft.Get(); d != nil {
											return d.FolderID
										}
										return ""
									},
									OnChange: func(v string) {
										m.MutateDraft(func(d *EditDraft) { d.FolderID = v })
									},
								})
							}),
							ui.Checkbox{
								TestID: "editor-favorite",
								Text:   "Favorite",
								Checked: func() bool {
									d := m.EditDraft.Get()
									return d != nil && d.Favorite
								},
								OnChange: func(v bool) {
									m.MutateDraft(func(d *EditDraft) { d.Favorite = v })
								},
							},
							ui.Checkbox{
								TestID: "editor-reprompt",
								Text:   "Master password reprompt",
								Checked: func() bool {
									d := m.EditDraft.Get()
									return d != nil && d.Reprompt
								},
								OnChange: func(v bool) {
									m.MutateDraft(func(d *EditDraft) { d.Reprompt = v })
								},
							},
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						d := m.EditDraft.Get()
						if d == nil {
							return nil
						}
						switch d.Type {
						case api.CipherTypeLogin:
							return editorLoginFields(cx, m, showPW)
						case api.CipherTypeCard:
							return editorCardFields(m)
						case api.CipherTypeIdentity:
							return editorIdentityFields(m)
						default:
							return nil
						}
					}),
					editorCustomFieldsSection(m),
					labeledField("Notes", base.Input{
						TestID:      "editor-notes",
						Class:       inputClass + " min-h-[96px]",
						Placeholder: "Notes...",
						Multiline:   true,
						Value: func() string {
							if d := m.EditDraft.Get(); d != nil {
								return d.Notes
							}
							return ""
						},
						OnChange: func(v string) {
							m.MutateDraft(func(d *EditDraft) { d.Notes = v })
						},
					}),
				},
			},
		},
	}
}

func editorLoginFields(cx *core.Scope, m *AppModel, showPW *core.Signal[bool]) core.Node {
	return core.View{
		Class: "gap-3",
		Children: []core.Node{
			labeledField("Username", base.Input{
				TestID:        "editor-username",
				Class:         inputClass,
				Placeholder:   "alice@example.com",
				NoAutoCorrect: true,
				Value: func() string {
					if d := m.EditDraft.Get(); d != nil {
						return d.Username
					}
					return ""
				},
				OnChange: func(v string) {
					m.MutateDraft(func(d *EditDraft) { d.Username = v })
				},
			}),
			labeledField("Password", core.View{
				Class: "flex-row items-center gap-2",
				Children: []core.Node{
					core.Dynamic(func(cx *core.Scope) core.Node {
						masked := !showPW.Get()
						return base.Input{
							TestID:        "editor-password",
							Class:         inputClass + " flex-1 font-mono",
							Placeholder:   "Password",
							Masked:        masked,
							NoAutoCorrect: true,
							Value: func() string {
								if d := m.EditDraft.Get(); d != nil {
									return d.Password
								}
								return ""
							},
							OnChange: func(v string) {
								m.MutateDraft(func(d *EditDraft) { d.Password = v })
							},
						}
					}),
					ui.Button{
						Icon:    func() *core.SVG { return eyeIcon(showPW.Get()) },
						Label:   "Toggle password visibility",
						Variant: ui.ButtonGhost,
						Size:    ui.SizeSmall,
						OnPress: func() { showPW.Set(!showPW.Get()) },
					},
					ui.Button{
						TestID:  "editor-generate-pw",
						Text:    "Generate",
						Icon:    lucide.Sparkles,
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						OnPress: func() {
							pw := m.GenerateInlinePassword()
							m.MutateDraft(func(d *EditDraft) { d.Password = pw })
						},
					},
				},
			}),
			labeledField("Authenticator Key (TOTP)", base.Input{
				TestID:        "editor-totp",
				Class:         inputClass + " font-mono",
				Placeholder:   "otpauth://totp/... or Base32 secret",
				NoAutoCorrect: true,
				Value: func() string {
					if d := m.EditDraft.Get(); d != nil {
						return d.TOTP
					}
					return ""
				},
				OnChange: func(v string) {
					m.MutateDraft(func(d *EditDraft) { d.TOTP = v })
				},
			}),
			core.View{
				Class: "gap-2",
				Children: []core.Node{
					core.View{
						Class: "flex-row items-center justify-between",
						Children: []core.Node{
							core.Text{Class: "text-xs font-medium text-neutral-600 dark:text-neutral-400", Content: "URIs"},
							ui.Button{
								TestID:  "editor-add-uri",
								Text:    "Add URI",
								Icon:    lucide.Plus,
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() {
									m.MutateDraft(func(d *EditDraft) {
										d.URIs = append(d.URIs, EditURIDraft{})
									})
								},
							},
						},
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						d := m.EditDraft.Get()
						if d == nil {
							return nil
						}
						rows := make([]core.Node, 0, len(d.URIs))
						for i := range d.URIs {
							idx := i
							rows = append(rows, core.View{
								Class: "flex-row items-center gap-2",
								Children: []core.Node{
									base.Input{
										TestID:        fmt.Sprintf("editor-uri-%d", idx),
										Class:         inputClass + " flex-1",
										Placeholder:   "https://example.com",
										NoAutoCorrect: true,
										Value: func() string {
											cur := m.EditDraft.Get()
											if cur == nil || idx >= len(cur.URIs) {
												return ""
											}
											return cur.URIs[idx].URI
										},
										OnChange: func(v string) {
											m.MutateDraft(func(d *EditDraft) {
												if idx < len(d.URIs) {
													d.URIs[idx].URI = v
												}
											})
										},
									},
									ui.Button{
										Icon:    lucide.X,
										Label:   "Remove URI",
										Variant: ui.ButtonGhost,
										Size:    ui.SizeSmall,
										OnPress: func() {
											m.MutateDraft(func(d *EditDraft) {
												if idx < len(d.URIs) {
													d.URIs = append(d.URIs[:idx], d.URIs[idx+1:]...)
												}
											})
										},
									},
								},
							})
						}
						return core.View{Class: "gap-2", Children: rows}
					}),
				},
			},
		},
	}
}

func editorCardFields(m *AppModel) core.Node {
	return core.View{
		Class: "gap-3",
		Children: []core.Node{
			labeledField("Cardholder Name", draftInput(m, "editor-cardholder", "Jane Doe", func(d *EditDraft) string { return d.Cardholder }, func(d *EditDraft, v string) { d.Cardholder = v })),
			labeledField("Brand", draftInput(m, "editor-brand", "Visa, Mastercard...", func(d *EditDraft) string { return d.Brand }, func(d *EditDraft, v string) { d.Brand = v })),
			labeledField("Number", draftInput(m, "editor-card-number", "4111 1111 1111 1111", func(d *EditDraft) string { return d.CardNumber }, func(d *EditDraft, v string) { d.CardNumber = v })),
			core.View{
				Class: "flex-row gap-3",
				Children: []core.Node{
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Exp Month", draftInput(m, "editor-exp-month", "01", func(d *EditDraft) string { return d.ExpMonth }, func(d *EditDraft, v string) { d.ExpMonth = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Exp Year", draftInput(m, "editor-exp-year", "2029", func(d *EditDraft) string { return d.ExpYear }, func(d *EditDraft, v string) { d.ExpYear = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Security Code", draftInput(m, "editor-card-code", "123", func(d *EditDraft) string { return d.CardCode }, func(d *EditDraft, v string) { d.CardCode = v }))}},
				},
			},
		},
	}
}

func editorIdentityFields(m *AppModel) core.Node {
	return core.View{
		Class: "gap-3",
		Children: []core.Node{
			core.View{
				Class: "flex-row gap-3",
				Children: []core.Node{
					core.View{Class: "flex-1", Children: []core.Node{labeledField("First Name", draftInput(m, "editor-first-name", "Alice", func(d *EditDraft) string { return d.FirstName }, func(d *EditDraft, v string) { d.FirstName = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Last Name", draftInput(m, "editor-last-name", "Smith", func(d *EditDraft) string { return d.LastName }, func(d *EditDraft, v string) { d.LastName = v }))}},
				},
			},
			labeledField("Company", draftInput(m, "editor-company", "Company", func(d *EditDraft) string { return d.Company }, func(d *EditDraft, v string) { d.Company = v })),
			core.View{
				Class: "flex-row gap-3",
				Children: []core.Node{
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Email", draftInput(m, "editor-ident-email", "alice@example.com", func(d *EditDraft) string { return d.Email }, func(d *EditDraft, v string) { d.Email = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Phone", draftInput(m, "editor-ident-phone", "+1 555-0100", func(d *EditDraft) string { return d.Phone }, func(d *EditDraft, v string) { d.Phone = v }))}},
				},
			},
			labeledField("Address", draftInput(m, "editor-ident-addr", "123 Main St", func(d *EditDraft) string { return d.Address1 }, func(d *EditDraft, v string) { d.Address1 = v })),
			core.View{
				Class: "flex-row gap-3",
				Children: []core.Node{
					core.View{Class: "flex-1", Children: []core.Node{labeledField("City", draftInput(m, "editor-ident-city", "City", func(d *EditDraft) string { return d.City }, func(d *EditDraft, v string) { d.City = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("State", draftInput(m, "editor-ident-state", "State", func(d *EditDraft) string { return d.State }, func(d *EditDraft, v string) { d.State = v }))}},
					core.View{Class: "flex-1", Children: []core.Node{labeledField("Postal Code", draftInput(m, "editor-ident-postal", "94107", func(d *EditDraft) string { return d.PostalCode }, func(d *EditDraft, v string) { d.PostalCode = v }))}},
				},
			},
			labeledField("Country", draftInput(m, "editor-ident-country", "Country", func(d *EditDraft) string { return d.Country }, func(d *EditDraft, v string) { d.Country = v })),
		},
	}
}

func editorCustomFieldsSection(m *AppModel) core.Node {
	return core.View{
		Class: "gap-2",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center justify-between",
				Children: []core.Node{
					core.Text{Class: "text-xs font-medium text-neutral-600 dark:text-neutral-400", Content: "Custom Fields"},
					ui.Button{
						TestID:  "editor-add-field",
						Text:    "Add Field",
						Icon:    lucide.Plus,
						Variant: ui.ButtonGhost,
						Size:    ui.SizeSmall,
						OnPress: func() {
							m.MutateDraft(func(d *EditDraft) {
								d.Fields = append(d.Fields, EditFieldDraft{Type: 0})
							})
						},
					},
				},
			},
			core.Dynamic(func(cx *core.Scope) core.Node {
				d := m.EditDraft.Get()
				if d == nil {
					return nil
				}
				rows := make([]core.Node, 0, len(d.Fields))
				for i := range d.Fields {
					idx := i
					rows = append(rows, core.View{
						Class: "flex-row items-center gap-2",
						Children: []core.Node{
							ui.Select[int]{
								Style: core.Style{Width: core.Pt(92)},
								Options: []ui.Option[int]{
									{Value: 0, Label: "Text"},
									{Value: 1, Label: "Hidden"},
								},
								Value: func() int {
									cur := m.EditDraft.Get()
									if cur == nil || idx >= len(cur.Fields) {
										return 0
									}
									return cur.Fields[idx].Type
								},
								OnChange: func(t int) {
									m.MutateDraft(func(d *EditDraft) {
										if idx < len(d.Fields) {
											d.Fields[idx].Type = t
										}
									})
								},
							},
							base.Input{
								Class:       inputClass + " flex-1",
								Placeholder: "Field name",
								Value: func() string {
									cur := m.EditDraft.Get()
									if cur == nil || idx >= len(cur.Fields) {
										return ""
									}
									return cur.Fields[idx].Name
								},
								OnChange: func(v string) {
									m.MutateDraft(func(d *EditDraft) {
										if idx < len(d.Fields) {
											d.Fields[idx].Name = v
										}
									})
								},
							},
							base.Input{
								Class:       inputClass + " flex-1",
								Placeholder: "Value",
								Value: func() string {
									cur := m.EditDraft.Get()
									if cur == nil || idx >= len(cur.Fields) {
										return ""
									}
									return cur.Fields[idx].Value
								},
								OnChange: func(v string) {
									m.MutateDraft(func(d *EditDraft) {
										if idx < len(d.Fields) {
											d.Fields[idx].Value = v
										}
									})
								},
							},
							ui.Button{
								Icon:    lucide.X,
								Label:   "Remove field",
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() {
									m.MutateDraft(func(d *EditDraft) {
										if idx < len(d.Fields) {
											d.Fields = append(d.Fields[:idx], d.Fields[idx+1:]...)
										}
									})
								},
							},
						},
					})
				}
				return core.View{Class: "gap-2", Children: rows}
			}),
		},
	}
}

func draftInput(m *AppModel, testID, placeholder string, get func(*EditDraft) string, set func(*EditDraft, string)) core.Node {
	return base.Input{
		TestID:        testID,
		Class:         inputClass,
		Placeholder:   placeholder,
		NoAutoCorrect: true,
		Value: func() string {
			if d := m.EditDraft.Get(); d != nil {
				return get(d)
			}
			return ""
		},
		OnChange: func(v string) {
			m.MutateDraft(func(d *EditDraft) { set(d, v) })
		},
	}
}
