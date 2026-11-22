package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type BackupMode int

const (
	BackupNone BackupMode = iota
	BackupExport
	BackupImport
)

const minBackupPasswordLength = 8

// ImportSession is a decrypted backup under review. It holds secrets, so
// it lives only until the import is applied, cancelled or the vault locks.
type ImportSession struct {
	FileName string
	Plan     *export.Plan
}

// importPending is a picked backup file waiting for its password.
type importPending struct {
	name string
	data []byte
}

func (m *AppModel) clearBackupState() {
	m.backupOp++
	m.BackupDialog.Set(BackupNone)
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
	if m.importPending != nil {
		crypto.ZeroBytes(m.importPending.data)
		m.importPending = nil
	}
	m.ImportSession.Set(nil)
	m.ImportBusy.Set(false)
	m.ImportShowIdentical.Set(false)
}

// StartExport asks for the master password, then for a backup password.
func (m *AppModel) StartExport() {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	m.openRepromptDialog("export your vault", func() {
		if m.StillUnlocked(gen) {
			m.openBackupDialog(BackupExport)
		}
	})
}

func (m *AppModel) openBackupDialog(mode BackupMode) {
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
	m.BackupDialog.Set(mode)
}

func (m *AppModel) CloseBackupDialog() {
	m.backupOp++
	if m.BackupDialog.Get() == BackupImport && m.importPending != nil {
		crypto.ZeroBytes(m.importPending.data)
		m.importPending = nil
	}
	m.BackupDialog.Set(BackupNone)
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
	m.ReleaseSecureInput()
}

func (m *AppModel) ConfirmBackupDialog(cx *core.Scope) {
	if m.BackupBusy.Get() {
		return
	}
	switch m.BackupDialog.Get() {
	case BackupExport:
		m.confirmExport(cx)
	case BackupImport:
		m.confirmImportPassword()
	}
}

func (m *AppModel) confirmExport(cx *core.Scope) {
	pw := m.BackupPW.Get()
	switch {
	case len([]rune(pw)) < minBackupPasswordLength:
		m.BackupError.Set(fmt.Sprintf("Use at least %d characters.", minBackupPasswordLength))
		return
	case pw != m.BackupPW2.Get():
		m.BackupError.Set("The passwords do not match.")
		return
	}
	backup := m.Core.BackupData()
	if n := len(backup.Unreadable); n > 0 {
		m.BackupError.Set(fmt.Sprintf("%d personal item(s) are in a format GoVault cannot read, so the backup would be incomplete. Export from the Bitwarden web vault instead.", n))
		return
	}
	m.ReleaseSecureInput()
	m.BackupBusy.Set(true)
	m.BackupError.Set("")
	gen := m.LockGeneration()
	pwBytes := []byte(pw)
	ciphers, folders := backup.Ciphers, backup.Folders
	go func() {
		defer crypto.ZeroBytes(pwBytes)
		var data []byte
		v, err := export.Build(ciphers, folders)
		if err == nil {
			data, err = export.EncryptWithPassword(v, pwBytes, export.DefaultKDF)
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				crypto.ZeroBytes(data)
				return
			}
			m.BackupBusy.Set(false)
			if err != nil {
				m.BackupError.Set(err.Error())
				return
			}
			m.CloseBackupDialog()
			name := "govault_encrypted_export_" + time.Now().Format("20060102150405") + ".json"
			m.chooseSavePath(cx, name, func(target saveTarget, err error) {
				if err != nil || target.dir == "" || !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					if err != nil {
						m.ShowToast(ui.ToastError, "Export failed", err.Error())
					}
					return
				}
				go func() {
					_, published, err := m.savePrivateFile(gen, target, data)
					m.Scope.Post(func() {
						switch {
						case err != nil:
							m.ShowToast(ui.ToastError, "Export failed", err.Error())
						case published:
							m.ShowToast(ui.ToastSuccess, "Encrypted backup saved", "Keep the backup password safe; it cannot be recovered.")
						}
					})
				}()
			})
		})
	}()
}

// StartImport picks a Bitwarden JSON export. Nothing in the vault changes
// until the user approves items in the review.
func (m *AppModel) StartImport(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	cx.PickFiles(core.PickFilesOptions{Title: "Import Backup", Button: "Import", Types: []string{".json"}}, func(files []core.File, err error) {
		if err != nil {
			m.ShowToast(ui.ToastError, "Could not open file", err.Error())
			return
		}
		if len(files) == 0 {
			return
		}
		f := files[0]
		go func() {
			data, err := readBackupFile(f)
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					return
				}
				if err != nil {
					m.ShowToast(ui.ToastError, "Import failed", err.Error())
					return
				}
				m.receiveBackup(f.Name, data)
			})
		}()
	})
}

func readBackupFile(f core.File) ([]byte, error) {
	if f.Temporary && f.Path != "" {
		defer os.Remove(f.Path)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, export.MaxFileSize+1))
	if err != nil {
		crypto.ZeroBytes(data)
		return nil, err
	}
	if len(data) > export.MaxFileSize {
		crypto.ZeroBytes(data)
		return nil, fmt.Errorf("the file is larger than %d MiB", export.MaxFileSize>>20)
	}
	return data, nil
}

func (m *AppModel) receiveBackup(name string, data []byte) {
	needs, err := export.NeedsPassword(data)
	if err != nil {
		crypto.ZeroBytes(data)
		m.ShowToast(ui.ToastError, "Import failed", backupError(err))
		return
	}
	if needs {
		m.importPending = &importPending{name: name, data: data}
		m.openBackupDialog(BackupImport)
		return
	}
	v, err := export.Read(data, nil)
	crypto.ZeroBytes(data)
	if err != nil {
		m.ShowToast(ui.ToastError, "Import failed", backupError(err))
		return
	}
	m.beginImportReview(name, v)
}

func (m *AppModel) confirmImportPassword() {
	pending := m.importPending
	pw := m.BackupPW.Get()
	if pending == nil || pw == "" {
		m.BackupError.Set("Enter the backup password.")
		return
	}
	m.ReleaseSecureInput()
	m.BackupBusy.Set(true)
	m.BackupError.Set("")
	gen := m.LockGeneration()
	m.backupOp++
	op := m.backupOp
	pwBytes := []byte(pw)
	// The worker reads its own copy: Cancel and lock zero pending.data.
	data := bytes.Clone(pending.data)
	go func() {
		defer crypto.ZeroBytes(pwBytes)
		defer crypto.ZeroBytes(data)
		v, err := export.Read(data, pwBytes)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) || op != m.backupOp || m.importPending != pending {
				return
			}
			m.BackupBusy.Set(false)
			if errors.Is(err, export.ErrWrongPassword) {
				m.BackupError.Set("Incorrect backup password.")
				return
			}
			m.CloseBackupDialog()
			if err != nil {
				m.ShowToast(ui.ToastError, "Import failed", backupError(err))
				return
			}
			m.beginImportReview(pending.name, v)
		})
	}()
}

func backupError(err error) string {
	switch {
	case errors.Is(err, export.ErrNotBitwardenExport):
		return "This is not a Bitwarden JSON export."
	case errors.Is(err, export.ErrAccountRestricted):
		return "This backup is locked to its account. Export it again as a password-protected file."
	}
	return friendlyError(err)
}

func (m *AppModel) beginImportReview(name string, v *export.Vault) {
	current := m.Core.AllCiphers()
	for _, c := range current {
		c.ReadOnly = c.ReadOnly || m.CipherReadOnly(c)
		c.HidePassword = c.HidePassword || m.PasswordHidden(c)
	}
	plan := export.BuildPlan(v, current, m.Core.Folders())
	m.ImportShowIdentical.Set(false)
	m.ImportSession.Set(&ImportSession{FileName: name, Plan: plan})
	m.Route.Set(RouteImport)
}

// mutateImport changes the plan and redraws the review.
func (m *AppModel) mutateImport(fn func(p *export.Plan)) {
	sess := m.ImportSession.Get()
	if sess == nil || m.ImportBusy.Get() {
		return
	}
	m.ResetIdleTimer()
	fn(sess.Plan)
	m.ImportRev.Set(m.ImportRev.GetUntracked() + 1)
}

func (m *AppModel) SetImportAction(i int, a export.Action) {
	sess := m.ImportSession.Get()
	if sess == nil || i < 0 || i >= len(sess.Plan.Entries) {
		return
	}
	if e := &sess.Plan.Entries[i]; a == export.ActionUpdate && e.NeedsReprompt() && slices.Contains(e.Allowed(), a) {
		gen := m.LockGeneration()
		m.openRepromptDialog("update a protected item", func() {
			if m.StillUnlocked(gen) && m.ImportSession.Get() == sess {
				m.mutateImport(func(*export.Plan) {
					e.ApproveReprompt()
					e.SetAction(a)
				})
			}
		})
		m.ImportRev.Set(m.ImportRev.GetUntracked() + 1)
		return
	}
	m.mutateImport(func(p *export.Plan) { p.Entries[i].SetAction(a) })
}

// BatchImport sets action a on every entry of class, where allowed.
func (m *AppModel) BatchImport(class export.Class, a export.Action) {
	m.mutateImport(func(p *export.Plan) {
		for i := range p.Entries {
			if p.Entries[i].Class == class {
				p.Entries[i].SetAction(a)
			}
		}
	})
}

func (m *AppModel) SkipAllImport() {
	m.mutateImport(func(p *export.Plan) {
		for i := range p.Entries {
			p.Entries[i].SetAction(export.ActionSkip)
		}
	})
}

func (m *AppModel) CancelImport() {
	if m.ImportBusy.Get() {
		return
	}
	m.ImportSession.Set(nil)
	m.Route.Set(RouteVault)
}

func (m *AppModel) ApplyImport() {
	sess := m.ImportSession.Get()
	if sess == nil || m.ImportBusy.Get() || m.SyncState.Get() == SyncOffline {
		return
	}
	if c := sess.Plan.Counts(); c.Create+c.Update == 0 {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ImportBusy.Set(true)
	gen := m.LockGeneration()
	go func() {
		defer cancel()
		res := export.Apply(ctx, m.Core, sess.Plan)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.ImportBusy.Set(false)
			m.ImportSession.Set(nil)
			m.Route.Set(RouteVault)
			m.RefreshVaultData()
			title := fmt.Sprintf("Imported: %d created, %d updated", res.Created, res.Updated)
			if res.LocalCopyErr != nil && res.Failed == 0 {
				m.ShowLocalCopyWarning(title)
				return
			}
			if res.Failed > 0 {
				m.ShowToast(ui.ToastWarning, title, fmt.Sprintf("%d item(s) failed: %s", res.Failed, friendlyError(res.Err)))
				return
			}
			m.ShowToast(ui.ToastSuccess, title, fmt.Sprintf("%d skipped", res.Skipped))
		})
	}()
}

func importActionLabel(e *export.Entry, a export.Action) string {
	switch a {
	case export.ActionCreate:
		if e.Class == export.ClassNew {
			return "Create"
		}
		return "Create Copy"
	case export.ActionUpdate:
		return "Update Existing"
	}
	return "Skip"
}

func ImportView(cx *core.Scope, m *AppModel) core.Node {
	return core.View{
		TestID: "import-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				sess := m.ImportSession.Get()
				if sess == nil {
					return core.View{
						Class: "flex-1 items-center justify-center gap-2",
						Children: []core.Node{
							core.Text{Class: "text-[13px] font-semibold text-gv-fg", Content: "No Import in Progress"},
							core.Text{Class: "text-[12px] text-gv-fg2", Content: "Choose Import Backup in Settings to review a backup."},
						},
					}
				}
				return importReview(cx, m, sess)
			}),
		},
	}
}

func importReview(cx *core.Scope, m *AppModel, sess *ImportSession) core.Node {
	batch := func(testID, label string, onPress func()) core.Node {
		return ui.Button{TestID: testID, Text: label, Variant: ui.ButtonSecondary, Size: ui.SizeSmall, OnPress: onPress}
	}
	return core.View{
		Class: "flex-1",
		Children: []core.Node{
			core.Scroll{
				Class: "flex-1",
				Children: []core.Node{
					core.Dynamic(func(cx *core.Scope) core.Node {
						m.ImportRev.Get()
						p := sess.Plan
						c := p.Counts()
						blocks := []core.Node{
							core.View{
								Class: "gap-1",
								Children: []core.Node{
									core.Text{Class: "text-[17px] font-semibold text-gv-fg", Content: "Review Import"},
									core.Text{
										TestID:  "import-summary",
										Class:   "text-[12.5px] text-gv-fg2",
										Content: fmt.Sprintf("%s · %d new, %d changed, %d identical. Nothing changes until you apply.", sess.FileName, c.New, c.Conflicts, c.Identical),
									},
								},
							},
							core.View{
								Class: "flex-row flex-wrap gap-2",
								Children: []core.Node{
									batch("import-all-new", "Select All New", func() { m.BatchImport(export.ClassNew, export.ActionCreate) }),
									batch("import-skip-conflicts", "Skip All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionSkip) }),
									batch("import-copy-conflicts", "Copy All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionCreate) }),
									batch("import-update-conflicts", "Update All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionUpdate) }),
									batch("import-skip-all", "Skip All", m.SkipAllImport),
								},
							},
						}
						group := func(class export.Class, title string) {
							var rows []core.Node
							for i := range p.Entries {
								if p.Entries[i].Class == class {
									rows = append(rows, importRow(m, p, i))
								}
							}
							if len(rows) > 0 {
								blocks = append(blocks, section(fmt.Sprintf("%s (%d)", title, len(rows)), card(rows...)))
							}
						}
						group(export.ClassConflict, "Changed")
						group(export.ClassNew, "New")
						if c.Identical > 0 {
							blocks = append(blocks, ui.Button{
								TestID:  "import-toggle-identical",
								Text:    identicalToggleLabel(m.ImportShowIdentical.Get(), c.Identical),
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() { m.ImportShowIdentical.Set(!m.ImportShowIdentical.Get()) },
							})
							if m.ImportShowIdentical.Get() {
								group(export.ClassIdentical, "Identical")
							}
						}
						return core.View{Class: "w-full max-w-[760px] self-center px-7 pt-6 pb-8 gap-4", Children: blocks}
					}),
				},
			},
			core.View{
				Class: "flex-row items-center justify-end gap-2 px-7 h-[56px] border-t border-gv-line bg-gv-list",
				Children: []core.Node{
					ui.Button{
						TestID:   "import-cancel",
						Text:     "Cancel",
						Variant:  ui.ButtonSecondary,
						Disabled: m.ImportBusy.Get,
						OnPress:  m.CancelImport,
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						m.ImportRev.Get()
						c := sess.Plan.Counts()
						return ui.Button{
							TestID:   "import-apply",
							Text:     fmt.Sprintf("Apply: %d create, %d update, %d skipped", c.Create, c.Update, c.Skip),
							Icon:     lucide.Check,
							Variant:  ui.ButtonPrimary,
							Busy:     m.ImportBusy.Get,
							Disabled: func() bool { return c.Create+c.Update == 0 || m.SyncState.Get() == SyncOffline },
							OnPress:  m.ApplyImport,
						}
					}),
				},
			},
		},
	}
}

// importDestination names where a matched vault item lives: the personal
// vault, or an organization and its collections.
func (m *AppModel) importDestination(c *state.Cipher) string {
	if c == nil || c.OrganizationID == nil || *c.OrganizationID == "" {
		return "your personal vault"
	}
	org := "an organization"
	for _, o := range m.Core.Organizations() {
		if o.ID == *c.OrganizationID {
			org = o.Name
		}
	}
	var cols []string
	for _, col := range m.Core.Collections() {
		if slices.Contains(c.CollectionIDs, col.ID) {
			cols = append(cols, col.Name)
		}
	}
	if len(cols) == 0 {
		return "the shared vault of " + org
	}
	return org + " · " + strings.Join(cols, ", ")
}

func identicalToggleLabel(shown bool, n int) string {
	if shown {
		return fmt.Sprintf("Hide %d identical items", n)
	}
	return fmt.Sprintf("Show %d identical items", n)
}

func importRow(m *AppModel, p *export.Plan, i int) core.Node {
	e := &p.Entries[i]
	sub := CipherTypeLabel(e.Item.Type)
	if e.Item.Login != nil && e.Item.Login.Username != nil && *e.Item.Login.Username != "" {
		sub = *e.Item.Login.Username
	}
	if e.FolderName != "" {
		sub += " · " + e.FolderName
	}
	var note string
	switch e.Class {
	case export.ClassConflict:
		note = "Differs: " + strings.Join(e.Diff, ", ") + " · in " + m.importDestination(e.Match)
		switch {
		case e.UpdateBlocked != "":
			note += " · cannot update: " + e.UpdateBlocked
		case !e.CanUpdate:
			note += " · existing item is read-only"
		case e.NeedsReprompt():
			note += " · protected: Update asks for your master password"
		}
	case export.ClassIdentical:
		note = "Already in " + m.importDestination(e.Match)
	case export.ClassNew:
		switch {
		case e.Unsupported:
			note = "GoVault cannot save this type of item yet, so it is skipped."
		case e.Ambiguous:
			note = "Several vault items have this name, so it is not matched to any. Choose Create to add it as a new item."
		case e.Item.ArchivedDate != nil && !m.Core.CanArchive():
			note = "Archived in the backup; it is created in your vault, since Archive needs a premium membership."
		}
	}
	opts := make([]ui.Option[export.Action], 0, 3)
	for _, a := range e.Allowed() {
		opts = append(opts, ui.Option[export.Action]{Value: a, Label: importActionLabel(e, a)})
	}
	texts := []core.Node{
		core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: e.Item.Name},
		core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: sub},
	}
	if note != "" {
		texts = append(texts, core.Text{TestID: fmt.Sprintf("import-note-%d", i), MaxLines: 2, Class: "text-[11.5px] text-gv-warn", Content: note})
	}
	return core.View{
		TestID: "import-row",
		Class:  "flex-row items-center gap-3 pl-3.5 pr-3 py-2 min-h-[52px]",
		Children: []core.Node{
			itemEmblem(e.Item.Name, e.Item.Type, "", 28),
			core.View{Class: "flex-1 gap-[2px] overflow-hidden", Children: texts},
			ui.Select[export.Action]{
				TestID:  fmt.Sprintf("import-action-%d", i),
				Style:   core.Style{Width: core.Pt(150)},
				Options: opts,
				Value: func() export.Action {
					m.ImportRev.Get()
					return p.Entries[i].Action
				},
				OnChange: func(a export.Action) { m.SetImportAction(i, a) },
			},
		},
	}
}
