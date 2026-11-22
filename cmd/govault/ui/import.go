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
	"github.com/txchen/govault/cmd/govault/locales"
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
	m.openRepromptDialog(RepromptExportVault, func() {
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
		m.BackupError.Set(locales.BackupPasswordTooShort(cx, minBackupPasswordLength))
		return
	case pw != m.BackupPW2.Get():
		m.BackupError.Set(locales.BackupPasswordsDiffer(cx))
		return
	}
	backup := m.Core.BackupData()
	if n := len(backup.Unreadable); n > 0 {
		m.BackupError.Set(locales.BackupIncomplete(cx, n))
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
				m.BackupError.Set(m.errorText(err))
				return
			}
			m.CloseBackupDialog()
			name := "govault_encrypted_export_" + time.Now().Format("20060102150405") + ".json"
			m.chooseSavePath(cx, name, func(target saveTarget, err error) {
				if err != nil || target.dir == "" || !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					if err != nil {
						m.ShowToast(ui.ToastError, locales.ExportFailed(m.Scope), m.errorText(err))
					}
					return
				}
				go func() {
					_, published, err := m.savePrivateFile(gen, target, data)
					m.Scope.Post(func() {
						switch {
						case err != nil:
							m.ShowToast(ui.ToastError, locales.ExportFailed(m.Scope), m.errorText(err))
						case published:
							m.ShowToast(ui.ToastSuccess, locales.BackupSaved(m.Scope), locales.BackupSavedDetail(m.Scope))
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
	cx.PickFiles(core.PickFilesOptions{Title: locales.ImportBackupTitle(cx), Button: locales.ImportButton(cx), Types: []string{".json"}}, func(files []core.File, err error) {
		if err != nil {
			m.ShowToast(ui.ToastError, locales.CouldNotOpenFile(m.Scope), m.errorText(err))
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
					m.ShowToast(ui.ToastError, locales.ImportFailed(m.Scope), m.errorText(err))
					return
				}
				m.receiveBackup(f.Name, data)
			})
		}()
	})
}

// errBackupFileTooLarge means a picked backup is larger than GoVault reads.
var errBackupFileTooLarge = fmt.Errorf("the file is larger than %d MiB", export.MaxFileSize>>20)

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
		return nil, errBackupFileTooLarge
	}
	return data, nil
}

func (m *AppModel) receiveBackup(name string, data []byte) {
	needs, err := export.NeedsPassword(data)
	if err != nil {
		crypto.ZeroBytes(data)
		m.ShowToast(ui.ToastError, locales.ImportFailed(m.Scope), m.backupError(err))
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
		m.ShowToast(ui.ToastError, locales.ImportFailed(m.Scope), m.backupError(err))
		return
	}
	m.beginImportReview(name, v)
}

func (m *AppModel) confirmImportPassword() {
	pending := m.importPending
	pw := m.BackupPW.Get()
	if pending == nil || pw == "" {
		m.BackupError.Set(locales.BackupPasswordRequired(m.Scope))
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
				m.BackupError.Set(locales.IncorrectBackupPassword(m.Scope))
				return
			}
			m.CloseBackupDialog()
			if err != nil {
				m.ShowToast(ui.ToastError, locales.ImportFailed(m.Scope), m.backupError(err))
				return
			}
			m.beginImportReview(pending.name, v)
		})
	}()
}

func (m *AppModel) backupError(err error) string {
	if errors.Is(err, errBackupFileTooLarge) {
		return locales.BackupFileTooLarge(m.Scope, export.MaxFileSize>>20)
	}
	return m.errorText(err)
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
		m.openRepromptDialog(RepromptUpdateProtectedItem, func() {
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
			title := locales.ImportResult(m.Scope, res.Created, res.Updated)
			if res.LocalCopyErr != nil && res.Failed == 0 {
				m.ShowLocalCopyWarning(title)
				return
			}
			if res.Failed > 0 {
				m.ShowToast(ui.ToastWarning, title, locales.ImportSomeFailed(m.Scope, res.Failed, m.errorText(res.Err)))
				return
			}
			m.ShowToast(ui.ToastSuccess, title, locales.ImportSkipped(m.Scope, res.Skipped))
		})
	}()
}

func importActionLabel(cx *core.Scope, e *export.Entry, a export.Action) string {
	switch a {
	case export.ActionCreate:
		if e.Class == export.ClassNew {
			return locales.ImportCreate(cx)
		}
		return locales.ImportCreateCopy(cx)
	case export.ActionUpdate:
		return locales.ImportUpdate(cx)
	}
	return locales.ImportSkip(cx)
}

func diffFieldName(cx *core.Scope, f export.DiffField) string {
	switch f {
	case export.FieldName:
		return locales.DiffName(cx)
	case export.FieldNotes:
		return locales.DiffNotes(cx)
	case export.FieldFolder:
		return locales.DiffFolder(cx)
	case export.FieldFavorite:
		return locales.DiffFavorite(cx)
	case export.FieldReprompt:
		return locales.DiffReprompt(cx)
	case export.FieldUsername:
		return locales.DiffUsername(cx)
	case export.FieldPassword:
		return locales.DiffPassword(cx)
	case export.FieldTOTP:
		return locales.DiffTOTP(cx)
	case export.FieldWebsites:
		return locales.DiffWebsites(cx)
	case export.FieldPasskey:
		return locales.DiffPasskey(cx)
	case export.FieldCard:
		return locales.DiffCard(cx)
	case export.FieldIdentity:
		return locales.DiffIdentity(cx)
	case export.FieldSSHKey:
		return locales.DiffSSHKey(cx)
	case export.FieldCustomFields:
		return locales.DiffCustomFields(cx)
	}
	return string(f)
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
							core.Text{Class: "text-[13px] font-semibold text-gv-fg", Content: locales.NoImport(cx)},
							core.Text{Class: "text-[12px] text-gv-fg2", Content: locales.NoImportHint(cx)},
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
									core.Text{Class: "text-[17px] font-semibold text-gv-fg", Content: locales.ReviewImport(cx)},
									core.Text{
										TestID:  "import-summary",
										Class:   "text-[12.5px] text-gv-fg2",
										Content: locales.ImportSummary(cx, sess.FileName, c.New, c.Conflicts, c.Identical),
									},
								},
							},
							core.View{
								Class: "flex-row flex-wrap gap-2",
								Children: []core.Node{
									batch("import-all-new", locales.SelectAllNew(cx), func() { m.BatchImport(export.ClassNew, export.ActionCreate) }),
									batch("import-skip-conflicts", locales.SkipAllConflicts(cx), func() { m.BatchImport(export.ClassConflict, export.ActionSkip) }),
									batch("import-copy-conflicts", locales.CopyAllConflicts(cx), func() { m.BatchImport(export.ClassConflict, export.ActionCreate) }),
									batch("import-update-conflicts", locales.UpdateAllConflicts(cx), func() { m.BatchImport(export.ClassConflict, export.ActionUpdate) }),
									batch("import-skip-all", locales.SkipAll(cx), m.SkipAllImport),
								},
							},
						}
						group := func(class export.Class, title func(int) string) {
							var rows []core.Node
							for i := range p.Entries {
								if p.Entries[i].Class == class {
									rows = append(rows, importRow(m, p, i))
								}
							}
							if len(rows) > 0 {
								blocks = append(blocks, section(title(len(rows)), card(rows...)))
							}
						}
						group(export.ClassConflict, func(n int) string { return locales.ImportGroupChanged(cx, n) })
						group(export.ClassNew, func(n int) string { return locales.ImportGroupNew(cx, n) })
						if c.Identical > 0 {
							blocks = append(blocks, ui.Button{
								TestID:  "import-toggle-identical",
								Text:    identicalToggleLabel(cx, m.ImportShowIdentical.Get(), c.Identical),
								Variant: ui.ButtonGhost,
								Size:    ui.SizeSmall,
								OnPress: func() { m.ImportShowIdentical.Set(!m.ImportShowIdentical.Get()) },
							})
							if m.ImportShowIdentical.Get() {
								group(export.ClassIdentical, func(n int) string { return locales.ImportGroupIdentical(cx, n) })
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
						Text:     locales.Cancel(cx),
						Variant:  ui.ButtonSecondary,
						Disabled: m.ImportBusy.Get,
						OnPress:  m.CancelImport,
					},
					core.Dynamic(func(cx *core.Scope) core.Node {
						m.ImportRev.Get()
						c := sess.Plan.Counts()
						return ui.Button{
							TestID:   "import-apply",
							Text:     locales.ImportApply(cx, c.Create, c.Update, c.Skip),
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
	cx := m.Scope
	if c == nil || c.OrganizationID == nil || *c.OrganizationID == "" {
		return locales.PersonalVault(cx)
	}
	org := locales.AnOrganization(cx)
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
		return locales.SharedVaultOf(cx, org)
	}
	return locales.OrganizationCollections(cx, org, joinList(cols))
}

func identicalToggleLabel(cx *core.Scope, shown bool, n int) string {
	if shown {
		return locales.HideIdentical(cx, n)
	}
	return locales.ShowIdentical(cx, n)
}

func importRow(m *AppModel, p *export.Plan, i int) core.Node {
	cx := m.Scope
	e := &p.Entries[i]
	sub := CipherTypeLabel(cx, e.Item.Type)
	if e.Item.Login != nil && e.Item.Login.Username != nil && *e.Item.Login.Username != "" {
		sub = *e.Item.Login.Username
	}
	if e.FolderName != "" {
		sub += " · " + e.FolderName
	}
	var note string
	switch e.Class {
	case export.ClassConflict:
		fields := make([]string, len(e.Diff))
		for j, f := range e.Diff {
			fields[j] = diffFieldName(cx, f)
		}
		notes := []string{locales.ImportDiffers(cx, joinList(fields), m.importDestination(e.Match))}
		switch {
		case e.UpdateBlocked == export.UpdateBlockedIncomplete:
			notes = append(notes, locales.ImportCannotUpdateIncomplete(cx))
		case e.UpdateBlocked == export.UpdateBlockedUnmatchable:
			notes = append(notes, locales.ImportCannotUpdateUnmatchable(cx))
		case !e.CanUpdate:
			notes = append(notes, locales.ImportReadOnly(cx))
		case e.NeedsReprompt():
			notes = append(notes, locales.ImportProtected(cx))
		}
		note = strings.Join(notes, " · ")
	case export.ClassIdentical:
		note = locales.ImportAlreadyIn(cx, m.importDestination(e.Match))
	case export.ClassNew:
		switch {
		case e.Unsupported:
			note = locales.ImportUnsupported(cx)
		case e.Ambiguous:
			note = locales.ImportAmbiguous(cx)
		case e.Item.ArchivedDate != nil && !m.Core.CanArchive():
			note = locales.ImportArchivedNoPremium(cx)
		}
	}
	opts := make([]ui.Option[export.Action], 0, 3)
	for _, a := range e.Allowed() {
		opts = append(opts, ui.Option[export.Action]{Value: a, Label: importActionLabel(cx, e, a)})
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
