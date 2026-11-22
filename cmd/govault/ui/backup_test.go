package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestCloneCreatesPersonalCopy(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	org := "org-1"
	gh := svc.ciphers["c-github"]
	gh.OrganizationID = &org
	gh.CollectionIDs = []string{"col-1"}
	gh.Attachments = []state.Attachment{{ID: "att-1", FileName: "a.txt"}}
	gh.PasswordHistory = []state.PasswordHistoryEntry{{Password: "older"}}
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-clone", 2*time.Second)
	app.Press("id:detail-clone")
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	d := m.EditDraft.Get()
	if !d.IsNew || d.ID != "" || d.Name != "GitHub (Copy)" || d.Password != "gh-secret-password" {
		t.Fatalf("clone draft = %+v", d)
	}
	app.Press("id:editor-save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })

	cp, err := svc.GetCipher("c-new")
	if err != nil || cp.Name != "GitHub (Copy)" || cp.OrganizationID != nil || cp.CollectionIDs != nil || cp.Attachments != nil || cp.PasswordHistory != nil || cp.Login.Password != "gh-secret-password" {
		t.Fatalf("clone = %+v, %v", cp, err)
	}
	if orig, _ := svc.GetCipher("c-github"); orig.Name != "GitHub" || orig.OrganizationID == nil {
		t.Fatal("clone changed the original")
	}
}

func TestEmptyTrashConfirmsAndKeepsReadOnly(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	now := time.Now()
	for _, c := range []*state.Cipher{
		{ID: "t-1", Type: api.CipherTypeSecureNote, Name: "Old", DeletedDate: &now, SecureNote: &state.SecureNote{}},
		{ID: "t-ro", Type: api.CipherTypeSecureNote, Name: "Shared Old", DeletedDate: &now, ReadOnly: true, SecureNote: &state.SecureNote{}},
	} {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	answers := []int{0, 1}
	app.OnAlert = func(core.AlertConfig) int { a := answers[0]; answers = answers[1:]; return a }

	app.Press("id:sidebar-trash")
	app.WaitFor("id:trash-empty", 2*time.Second)
	app.Press("id:trash-empty")
	app.Settle()
	if _, err := svc.GetCipher("t-1"); err != nil {
		t.Fatal("trash emptied without confirmation")
	}
	app.Press("id:trash-empty")
	app.WaitUntil(2*time.Second, func() bool { _, err := svc.GetCipher("t-1"); return err != nil })
	if _, err := svc.GetCipher("t-ro"); err != nil {
		t.Fatal("read-only trashed item was deleted")
	}
	app.WaitForGone("id:trash-empty", 2*time.Second)
	_ = m
}

func writeBackup(t *testing.T, dir, name string, v *export.Vault, password string) string {
	t.Helper()
	var data []byte
	var err error
	if password == "" {
		data, err = json.Marshal(v)
	} else {
		data, err = export.EncryptWithPassword(v, []byte(password), crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000})
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportReviewLeavesConflictsUntilApproved(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	changed := *svc.ciphers["c-github"]
	login := *changed.Login
	login.Password = "backup-password-value"
	changed.Login = &login
	fresh := &state.Cipher{ID: "b-new", Type: api.CipherTypeLogin, Name: "Brand New", Login: &state.Login{Username: "n", Password: "pw"}}
	backup, _ := export.Build([]*state.Cipher{&changed, fresh}, nil)

	dir := t.TempDir()
	plain := writeBackup(t, dir, "plain.json", backup, "")
	encrypted := writeBackup(t, dir, "encrypted.json", backup, "correct horse")
	pick := plain
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.PickFiles = func(core.FilesRequest) []core.File {
		return []core.File{{Name: filepath.Base(pick), Path: pick}}
	}

	app.Post(func() { m.StartImport(m.Scope) })
	app.WaitFor("id:import-view", 2*time.Second)
	p := m.ImportSession.Get().Plan
	byName := map[string]export.Entry{}
	for _, e := range p.Entries {
		byName[e.Item.Name] = e
	}
	if e := byName["GitHub"]; e.Class != export.ClassConflict || e.Action != export.ActionSkip {
		t.Fatalf("conflict defaults: %+v", e)
	}
	if e := byName["Brand New"]; e.Class != export.ClassNew || e.Action != export.ActionCreate {
		t.Fatalf("new defaults: %+v", e)
	}
	app.Find("id:import-view >> text:Differs: Password")
	app.Find("id:import-apply >> text:Apply: 1 create, 0 update, 1 skipped")
	app.Press("id:import-apply")
	app.WaitUntil(2*time.Second, func() bool { return m.ImportSession.Get() == nil })
	if c, _ := svc.GetCipher("c-github"); c.Login.Password != "gh-secret-password" {
		t.Fatal("conflict overwritten without approval")
	}
	if c, err := svc.GetCipher("c-new"); err != nil || c.Name != "Brand New" {
		t.Fatalf("new item not created: %+v, %v", c, err)
	}

	pick = encrypted
	app.Post(func() { m.StartImport(m.Scope) })
	app.WaitUntil(2*time.Second, func() bool { return m.BackupDialog.Get() == BackupImport })
	app.Post(func() { m.BackupPW.Set("wrong password"); m.ConfirmBackupDialog(m.Scope) })
	app.WaitUntil(5*time.Second, func() bool { return m.BackupError.Get() != "" })
	app.Post(func() { m.BackupPW.Set("correct horse"); m.ConfirmBackupDialog(m.Scope) })
	app.WaitFor("id:import-view", 5*time.Second)
	app.Press("id:import-skip-all")
	app.Press("id:import-update-conflicts")
	app.Find("id:import-apply >> text:Apply: 0 create, 1 update, 1 skipped")
	app.Press("id:import-apply")
	app.WaitUntil(2*time.Second, func() bool { return m.ImportSession.Get() == nil })
	if c, _ := svc.GetCipher("c-github"); c.Login.Password != "backup-password-value" || c.ID != "c-github" {
		t.Fatalf("approved update not applied: %+v", c.Login)
	}
	if _, err := svc.GetCipher("c-new-2"); err == nil {
		t.Fatal("skipped item was created")
	}
}

func TestExportEncryptedBackup(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	dest := filepath.Join(t.TempDir(), "backup.json")
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{
		ChooseSavePath: func(_ string, done func(string, bool, error)) { done(dest, true, nil) },
	})

	app.Post(m.StartExport)
	verifyReprompt(app, m)
	app.WaitUntil(2*time.Second, func() bool { return m.BackupDialog.Get() == BackupExport })
	app.Post(func() {
		m.BackupPW.Set("long backup pass")
		m.BackupPW2.Set("different")
		m.ConfirmBackupDialog(m.Scope)
	})
	app.WaitUntil(2*time.Second, func() bool { return m.BackupError.Get() != "" })
	app.Post(func() { m.BackupPW2.Set("long backup pass"); m.ConfirmBackupDialog(m.Scope) })
	app.WaitUntil(10*time.Second, func() bool { _, err := os.Stat(dest); return err == nil })

	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(dest)
	v, err := export.Read(data, []byte("long backup pass"))
	if err != nil || len(v.Items) != 2 {
		t.Fatalf("exported backup = (%v, %v)", v, err)
	}
}
