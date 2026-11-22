package ui

import (
	"github.com/nsgo-dev/nsgo/core"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestServerLogoutClearsTheUnlockedUI(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.AccountID = "acct-1"; p.BiometricEnabled = true; return p })
		m.StartCreateCipher(root)
		m.MutateDraft(func(d *EditDraft) { d.Name = "Secret draft"; d.Password = "typed secret" })
		m.openBackupDialog(BackupExport)
	})
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() && m.BackupDialog.Get() == BackupExport })
	gen := m.LockGeneration()

	svc.mu.Lock()
	svc.status = state.StatusLoggedOut
	svc.mu.Unlock()
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLoggedOut) })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusLoggedOut })

	if m.EditDraft.Get() != nil || m.EditMode.Get() || m.BackupDialog.Get() != BackupNone {
		t.Fatal("a draft or dialog survived the server logout")
	}
	if p := m.Prefs.Get(); p.AccountID != "" || p.BiometricEnabled {
		t.Fatalf("account settings survived the server logout: %+v", p)
	}
	if m.StillUnlocked(gen) || m.LockGeneration() == gen {
		t.Fatal("pending actions were not revoked")
	}
}

func TestSleepDuringUnlockRevokesIt(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	var gen uint64
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LockBusy.Set(true)
		gen = m.LockGeneration()
		m.LockOnSystemEvent()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.LockBusy.Get() })
	if m.LockGeneration() == gen {
		t.Fatal("a sleep during unlock did not revoke the attempt")
	}
}

func TestDeviceIDExistsBeforeTheServiceStarts(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	var first, again string
	app.Post(func() {
		first = m.Prefs.Get().DeviceID
		again = EnsureDeviceID(m.Prefs).DeviceID
	})
	app.WaitUntil(2*time.Second, func() bool { return first != "" })
	if again != first {
		t.Fatalf("device id changed: %q then %q", first, again)
	}
}

func TestSleepDuringSignInRevokesTheAttempt(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.LockOnSleep = true; return p })
		m.LoginBusy.Set(true)
		m.LockOnSystemEvent()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.LoginBusy.Get() })
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.revokes != 1 {
		t.Fatalf("revokes = %d, want the sign-in revoked", svc.revokes)
	}
}

func TestLocalOnlyVaultAsksToSignInAgainAndKeepsTheCache(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.Post(func() { m.SyncState.Set(SyncAuthExpired) })
	app.WaitFor("id:signin-banner", 2*time.Second)
	app.Find("text:Sign in again to sync. Your vault is available offline until then.")
	app.Press("id:signin-banner-action")
	app.WaitFor("id:login-server", 2*time.Second)
	if !m.ReSignIn.Get() || svc.Status() != state.StatusLocked {
		t.Fatalf("sign in again: resignin %v, status %v", m.ReSignIn.Get(), svc.Status())
	}
	if _, err := svc.GetCipher("c-github"); err == nil {
		t.Fatal("locked vault still readable")
	}
	svc.mu.RLock()
	n := len(svc.ciphers)
	svc.mu.RUnlock()
	if n == 0 {
		t.Fatal("signing in again removed the local vault")
	}
}

func TestUnsavedCredentialsShowABanner(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.credsUnsaved = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.WaitFor("id:signin-banner", 2*time.Second)
	app.Find("text:Your sign-in could not be saved. Sign in again so GoVault can still sync after you lock.")
}

func TestSnapshotMetadataNeverSetsTheServer(t *testing.T) {
	svc := newMockVaultService(state.StatusLocked)
	hooks := PlatformHooks{DiscoverSnapshot: func(string) *AccountSnapshotMeta {
		return &AccountSnapshotMeta{AccountID: "acct-1", ServerURL: "https://attacker.example", Email: "a@b.c"}
	}}
	app, m, _ := startSecurityApp(t, svc, hooks)
	app.Post(func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.ServerURL = "https://vault.example"; return p })
		m.SyncAccountMetaFromSnapshot()
	})
	app.WaitUntil(2*time.Second, func() bool { return m.Prefs.Get().AccountID == "acct-1" })
	if got := m.Prefs.Get().ServerURL; got != "https://vault.example" {
		t.Fatalf("server in settings = %q, want the one the user signed in to", got)
	}
}

func TestSessionExitClearsDialogsAndTheGeneratedPassword(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() {
		m.FolderDialog.Set(FolderModal{Open: true, FolderID: "f-1", Name: "Secret project"})
		m.GenResult.Set("generated-secret")
	})
	app.WaitFor("id:folder-name-input", 2*time.Second)

	svc.mu.Lock()
	svc.status = state.StatusLoggedOut
	svc.mu.Unlock()
	app.Post(func() { m.ServiceLeftUnlocked(state.StatusLoggedOut) })
	app.WaitForGone("id:folder-name-input", 2*time.Second)
	if m.FolderDialog.Get().Open || m.FolderDialog.Get().Name != "" || m.GenResult.Get() != "" {
		t.Fatalf("after logout: folder dialog %+v, generated %q", m.FolderDialog.Get(), m.GenResult.Get())
	}

	// A dialog opened while locked is never mounted.
	app.Post(func() { m.FolderDialog.Set(FolderModal{Open: true, Name: "x"}) })
	app.Settle()
	if app.Exists("id:folder-name-input") {
		t.Fatal("a vault dialog is shown over the sign-in screen")
	}
}

func TestLateSaveLeavesANewerDraftAlone(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	gate := make(chan struct{})
	svc.saveGate = gate
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "First" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	// While it saves, the user discards the editor and starts another item.
	app.Post(func() { m.EditMode.Set(false); m.EditDraft.Set(nil); m.EditDirty.Set(false) })
	app.Post(func() { m.StartCreateCipher(root) })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "Second" }) })
	app.WaitUntil(2*time.Second, func() bool { d := m.EditDraft.Get(); return d != nil && d.Name == "Second" })
	close(gate)
	app.WaitUntil(2*time.Second, func() bool { return !m.EditBusy.Get() })
	app.Settle()
	if d := m.EditDraft.Get(); d == nil || d.Name != "Second" || !m.EditMode.Get() {
		t.Fatalf("the newer draft was replaced: %+v", d)
	}
}

func TestLockDuringSaveClearsBusy(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.saveGate = make(chan struct{})
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.StartCreateCipher(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	app.Post(func() { m.MutateDraft(func(d *EditDraft) { d.Name = "x" }); m.SaveDraft(root) })
	app.WaitUntil(2*time.Second, func() bool { return m.EditBusy.Get() })
	app.Post(m.Lock)
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusLocked })
	if m.EditBusy.Get() {
		t.Fatal("EditBusy survived the lock and would block every later save")
	}
	close(svc.saveGate)
}

func TestSignInAgainCanGoBackToUnlockLocalOnly(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.localOnly = true
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(m.RefreshVaultData)
	app.Post(func() { m.SyncState.Set(SyncAuthExpired) })
	app.WaitFor("id:signin-banner-action", 2*time.Second)
	app.Press("id:signin-banner-action")
	app.WaitFor("id:login-back-to-unlock", 2*time.Second)

	app.Press("id:login-back-to-unlock")
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.ReSignIn.Get() || app.Exists("id:login-screen") {
		t.Fatal("still on the sign-in form")
	}
	app.Post(func() { m.LockPassword.Set("master-password"); m.UnlockWithPassword() })
	app.WaitUntil(2*time.Second, func() bool { return m.LockState.Get() == state.StatusUnlocked })
	if c, err := svc.GetCipher("c-github"); err != nil || c.Name != "GitHub" {
		t.Fatalf("local vault after going back: %+v, %v", c, err)
	}
}

func TestFirstSignInHasNoWayBackToUnlock(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	app, _, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.WaitFor("id:login-submit", 2*time.Second)
	if app.Exists("id:login-back-to-unlock") {
		t.Fatal("a first sign-in offers Back to Unlock")
	}
}
