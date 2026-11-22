package ui

import (
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
