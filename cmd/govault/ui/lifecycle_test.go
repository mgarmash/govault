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
