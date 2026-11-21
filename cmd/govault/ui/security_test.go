package ui

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func startSecurityApp(t *testing.T, svc *mockVaultService, hooks PlatformHooks) (*nsgotest.App, *AppModel, *core.Scope) {
	t.Helper()
	var model *AppModel
	var root *core.Scope
	hooks.VerifyMasterPassword = func([]byte) error { return nil }
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		root = cx
		model = NewAppModel(cx, svc, hooks)
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))
	return app, model, root
}

func verifyReprompt(app *nsgotest.App, m *AppModel) {
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	app.Post(func() {
		m.RepromptPW.Set("master-password")
		m.SubmitReprompt()
	})
	app.WaitUntil(2*time.Second, func() bool { return !m.Reprompt.Get().Open })
}

func TestRepromptGatesEditAndTOTP(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-totp-section", 2*time.Second)
	app.WaitUntil(2*time.Second, func() bool { return m.TOTPCode.Get() != "" })
	code := m.TOTPCode.Get()
	if app.Exists("id:detail-totp-section >> text:" + FormatTOTPCode(code)) {
		t.Fatal("live TOTP code shown before reprompt")
	}
	app.Find("id:detail-totp-section >> text:••• •••")

	app.Press("id:detail-reveal-totp")
	verifyReprompt(app, m)
	app.WaitUntil(2*time.Second, func() bool { return m.RevealTOTP.Get() })

	app.Press("id:detail-edit")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	if m.EditMode.Get() || m.EditDraft.Get() != nil {
		t.Fatal("edit draft built before reprompt")
	}
	verifyReprompt(app, m)
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() && m.EditDraft.Get() != nil })
}

func TestLockRevokesPendingSecretActions(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Reprompt = 1
	svc.ciphers["c-github"].Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt"}}
	var copies atomic.Int32
	app, m, root := startSecurityApp(t, svc, PlatformHooks{
		CopySecret: func(string, time.Duration) (bool, error) { copies.Add(1); return true, nil },
	})
	app.SaveFile = func(core.SaveRequest) string { return t.TempDir() + "/codes.txt" }

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-copy-pw", 2*time.Second)
	app.Press("id:detail-copy-pw")
	app.WaitUntil(2*time.Second, func() bool { return m.Reprompt.Get().Open })
	allow := m.Reprompt.Get().OnAllow
	app.Post(m.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	if m.Reprompt.Get().Open {
		t.Fatal("reprompt dialog survived lock")
	}
	app.Post(allow)
	app.Post(func() {})
	if copies.Load() != 0 {
		t.Fatal("secret copied after lock")
	}

	svc.mu.Lock()
	svc.status = state.StatusUnlocked
	svc.ciphers["c-github"].Reprompt = 0
	svc.downloadGate = make(chan struct{})
	svc.mu.Unlock()
	app.Post(func() {
		m.LockState.Set(state.StatusUnlocked)
		m.RefreshVaultData()
		m.SelectCipher(root, "c-github")
	})
	app.WaitFor("id:detail-attachment-download-0", 2*time.Second)
	app.Press("id:detail-attachment-download-0")
	app.WaitUntil(2*time.Second, func() bool { return m.AttachmentBusy.Get() == "att-1" })
	app.Post(m.Lock)
	close(svc.downloadGate)
	time.Sleep(50 * time.Millisecond)
	app.Post(func() {})
	if len(app.Saves) != 0 {
		t.Fatalf("save dialog opened after lock: %d", len(app.Saves))
	}
}

func TestHiddenPasswordsHideAttachmentAndHiddenFields(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	c := svc.ciphers["c-github"]
	c.HidePassword = true
	c.Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt"}}
	c.Fields = []state.CustomField{{Name: "Recovery", Value: "hidden-recovery-value", Type: 1}}
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-view >> text:codes.txt", 2*time.Second)
	if app.Exists("id:detail-attachment-download-0") {
		t.Fatal("download offered for an item with hidden passwords")
	}
	app.Find("id:detail-view >> text:Recovery")
	if app.Exists("id:detail-field-0-reveal") || app.Exists("id:detail-field-0-copy") || !app.Exists("id:detail-field-0") {
		t.Fatal("hidden custom field can be revealed or copied")
	}
}
