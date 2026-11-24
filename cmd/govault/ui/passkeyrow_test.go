package ui

import (
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/state"
)

// A login with a passkey shows the passkey icon, named for assistive
// technology, in its list row; others do not.
func TestListRowShowsPasskeys(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Login.Fido2Credentials = []state.Fido2Credential{{CredentialID: "cred", RpID: "github.com"}}
	app, _, _ := startSecurityApp(t, svc, PlatformHooks{})
	app.WaitFor("id:vault-row-passkey", 2*time.Second)
	if n := len(app.Query("id:vault-row-passkey")); n != 1 {
		t.Fatalf("%d rows show a passkey, want 1", n)
	}
	app.Find("label:Has a passkey")
}
