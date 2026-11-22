package ui

import (
	"slices"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// testYubiKeyOTP has the shape of a Yubico OTP: 44 modhex characters.
const testYubiKeyOTP = "ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded"

func startTwoFactor(t *testing.T, svc *mockVaultService, releases *[]bool) *nsgotest.App {
	t.Helper()
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, svc, PlatformHooks{ReleaseSecureInput: func(force bool) {
			if releases != nil {
				*releases = append(*releases, force)
			}
		}})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))
	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:twofactor-screen", 2*time.Second)
	return app
}

func yubiKeyService() *mockVaultService {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = testYubiKeyOTP
	svc.twoFactorProvider = api.TwoFactorYubiKey
	svc.twoFactorOffered = []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail, api.TwoFactorYubiKey}
	return svc
}

func TestYubiKeyOTPSubmitsOnEnter(t *testing.T) {
	svc := yubiKeyService()
	var releases []bool
	app := startTwoFactor(t, svc, &releases)

	// YubiKey is the preferred method when offered, as in Bitwarden.
	app.Find("id:twofactor-provider-yubikey")
	app.Find("text:Insert your YubiKey and touch it.")
	app.Press("id:twofactor-remember")
	app.Settle()
	n := len(releases)
	// The key types its OTP and Enter; whitespace around it is trimmed.
	app.Type("id:twofactor-code", " "+testYubiKeyOTP+"\n")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	req := svc.lastLogin
	svc.mu.RUnlock()
	if req.TwoFactorProvider != api.TwoFactorYubiKey || req.TwoFactorCode != testYubiKeyOTP || !req.RememberDevice {
		t.Fatalf("login = provider %d, code %q, remember %v", req.TwoFactorProvider, req.TwoFactorCode, req.RememberDevice)
	}
	if !slices.Contains(releases[n:], true) {
		t.Fatalf("secure input not force-released on submit: %v", releases[n:])
	}
}

func TestYubiKeyMalformedOTPIsNotSent(t *testing.T) {
	svc := yubiKeyService()
	app := startTwoFactor(t, svc, nil)
	svc.mu.RLock()
	before := svc.logins
	svc.mu.RUnlock()

	for _, bad := range []string{"123456", testYubiKeyOTP[:43], testYubiKeyOTP[:43] + "a"} {
		app.Type("id:twofactor-code", bad+"\n")
		app.WaitFor("text:That is not a code from a YubiKey. Touch your YubiKey to enter a new one.", 2*time.Second)
		if v := app.Find("id:twofactor-code"); v.Text != "" {
			t.Fatalf("malformed OTP %q left in the field: %q", bad, v.Text)
		}
	}
	app.Press("id:twofactor-verify")
	app.WaitFor("text:Touch your YubiKey to enter its code.", 2*time.Second)

	svc.mu.RLock()
	after := svc.logins
	svc.mu.RUnlock()
	if after != before {
		t.Fatalf("a malformed OTP reached the server: %d logins, want %d", after, before)
	}
	app.Press("id:twofactor-back")
	app.WaitFor("id:login-screen", 2*time.Second)
}

func TestYubiKeyRejectedOTP(t *testing.T) {
	svc := yubiKeyService()
	app := startTwoFactor(t, svc, nil)
	// Well formed, but not the code the server accepts.
	app.Type("id:twofactor-code", "cccccccccccccccccccccccccccccccccccccccccccc\n")
	app.WaitFor("text:The server did not accept this YubiKey code. Touch your YubiKey again to enter a new one.", 2*time.Second)
	if v := app.Find("id:twofactor-code"); v.Text != "" {
		t.Fatalf("rejected OTP left in the field: %q", v.Text)
	}
}

func TestYubiKeyNotRegistered(t *testing.T) {
	svc := yubiKeyService()
	svc.rejectMessage = "Given Yubikey is not registered"
	app := startTwoFactor(t, svc, nil)
	app.Type("id:twofactor-code", "vvvvvvvvvvvvcccccccccccccccccccccccccccccccc\n")
	app.WaitFor("text:This YubiKey is not registered with your account. Use a YubiKey you added in your vault web settings.", 2*time.Second)
}

func TestYubiKeyOfferedOnlyWhenListed(t *testing.T) {
	app := startTwoFactor(t, newMockVaultServiceWithTwoFactor(), nil)
	app.Find("id:twofactor-provider-authenticator")
	if app.Exists("id:twofactor-provider-yubikey") {
		t.Fatal("YubiKey offered for an account without it")
	}

	svc := yubiKeyService()
	app = startTwoFactor(t, svc, nil)
	app.Press("id:twofactor-provider-authenticator")
	app.Find("text:Enter the 6-digit code from your authenticator app.")
	app.Press("id:twofactor-provider-yubikey")
	app.Find("text:Insert your YubiKey and touch it.")

	// An account with YubiKey alone shows no method choice.
	svc = yubiKeyService()
	svc.twoFactorOffered = []api.TwoFactorProvider{api.TwoFactorYubiKey}
	app = startTwoFactor(t, svc, nil)
	if app.Exists("id:twofactor-providers") {
		t.Fatal("method choice shown for a single method")
	}
	app.Find("text:Insert your YubiKey and touch it.")
}

func newMockVaultServiceWithTwoFactor() *mockVaultService {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "654321"
	return svc
}
