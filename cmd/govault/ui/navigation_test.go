package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestHealthFilterAndBackForward(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	add := func(c *state.Cipher) {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	add(&state.Cipher{ID: "c-router", Type: api.CipherTypeLogin, Name: "Router", Login: &state.Login{Password: "admin", URIs: []state.LoginURI{{URI: "http://router.example.net"}}}})
	add(&state.Cipher{ID: "c-old-card", Type: api.CipherTypeCard, Name: "Old Card", Card: &state.Card{ExpMonth: "1", ExpYear: "2020"}})

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))

	if model.CanGoBack.Get() {
		t.Fatal("history not empty at start")
	}
	app.Press("id:sidebar-health")
	app.WaitFor("id:health-view", 2*time.Second)
	app.Find("id:health-view >> text:Old Card")

	app.Press("id:health-count-unsecured")
	app.WaitForGone("id:health-view >> text:Old Card", 2*time.Second)
	app.Find("id:health-view >> text:http://router.example.net")
	if model.HealthFilter.Get() != HealthUnsecured {
		t.Fatalf("HealthFilter = %q", model.HealthFilter.Get())
	}

	app.Press("id:health-view >> text:Router")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "c-router"
	})

	app.Press("id:toolbar-back")
	app.WaitFor("id:health-view", 2*time.Second)
	if model.HealthFilter.Get() != HealthUnsecured || app.Exists("id:health-view >> text:Old Card") {
		t.Fatalf("Back lost the health filter: %q", model.HealthFilter.Get())
	}
	if !model.CanGoForward.Get() {
		t.Fatal("Forward unavailable after Back")
	}

	app.Key("mod+]")
	app.WaitUntil(2*time.Second, func() bool {
		return model.Route.Get() == RouteVault && model.SelectedID.Get() == "c-router"
	})

	app.Post(model.GoBackFromSystem)
	app.WaitFor("id:health-view", 2*time.Second)
	app.Press("id:health-count-unsecured")
	app.WaitFor("id:health-view >> text:Old Card", 2*time.Second)

	app.Post(model.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	if model.CanGoBack.Get() || model.CanGoForward.Get() {
		t.Fatal("history survived lock")
	}
}

func TestLockDoesNotAutoPromptTouchID(t *testing.T) {
	if DefaultUserPrefs().AutoPromptBiometric {
		t.Fatal("AutoPromptBiometric defaults to on")
	}
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{Secrets: noSecrets{}})
		model.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.AccountID, p.BiometricEnabled, p.AutoPromptBiometric = "acct", true, true
			return p
		})
		model.SetMainWindowVisible(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 700))
	app.BiometricAvailability = core.BiometricFingerprint
	app.BiometricAnswer = core.BiometricCancelled
	app.Post(model.RefreshBiometricAvailability)
	app.WaitUntil(2*time.Second, model.CanUseBiometric)

	app.Post(model.Lock)
	app.WaitFor("id:lock-screen", 2*time.Second)
	app.Settle()
	if n := len(app.AuthenticationReasons); n != 0 {
		t.Fatalf("locking prompted Touch ID %d times", n)
	}

	app.Post(func() { model.SetMainWindowVisible(false) })
	app.Post(func() { model.SetMainWindowVisible(true) })
	app.WaitUntil(2*time.Second, func() bool { return len(app.AuthenticationReasons) == 1 })
}

type noSecrets struct{}

func (noSecrets) Get(string) (string, bool, error) { return "", false, nil }
func (noSecrets) Set(string, string) error         { return nil }
func (noSecrets) Delete(string) error              { return nil }
