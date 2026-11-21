package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestHealthViewCountsAndOpensFlaggedItem(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	add := func(c *state.Cipher) {
		svc.ciphers[c.ID] = c
		svc.order = append(svc.order, c.ID)
	}
	add(&state.Cipher{ID: "c-gitlab", Type: api.CipherTypeLogin, Name: "GitLab", Login: &state.Login{Password: "gh-secret-password"}})
	add(&state.Cipher{ID: "c-router", Type: api.CipherTypeLogin, Name: "Router", Login: &state.Login{Password: "admin", URIs: []state.LoginURI{{URI: "http://router.example.net"}}}})
	add(&state.Cipher{ID: "c-old-card", Type: api.CipherTypeCard, Name: "Old Card", Card: &state.Card{ExpMonth: "1", ExpYear: "2020"}})

	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))

	app.WaitFor("id:sidebar-health >> text:5", 2*time.Second)
	app.Press("id:sidebar-health")
	app.WaitFor("id:health-view", 2*time.Second)
	for id, want := range map[string]string{"reused": "2", "weak": "1", "cards": "1", "unsecured": "1"} {
		app.Find("id:health-count-" + id + " >> text:" + want)
	}
	app.Find("id:health-view >> text:Expired 01/2020")
	if app.Exists("id:health-view >> text:gh-secret-password") {
		t.Fatal("health view shows a raw password")
	}

	app.Press("id:health-view >> text:Router >> nth=0")
	app.WaitUntil(2*time.Second, func() bool { c := model.ActiveCipher.Get(); return c != nil && c.ID == "c-router" })
	app.WaitFor("id:detail-view >> text:Router", 2*time.Second)
	if model.Route.Get() != RouteVault || model.SelectedID.Get() != "c-router" {
		t.Fatalf("route=%v selected=%q", model.Route.Get(), model.SelectedID.Get())
	}

	app.Post(func() {
		svc.ciphers["c-router"].Login.Password = "x7#Kq9!vLm2@Pz4w&Rt8"
		svc.ciphers["c-router"].Login.URIs = nil
		svc.ciphers["c-gitlab"].Login.Password = "Unique-Strong-Pass-123!"
		svc.ciphers["c-old-card"].DeletedDate = &time.Time{}
		model.RefreshVaultData()
		model.Route.Set(RouteHealth)
	})
	app.WaitFor("id:health-all-clear", 2*time.Second)
	if app.Exists("id:sidebar-health-badge") {
		t.Fatal("badge shown with no issues")
	}
}
