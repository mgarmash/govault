package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestServerPresetOf(t *testing.T) {
	for server, want := range map[string]ServerPreset{
		"https://vault.bitwarden.com": PresetUS,
		"bitwarden.com":               PresetUS,
		"https://vault.bitwarden.eu":  PresetEU,
		"vault.bitwarden.eu/":         PresetEU,
		"https://vault.example.com":   PresetSelfHosted,
		"https://bitwarden.com/x":     PresetSelfHosted,
		"":                            PresetSelfHosted,
	} {
		if got := ServerPresetOf(server); got != want {
			t.Errorf("ServerPresetOf(%q) = %v, want %v", server, got, want)
		}
	}
}

// The cloud presets fill the server and hide its field; self-hosted shows
// it, empty.
func TestSignInServerPresets(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var m *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{})
		m.MainWinVisible.Set(true)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 900))
	app.WaitFor("id:login-server-preset", 2*time.Second)

	app.Post(func() { m.SetServerPreset(PresetEU) })
	app.WaitForGone("id:login-server", 2*time.Second)
	if got := m.LoginServer.Get(); got != "https://vault.bitwarden.eu" {
		t.Fatalf("EU preset server = %q", got)
	}
	app.Post(func() { m.SetServerPreset(PresetSelfHosted) })
	app.WaitFor("id:login-server", 2*time.Second)
	if got := m.LoginServer.Get(); got != "" {
		t.Fatalf("self-hosted server = %q", got)
	}
}
