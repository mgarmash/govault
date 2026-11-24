package ui

import (
	"testing"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// The appearance chosen in Settings applies at once and is remembered;
// System follows the system again.
func TestAppearanceSetting(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
	for pref, want := range map[string]core.Appearance{"dark": core.AppearanceDark, "light": core.AppearanceLight, "": core.AppearanceSystem} {
		var got core.Appearance
		app.Post(func() {
			m.SetAppearance(pref)
			got = m.Scope.Env().Appearance()
		})
		app.Settle()
		if got != want || m.Prefs.Get().Appearance != pref {
			t.Fatalf("%q: appearance %v, pref %q", pref, got, m.Prefs.Get().Appearance)
		}
	}
}
