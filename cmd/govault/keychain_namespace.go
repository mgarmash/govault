package main

import (
	"runtime"

	"github.com/nsgo-dev/nsgo/core"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

func desktopSecrets(app *core.Scope) core.Secrets {
	secrets := app.Secrets()
	if runtime.GOOS == "darwin" {
		// The ad-hoc builds' ACLs belong to a different signing identity.
		secrets.Service += ".credentials-v2"
	}
	return secrets
}

const keychainNamespaceMarker = "govault.keychain-credentials-v2"

func resetLegacyBiometricPreference(storage core.Storage, prefs *core.Persisted[govaultui.UserPrefs]) error {
	if _, migrated := storage.GetItem(keychainNamespaceMarker); migrated {
		return nil
	}
	p := prefs.Get()
	if p.BiometricEnabled {
		p.BiometricEnabled = false
		if err := prefs.Set(p); err != nil {
			return err
		}
	}
	return storage.SetItem(keychainNamespaceMarker, "1")
}
