package main

import (
	"runtime"

	"github.com/nsgo-dev/nsgo/core"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

// Set by the local signing build to the app's private Apple access group.
var macKeychainAccessGroup string

func desktopSecrets(app *core.Scope) core.Secrets {
	secrets := app.Secrets()
	if runtime.GOOS == "darwin" {
		// A nonempty access group makes NSGo use Data Protection, not login.
		secrets.Service += ".credentials-v3"
		secrets.AccessGroup = macKeychainAccessGroup
		secrets.Accessible = core.SecretWhenUnlockedThisDeviceOnly
	}
	return secrets
}

const keychainNamespaceMarker = "govault.keychain-credentials-v3"

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
