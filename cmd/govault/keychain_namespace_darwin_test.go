//go:build darwin && !ios

package main

import (
	"testing"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

func TestDesktopKeychainLeavesLegacyCredentialsUntouched(t *testing.T) {
	const account = "refresh:synthetic"
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		legacy := cx.Secrets()
		if err := legacy.Set(account, "legacy-token"); err != nil {
			t.Fatal(err)
		}
		fresh := desktopSecrets(cx)
		if _, ok, err := fresh.Get(account); ok || err != nil {
			t.Fatalf("v2 read a legacy item: found=%v, err=%v", ok, err)
		}
		if err := fresh.Set(account, "fresh-token"); err != nil {
			t.Fatal(err)
		}
		if token, ok, err := desktopSecrets(cx).Get(account); token != "fresh-token" || !ok || err != nil {
			t.Fatalf("v2 cannot reopen its new token: found=%v, err=%v", ok, err)
		}
		if err := fresh.Delete(account); err != nil {
			t.Fatal(err)
		}
		if token, ok, err := legacy.Get(account); token != "legacy-token" || !ok || err != nil {
			t.Fatalf("legacy token changed: found=%v, err=%v", ok, err)
		}
		return core.View{}
	})
	app.Settle()
}

func TestDesktopKeychainRequiresBiometricSetupOnlyOnce(t *testing.T) {
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		prefs := core.NewPersisted(cx, govaultui.DefaultPrefsKey, govaultui.DefaultUserPrefs(), core.PersistOptions{Version: 1})
		p := prefs.Get()
		p.BiometricEnabled, p.AutoPromptBiometric = true, true
		p.AccountID, p.DeviceID, p.QuickAccessHotKey = "account", "device", "ctrl+alt+k"
		if err := prefs.Set(p); err != nil {
			t.Fatal(err)
		}
		startup := func() {
			if err := resetLegacyBiometricPreference(cx.Storage(), prefs); err != nil {
				t.Fatal(err)
			}
		}
		startup()
		if got := prefs.Get(); got.BiometricEnabled || !got.AutoPromptBiometric || got.AccountID != p.AccountID || got.DeviceID != p.DeviceID || got.QuickAccessHotKey != p.QuickAccessHotKey {
			t.Fatal("upgrade failed to clear only the stale biometric enrollment")
		}
		if err := prefs.Set(p); err != nil {
			t.Fatal(err)
		}
		startup()
		if !prefs.Get().BiometricEnabled {
			t.Fatal("a subsequent launch reset the new biometric enrollment")
		}
		return core.View{}
	})
	app.Settle()
}
