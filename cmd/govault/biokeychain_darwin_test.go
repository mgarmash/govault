//go:build darwin && !ios

package main

import (
	"os"
	"testing"
)

// TestDataProtectionKeychainProbe reports how this macOS host and the signing
// identity of the test binary respond to a Touch ID bound keychain item.
// It never prompts: it only adds, checks for and deletes a throwaway item.
func TestDataProtectionKeychainProbe(t *testing.T) {
	if os.Getenv("GOVAULT_KEYCHAIN_PROBE") == "" || macKeychainAccessGroup == "" {
		t.Skip("requires opt-in and a provisioned test bundle")
	}
	kc := dataProtectionKeychain{group: macKeychainAccessGroup}
	const account = "userkey:govault-probe"
	if err := kc.Add(account, []byte("synthetic")); err != nil {
		t.Fatalf("Data Protection Keychain enrollment: %v", err)
	}
	t.Cleanup(func() {
		if err := kc.Delete(account); err != nil {
			t.Error(err)
		}
	})
	if exists, err := kc.Exists(account); !exists || err != nil {
		t.Fatalf("Data Protection Keychain lookup: exists=%v, err=%v", exists, err)
	}
}
