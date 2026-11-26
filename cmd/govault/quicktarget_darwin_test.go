//go:build darwin && !ios

package main

import (
	"testing"

	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

func TestQuickTrustedOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
		want    string
	}{
		{"native", nil, ""},
		{"single frame", []string{"https://bank.example"}, "https://bank.example"},
		{"same-origin nested frames", []string{"https://bank.example", "https://bank.example"}, "https://bank.example"},
		{"cross-origin nested frame", []string{"https://bank.example", "https://evil.example"}, ""},
		{"unverified frame", []string{"https://bank.example", ""}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quickTrustedOrigin(tt.origins); got != tt.want {
				t.Fatalf("quickTrustedOrigin(%q) = %q, want %q", tt.origins, got, tt.want)
			}
		})
	}
}

func TestQuickRoleFieldAllowed(t *testing.T) {
	tests := []struct {
		name          string
		role, subrole string
		field         govaultui.QuickField
		want          bool
	}{
		{"password secure field", "AXTextField", "AXSecureTextField", govaultui.QuickPassword, true},
		{"password insecure field", "AXTextField", "", govaultui.QuickPassword, false},
		{"username secure field", "AXTextField", "AXSecureTextField", govaultui.QuickUsername, false},
		{"username single-line field", "AXTextField", "", govaultui.QuickUsername, true},
		{"username multiline textarea", "AXTextArea", "", govaultui.QuickUsername, false},
		{"totp multiline textarea", "AXTextArea", "", govaultui.QuickTOTP, false},
		{"username button", "AXButton", "", govaultui.QuickUsername, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quickRoleFieldAllowed(tt.role, tt.subrole, tt.field); got != tt.want {
				t.Fatalf("quickRoleFieldAllowed(%q, %q, %d) = %v, want %v", tt.role, tt.subrole, tt.field, got, tt.want)
			}
		})
	}
}
