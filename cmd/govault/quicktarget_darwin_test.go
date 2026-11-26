//go:build darwin && !ios

package main

import (
	"errors"
	"os"
	"testing"
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

func TestQuickFillSteps(t *testing.T) {
	tests := []struct {
		name          string
		user, pass    string
		tab           bool
		wantTexts     []string
		wantTabAt     int
		wantUnavailab bool
	}{
		{name: "single takes first value", user: "alice", pass: "ignored", wantTexts: []string{"alice"}, wantTabAt: -1},
		{name: "single empty first", user: "", pass: "secret", wantUnavailab: true, wantTabAt: -1},
		{name: "pair username tab password", user: "alice", pass: "secret", tab: true, wantTexts: []string{"alice", "secret"}, wantTabAt: 1},
		{name: "pair needs username", user: "", pass: "secret", tab: true, wantUnavailab: true, wantTabAt: -1},
		{name: "pair needs password", user: "alice", pass: "", tab: true, wantUnavailab: true, wantTabAt: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps, err := quickFillSteps(tt.user, tt.pass, tt.tab)
			if tt.wantUnavailab {
				if !errors.Is(err, errQuickTargetUnavailable) {
					t.Fatalf("quickFillSteps(%q, %q, %v) error = %v, want unavailable", tt.user, tt.pass, tt.tab, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("quickFillSteps(%q, %q, %v) error = %v", tt.user, tt.pass, tt.tab, err)
			}
			var texts []string
			tabAt := -1
			for i, step := range steps {
				if step.tab {
					tabAt = i
					continue
				}
				texts = append(texts, step.text)
			}
			if tabAt != tt.wantTabAt {
				t.Fatalf("tab step at %d, want %d", tabAt, tt.wantTabAt)
			}
			if len(texts) != len(tt.wantTexts) {
				t.Fatalf("texts = %q, want %q", texts, tt.wantTexts)
			}
			for i := range texts {
				if texts[i] != tt.wantTexts[i] {
					t.Fatalf("texts = %q, want %q", texts, tt.wantTexts)
				}
			}
		})
	}
}

func TestQuickTargetFrontmost(t *testing.T) {
	self := int32(os.Getpid())
	tests := []struct {
		name           string
		capturedPID    int32
		capturedBundle string
		frontPID       int32
		frontBundle    string
		want           bool
	}{
		{"same app", 42, "com.example.app", 42, "com.example.app", true},
		{"pid changed", 42, "com.example.app", 43, "com.example.app", false},
		{"bundle changed", 42, "com.example.app", 42, "com.example.other", false},
		{"self", self, "com.example.app", self, "com.example.app", false},
		{"blocked terminal", 42, "com.apple.Terminal", 42, "com.apple.Terminal", false},
		{"no captured pid", 0, "com.example.app", 0, "com.example.app", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quickTargetFrontmost(tt.capturedPID, tt.capturedBundle, tt.frontPID, tt.frontBundle); got != tt.want {
				t.Fatalf("quickTargetFrontmost(%d, %q, %d, %q) = %v, want %v",
					tt.capturedPID, tt.capturedBundle, tt.frontPID, tt.frontBundle, got, tt.want)
			}
		})
	}
}

func TestQuickTextSafe(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"plain", "hunter2", true},
		{"unicode", "pässwörd-🔑", true},
		{"empty", "", true},
		{"line feed", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"tab", "a\tb", false},
		{"delete", "a\x7fb", false},
		{"nul", "a\x00b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quickTextSafe(tt.value); got != tt.want {
				t.Fatalf("quickTextSafe(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestQuickFillRejectsControlBeforeSending(t *testing.T) {
	var sent int
	oldText, oldTab := quickDeliverText, quickDeliverTab
	quickDeliverText = func(int32, string) error { sent++; return nil }
	quickDeliverTab = func(int32) error { sent++; return nil }
	t.Cleanup(func() { quickDeliverText, quickDeliverTab = oldText, oldTab })

	tests := []struct {
		name       string
		user, pass string
		tab        bool
	}{
		{name: "single", user: "alice\n"},
		{name: "pair username", user: "ali\tce", pass: "secret", tab: true},
		{name: "pair password", user: "alice", pass: "sec\rret", tab: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sent = 0
			if err := quickFill(42, "com.example.app", tt.user, tt.pass, tt.tab); !errors.Is(err, errQuickValueRejected) {
				t.Fatalf("quickFill error = %v, want rejected value", err)
			}
			if sent != 0 {
				t.Fatalf("sent %d events for an unsafe value, want 0", sent)
			}
		})
	}
}

func TestQuickTabVerdict(t *testing.T) {
	tests := []struct {
		name                    string
		readable, readSucceeded bool
		wantErr                 bool
	}{
		{"focus readable but unchanged", true, true, true},
		{"focus readable, no successful read", true, false, false},
		{"focus unreadable", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := quickTabVerdict(tt.readable, tt.readSucceeded)
			if got := errors.Is(err, errQuickTargetChanged); got != tt.wantErr {
				t.Fatalf("quickTabVerdict(%v, %v) = %v, want changed error %v", tt.readable, tt.readSucceeded, err, tt.wantErr)
			}
		})
	}
}
