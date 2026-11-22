package cli

import (
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// A mistyped command does not echo what follows it, which may be a secret.
func TestInvalidCommandDoesNotEchoArguments(t *testing.T) {
	g := newGV(t)
	r := g.run("unlok", "hunter2-master-password")
	if r.code != 1 || strings.Contains(r.err, "hunter2") || !strings.Contains(r.err, "Invalid command: unlok") {
		t.Fatalf("invalid command = %+v", r)
	}
}

// A malformed YubiKey code is refused before anything reaches the server.
func TestMalformedYubiKeyCodeIsRefusedLocally(t *testing.T) {
	g := newGV(t)
	g.env["PW"] = fakeserver.Password
	before := len(g.srv.Requests())
	r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--method", "3", "--code", "not a yubikey otp")
	if r.code != 1 || !strings.Contains(r.err, "not a YubiKey code") {
		t.Fatalf("login = %+v", r)
	}
	if len(g.srv.Requests()) != before {
		t.Fatal("the malformed code reached the server")
	}
}
