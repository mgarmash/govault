package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/keyring"
)

func profileFile(g *gvTest, name string) string {
	return filepath.Join(g.env["BITWARDENCLI_APPDATA_DIR"], "GoVault CLI", name)
}

func editJSON(t *testing.T, path string, fn func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	raw, _ = json.Marshal(m)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An API key from the environment is sent only to the server it signed in
// to: editing both profile files to point elsewhere does not redirect it,
// and a key of another user is refused before any exchange.
func TestEnvironmentAPIKeyGoesOnlyToItsServer(t *testing.T) {
	g := newGV(t)
	g.ring = nil
	g.env["BW_CLIENTID"], g.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g.mustRun("login", "--apikey", "--nointeraction")

	attacker := fakeserver.New()
	defer attacker.Close()
	// Both files name the substitute consistently, as an attacker who can
	// write them would.
	for _, name := range []string{"account.json", "profile.json"} {
		raw, err := os.ReadFile(profileFile(g, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(profileFile(g, name), []byte(strings.ReplaceAll(string(raw), g.srv.URL(), attacker.URL())), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if r := g.run("sync"); r.code != 1 || !strings.Contains(r.err, "was not used to sign in") {
		t.Fatalf("sync to a substituted server = %+v", r)
	}
	for _, req := range attacker.Requests() {
		if strings.Contains(req.Path, "connect/token") {
			t.Fatal("the API key was sent to the substituted server")
		}
	}

	g2 := newGV(t)
	g2.ring = nil
	g2.env["BW_CLIENTID"], g2.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g2.mustRun("login", "--apikey", "--nointeraction")
	before := len(g2.srv.Requests())
	g2.env["BW_CLIENTID"] = "user.00000000-0000-4000-8000-000000000000"
	if r := g2.run("sync"); r.code != 1 || !strings.Contains(r.err, "different account") {
		t.Fatalf("sync with another user's key = %+v", r)
	}
	for _, req := range g2.srv.Requests()[before:] {
		if strings.Contains(req.Path, "connect/token") {
			t.Fatal("another user's key was exchanged")
		}
	}
}

type failingRing struct {
	keyring.Store
	fail bool
}

func (r *failingRing) Set(service, account string, secret []byte) error {
	if r.fail {
		return errors.New("credential store unavailable")
	}
	return r.Store.Set(service, account, secret)
}

// A login that cannot save its credentials leaves nothing behind, and one
// interrupted after saving them is rolled back by the next command.
func TestInterruptedLoginIsRolledBack(t *testing.T) {
	g := newGV(t)
	ring := &failingRing{Store: keyring.NewMemory(), fail: true}
	g.ring = ring
	g.env["PW"] = fakeserver.Password
	if r := g.run("login", fakeserver.Email, "--passwordenv", "PW", "--raw"); r.code != 1 {
		t.Fatalf("login with a failing credential store = %+v", r)
	}
	if out := g.mustRun("status"); !strings.Contains(out, `"status":"unauthenticated"`) {
		t.Fatalf("status = %s", out)
	}
	for _, name := range []string{"account.json", "credentials.json"} {
		if _, err := os.Stat(profileFile(g, name)); err == nil {
			t.Fatalf("%s was left behind", name)
		}
	}
	ring.fail = false
	g.login()

	// A crash before the account was committed: the journal says pending.
	editJSON(t, profileFile(g, "account.json"), func(m map[string]any) { m["pending"] = true })
	if out := g.mustRun("status"); !strings.Contains(out, `"status":"unauthenticated"`) {
		t.Fatalf("status after an interrupted login = %s", out)
	}
	var ps struct{ ProfileID string }
	raw, _ := os.ReadFile(profileFile(g, "profile.json"))
	_ = json.Unmarshal(raw, &ps)
	if _, err := ring.Get("GoVault CLI", ps.ProfileID); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("the credential store still holds the interrupted login: %v", err)
	}
	g.login()
}

type smallRing struct{ keyring.Store }

// Windows Credential Manager holds at most 2,560 bytes.
func (r smallRing) Set(service, account string, secret []byte) error {
	if len(secret) > 2560 {
		return errors.New("credential too large")
	}
	return r.Store.Set(service, account, secret)
}

// The credential store keeps a fixed-size key, so a large token fits.
func TestLargeTokensFitTheCredentialStore(t *testing.T) {
	g := newGV(t)
	g.ring = smallRing{keyring.NewMemory()}
	g.srv.Configure(func(c *fakeserver.Config) { c.ClaimPadding = 4000 })
	g.login()
	g.mustRun("sync", "-f")
	if out := g.mustRun("get", "username", fakeserver.ItemGitHub); out != "alice" {
		t.Fatalf("username = %q", out)
	}
}
