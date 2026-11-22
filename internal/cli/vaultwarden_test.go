package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

// TestVaultwarden runs gv against a real, disposable Vaultwarden account:
//
//	GV_VAULTWARDEN_URL=https://vw.example.test \
//	GV_VAULTWARDEN_EMAIL=test@example.test GV_VAULTWARDEN_PASSWORD=... \
//	[GV_VAULTWARDEN_TOTP_SEED=BASE32] \
//	[GV_VAULTWARDEN_CLIENT_ID=user.… GV_VAULTWARDEN_CLIENT_SECRET=…] \
//	go test ./internal/cli -run TestVaultwarden -v
//
// It signs in and out and syncs, but never changes the vault.
func TestVaultwarden(t *testing.T) {
	url := os.Getenv("GV_VAULTWARDEN_URL")
	if url == "" {
		t.Skip("set GV_VAULTWARDEN_URL and a test account to run against Vaultwarden")
	}
	acct := vwAccount{
		email: os.Getenv("GV_VAULTWARDEN_EMAIL"), password: os.Getenv("GV_VAULTWARDEN_PASSWORD"),
		totpSeed: os.Getenv("GV_VAULTWARDEN_TOTP_SEED"),
		clientID: os.Getenv("GV_VAULTWARDEN_CLIENT_ID"), clientSecret: os.Getenv("GV_VAULTWARDEN_CLIENT_SECRET"),
	}
	if acct.email == "" || acct.password == "" {
		t.Fatal("GV_VAULTWARDEN_EMAIL and GV_VAULTWARDEN_PASSWORD are required")
	}
	runServerSuite(t, url, http.DefaultClient, acct)
}

// TestBitwardenCloud runs the API-key suite against Bitwarden's cloud with
// a disposable account:
//
//	GV_BITWARDEN_REGION=us|eu GV_BITWARDEN_PASSWORD=… \
//	GV_BITWARDEN_CLIENT_ID=user.… GV_BITWARDEN_CLIENT_SECRET=… \
//	go test ./internal/cli -run TestBitwardenCloud -v
//
// GV_WRITE_TESTS=1 adds the write suite, which changes only items of its
// own. It signs in once, with the API key: a password login from a new device
// meets Bitwarden's new-device verification, which gv does not support.
// It renews the token once and never changes the vault.
func TestBitwardenCloud(t *testing.T) {
	region := os.Getenv("GV_BITWARDEN_REGION")
	if region == "" {
		t.Skip("set GV_BITWARDEN_REGION and a test account to run against Bitwarden's cloud")
	}
	server := map[string]string{"us": "bitwarden.com", "eu": "https://vault.bitwarden.eu"}[region]
	if server == "" {
		t.Fatalf("GV_BITWARDEN_REGION must be us or eu, not %q", region)
	}
	acct := vwAccount{
		password: os.Getenv("GV_BITWARDEN_PASSWORD"),
		clientID: os.Getenv("GV_BITWARDEN_CLIENT_ID"), clientSecret: os.Getenv("GV_BITWARDEN_CLIENT_SECRET"),
	}
	if acct.password == "" || acct.clientID == "" || acct.clientSecret == "" {
		t.Fatal("GV_BITWARDEN_PASSWORD, GV_BITWARDEN_CLIENT_ID and GV_BITWARDEN_CLIENT_SECRET are required")
	}
	runAPIKeySuite(t, server, http.DefaultClient, acct, keyring.NewMemory())
}

// isFake reports a fake server address, against which the write suite
// always runs.
func isFake(url string) bool { return strings.HasPrefix(url, "http://127.0.0.1:") }

// The suite itself is checked against the fake server.
func TestServerSuiteOnFakeServer(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	runServerSuite(t, srv.URL(), srv.Client(), vwAccount{
		email: fakeserver.Email, password: fakeserver.Password,
		clientID: fakeserver.ClientID, clientSecret: fakeserver.ClientSecret,
	})
}

type vwAccount struct {
	email, password, totpSeed, clientID, clientSecret string
}

func runServerSuite(t *testing.T, url string, client *http.Client, acct vwAccount) {
	email, password := acct.email, acct.password

	t.Run("password", func(t *testing.T) {
		vw := newVW(t, url, client, keyring.NewMemory())
		args := []string{"login", email, "--passwordenv", "PW", "--raw"}
		if seed := acct.totpSeed; seed != "" {
			cfg, err := totp.ParseTOTP(seed)
			if err != nil {
				t.Fatal(err)
			}
			code, _, _, _ := totp.Generate(cfg, time.Now())
			args = append(args, "--method", "0", "--code", code)
		}
		vw.env["PW"] = password
		vw.env["BW_SESSION"] = vw.must(t, args...)
		vw.checkReads(t)
		if writesEnabled() || isFake(url) {
			vw.checkWrites(t)
		}
		vw.must(t, "lock")
		if r := vw.run("list", "items", "--nointeraction"); r.err != "Vault is locked." {
			t.Fatalf("after lock: %+v", r)
		}
		vw.env["BW_SESSION"] = vw.must(t, "unlock", "--passwordenv", "PW", "--raw")
		vw.must(t, "logout")
	})

	id, secret := acct.clientID, acct.clientSecret
	if id == "" || secret == "" {
		t.Log("API key login skipped: set GV_VAULTWARDEN_CLIENT_ID and GV_VAULTWARDEN_CLIENT_SECRET")
		return
	}
	for _, withKeyring := range []bool{true, false} {
		name := "apikey-no-keyring"
		var ring *keyring.Memory
		if withKeyring {
			name, ring = "apikey-keyring", keyring.NewMemory()
		}
		t.Run(name, func(t *testing.T) { runAPIKeySuite(t, url, client, acct, ring) })
	}
}

// runAPIKeySuite signs in with the API key once, unlocks with the master
// password, reads, renews a rejected token (with a keyring), locks and logs
// out. Without a keyring it also checks that a locked sync needs the key
// again.
func runAPIKeySuite(t *testing.T, url string, client *http.Client, acct vwAccount, ring *keyring.Memory) {
	withKeyring := ring != nil
	id, secret := acct.clientID, acct.clientSecret
	vw := newVW(t, url, client, ring)
	vw.env["BW_CLIENTID"], vw.env["BW_CLIENTSECRET"], vw.env["PW"] = id, secret, acct.password
	vw.must(t, "login", "--apikey", "--nointeraction")
	t.Log("ok: login --apikey")
	if !withKeyring {
		delete(vw.env, "BW_CLIENTID")
		delete(vw.env, "BW_CLIENTSECRET")
		if r := vw.run("sync"); r.code == 0 {
			t.Fatal("a locked sync without credentials succeeded on a keyring-free host")
		}
		t.Log("ok: locked sync refused without credentials")
		vw.env["BW_CLIENTID"], vw.env["BW_CLIENTSECRET"] = id, secret
	}
	vw.env["BW_SESSION"] = vw.must(t, "unlock", "--passwordenv", "PW", "--raw")
	t.Log("ok: unlock --passwordenv --raw")
	delete(vw.env, "BW_CLIENTID")
	delete(vw.env, "BW_CLIENTSECRET")
	vw.checkReads(t)
	if writesEnabled() || isFake(url) {
		vw.checkWrites(t)
	}
	if withKeyring {
		// A token the server rejects is renewed with a second client
		// credentials exchange; there is no refresh token.
		vw.spoilAccessToken(t, ring)
		session := vw.env["BW_SESSION"]
		delete(vw.env, "BW_SESSION")
		vw.must(t, "sync", "-f")
		t.Log("ok: locked sync -f renewed a rejected token")
		vw.env["BW_SESSION"] = session
	}
	vw.must(t, "lock")
	if r := vw.run("list", "items", "--nointeraction"); r.err != "Vault is locked." {
		t.Fatalf("after lock: exit %d %q", r.code, r.err)
	}
	t.Log("ok: lock")
	vw.must(t, "logout")
	if r := vw.run("status"); !strings.Contains(r.out, `"status":"unauthenticated"`) {
		t.Fatalf("status after logout: exit %d", r.code)
	}
	t.Log("ok: logout")
}

type vwRun struct {
	env    map[string]string
	ring   keyring.Store
	client *http.Client
}

func newVW(t *testing.T, url string, client *http.Client, ring *keyring.Memory) *vwRun {
	dir := t.TempDir()
	vw := &vwRun{env: map[string]string{"HOME": dir, "BITWARDENCLI_APPDATA_DIR": filepath.Join(dir, "bw")}, client: client}
	if ring != nil {
		vw.ring = ring
	}
	vw.must(t, "config", "server", url)
	return vw
}

func (vw *vwRun) run(args ...string) result {
	var stdout, stderr bytes.Buffer
	code := Run(&Environment{
		Args: args, Getenv: func(k string) string { return vw.env[k] },
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr, HTTPClient: vw.client, Version: "test",
		Keyring: func() (keyring.Store, error) {
			if vw.ring == nil {
				return nil, keyring.ErrUnavailable
			}
			return vw.ring, nil
		},
	})
	return result{stdout.String(), stderr.String(), code}
}

func (vw *vwRun) must(t *testing.T, args ...string) string {
	t.Helper()
	r := vw.run(args...)
	if r.code != 0 {
		// stdout may hold vault data, so only stderr is shown.
		t.Fatalf("gv %s: exit %d: %s", args[0], r.code, r.err)
	}
	return r.out
}

func (vw *vwRun) checkReads(t *testing.T) {
	var status struct{ Status string }
	if err := json.Unmarshal([]byte(vw.must(t, "status")), &status); err != nil || status.Status != "unlocked" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	vw.must(t, "sync", "-f")
	var items []map[string]any
	if err := json.Unmarshal([]byte(vw.must(t, "list", "items")), &items); err != nil {
		t.Fatalf("list items: %v", err)
	}
	for _, kind := range []string{"folders", "collections", "organizations"} {
		var list []any
		if err := json.Unmarshal([]byte(vw.must(t, "list", kind)), &list); err != nil {
			t.Fatalf("list %s: %v", kind, err)
		}
	}
	fields := 0
	for _, it := range items {
		id := it["id"].(string)
		vw.must(t, "get", "item", id)
		login, _ := it["login"].(map[string]any)
		if _, ok := login["username"].(string); ok && fields < 4 {
			vw.must(t, "get", "username", id)
			fields++
		}
		if _, ok := login["password"].(string); ok && fields < 4 {
			vw.must(t, "get", "password", id)
			fields++
		}
	}
	vw.must(t, "get", "fingerprint", "me")
	t.Logf("ok: status, sync -f, list items/folders/collections/organizations, get item (%d items), %d login fields, fingerprint", len(items), fields)
}

func (vw *vwRun) spoilAccessToken(t *testing.T, ring *keyring.Memory) {
	dir := vw.env["BITWARDENCLI_APPDATA_DIR"]
	raw, err := os.ReadFile(filepath.Join(dir, "GoVault CLI", "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ps struct{ ProfileID string }
	_ = json.Unmarshal(raw, &ps)
	creds, err := ring.Get("GoVault CLI", ps.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(creds, &c)
	c["accessToken"] = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.invalid"
	spoiled, _ := json.Marshal(c)
	if err := ring.Set("GoVault CLI", ps.ProfileID, spoiled); err != nil {
		t.Fatal(err)
	}
}
