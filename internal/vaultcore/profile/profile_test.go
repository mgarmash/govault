package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/keyring"
)

type harness struct {
	t    *testing.T
	srv  *fakeserver.Server
	dir  string
	ring *keyring.Memory
}

func newHarness(t *testing.T, withKeyring bool) *harness {
	t.Helper()
	srv := fakeserver.New()
	t.Cleanup(srv.Close)
	h := &harness{t: t, srv: srv, dir: filepath.Join(t.TempDir(), "profile")}
	if withKeyring {
		h.ring = keyring.NewMemory()
	}
	p := h.open()
	if err := p.SetServer(srv.URL()); err != nil {
		t.Fatal(err)
	}
	return h
}

// open opens the profile as a separate gv process would.
func (h *harness) open() *Profile {
	h.t.Helper()
	opts := Options{HTTPClient: h.srv.Client(), DeviceName: "test", DeviceType: 25}
	if h.ring != nil {
		opts.Keyring = h.ring
	}
	p, err := Open(h.dir, opts)
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) loginPassword() string {
	h.t.Helper()
	l, err := h.open().BeginPasswordLogin(context.Background(), fakeserver.Email, []byte(fakeserver.Password))
	if err != nil {
		h.t.Fatal(err)
	}
	defer l.Close()
	key, err := l.Complete(context.Background(), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return key
}

func (h *harness) unlock(apiKey *APIKey) string {
	h.t.Helper()
	key, err := h.open().Unlock(context.Background(), UnlockRequest{Password: []byte(fakeserver.Password), APIKey: apiKey})
	if err != nil {
		h.t.Fatal(err)
	}
	return key
}

func (h *harness) files() []string {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

var fixtureKey = &APIKey{ClientID: fakeserver.ClientID, ClientSecret: fakeserver.ClientSecret}

func TestSessionKeysEndWithUnlockLockAndLogout(t *testing.T) {
	h := newHarness(t, true)
	first := h.loginPassword()
	if err := h.open().CheckSession(first); err != nil {
		t.Fatalf("login session: %v", err)
	}
	second := h.unlock(nil)
	if err := h.open().CheckSession(first); !errors.Is(err, ErrLocked) {
		t.Fatalf("session from before unlock = %v, want ErrLocked", err)
	}
	if err := h.open().CheckSession(second); err != nil {
		t.Fatalf("new session: %v", err)
	}
	if err := h.open().Lock(); err != nil {
		t.Fatal(err)
	}
	if err := h.open().CheckSession(second); !errors.Is(err, ErrLocked) {
		t.Fatalf("session after lock = %v, want ErrLocked", err)
	}
	third := h.unlock(nil)
	if err := h.open().Logout(); err != nil {
		t.Fatal(err)
	}
	if err := h.open().CheckSession(third); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("session after logout = %v, want ErrNotLoggedIn", err)
	}
	if got := h.files(); !slices.Equal(got, []string{"credentials.lock", "profile.json", "state.lock"}) {
		t.Fatalf("files after logout = %v", got)
	}
	if h.ring.Len() != 0 {
		t.Fatal("logout left the keyring item")
	}
}

// A session record and its key copied into another profile unlock nothing
// there: the record is bound to its profile.
func TestSessionRecordIsBoundToItsProfile(t *testing.T) {
	a, b := newHarness(t, true), newHarness(t, true)
	key := a.loginPassword()
	b.loginPassword()
	raw, err := os.ReadFile(filepath.Join(a.dir, sessionFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, sessionFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.open().CheckSession(key); !errors.Is(err, ErrLocked) {
		t.Fatalf("copied session = %v, want ErrLocked", err)
	}
}

func TestSessionRecordHoldsNoPlainKey(t *testing.T) {
	h := newHarness(t, true)
	key := h.loginPassword()
	raw, _ := os.ReadFile(filepath.Join(h.dir, sessionFile))
	if strings.Contains(string(raw), key) {
		t.Fatal("the session key is stored")
	}
	var found bool
	err := h.open().Read(key, nil, func(v *Vault) error {
		found = len(v.Ciphers) > 0
		return nil
	})
	if err != nil || !found {
		t.Fatalf("Read = %v, items %v", err, found)
	}
}

func TestInterruptedLogoutFinishesBeforeAnythingElse(t *testing.T) {
	h := newHarness(t, true)
	key := h.loginPassword()
	p := h.open()
	acct, err := p.loadAccount()
	if err != nil {
		t.Fatal(err)
	}
	// A logout that stopped after marking the account, with a keyring that
	// failed to delete the credentials.
	acct.LoggingOut = true
	if err := writeJSON(p.path(accountFile), acct); err != nil {
		t.Fatal(err)
	}
	h.ring.Fail = errors.New("keyring offline")
	if _, err := Open(h.dir, Options{Keyring: h.ring}); err == nil {
		t.Fatal("Open succeeded while the cleanup could not finish")
	}
	h.ring.Fail = nil
	if st, err := h.open().Status(key); err != nil || st.State != Unauthenticated {
		t.Fatalf("status after the resumed logout = %+v, %v", st, err)
	}
	if got := h.files(); slices.Contains(got, accountFile) || slices.ContainsFunc(got, func(n string) bool { return strings.HasPrefix(n, "vault_") }) {
		t.Fatalf("files after the resumed logout = %v", got)
	}
}

// A sync that was fetching when the user logged out must not bring the
// account back.
func TestSyncDuringLogoutDoesNotRecreateTheAccount(t *testing.T) {
	h := newHarness(t, true)
	key := h.loginPassword()
	logout := sync.OnceFunc(func() {
		if err := h.open().Logout(); err != nil {
			t.Error(err)
		}
	})
	h.srv.Configure(func(c *fakeserver.Config) { c.OnSync = logout })
	err := h.open().Sync(context.Background(), SyncRequest{Force: true, SessionKey: key})
	if !errors.Is(err, ErrNotLoggedIn) && !errors.Is(err, ErrStale) {
		t.Fatalf("Sync = %v, want it refused after logout", err)
	}
	if got := h.files(); slices.Contains(got, accountFile) || slices.Contains(got, credentialsFile) || slices.ContainsFunc(got, func(n string) bool { return strings.HasPrefix(n, "vault_") }) {
		t.Fatalf("files after the stale sync = %v", got)
	}
	if h.ring.Len() != 0 {
		t.Fatal("the stale sync recreated the credentials")
	}
}

func TestAPIKeyRenewsWithAnotherExchangeAfterA401(t *testing.T) {
	h := newHarness(t, true)
	if err := h.open().LoginAPIKey(context.Background(), *fixtureKey); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.open().Status(""); st.State != Locked {
		t.Fatalf("status after API key login = %v, want locked", st.State)
	}
	h.srv.RejectNextToken()
	if err := h.open().Sync(context.Background(), SyncRequest{Force: true}); err != nil {
		t.Fatalf("locked sync with stored API key: %v", err)
	}
	if n := h.srv.GrantCount("client_credentials"); n != 2 {
		t.Fatalf("client_credentials grants = %d, want 2", n)
	}
	if n := h.srv.GrantCount("refresh_token"); n != 0 {
		t.Fatalf("refresh grants = %d, want none for an API key", n)
	}
	// The vault still unlocks offline from the API-key login's snapshot.
	h.srv.Close()
	h.unlock(nil)
}

func TestPasswordGrantRenewsWithItsRefreshToken(t *testing.T) {
	h := newHarness(t, true)
	h.loginPassword()
	h.srv.RejectNextToken()
	if err := h.open().Sync(context.Background(), SyncRequest{Force: true}); err != nil {
		t.Fatal(err)
	}
	if n := h.srv.GrantCount("refresh_token"); n != 1 {
		t.Fatalf("refresh grants = %d, want 1", n)
	}
	// The rotated refresh token was kept: a second rejection renews again.
	h.srv.RejectNextToken()
	if err := h.open().Sync(context.Background(), SyncRequest{Force: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalRefusesATokenForAnotherAccount(t *testing.T) {
	h := newHarness(t, true)
	h.loginPassword()
	h.srv.Configure(func(c *fakeserver.Config) { c.Subject = fakeserver.PeerUserID })
	h.srv.RejectNextToken()
	err := h.open().Sync(context.Background(), SyncRequest{Force: true})
	if !errors.Is(err, ErrDifferentAccount) {
		t.Fatalf("Sync = %v, want ErrDifferentAccount", err)
	}
}

func TestCredentialsStayWithTheirServer(t *testing.T) {
	h := newHarness(t, true)
	h.loginPassword()
	other := fakeserver.New()
	defer other.Close()
	// Logged in, the server cannot be changed; edit the file the way an
	// attacker with the user's files could.
	p := h.open()
	ps, _ := p.loadProfile()
	ps.Server = other.URL()
	if err := p.saveProfile(ps); err != nil {
		t.Fatal(err)
	}
	if err := h.open().Sync(context.Background(), SyncRequest{Force: true}); !errors.Is(err, ErrServerChanged) {
		t.Fatalf("Sync = %v, want ErrServerChanged", err)
	}
	if n := len(other.Requests()); n != 0 {
		t.Fatalf("the other server received %d requests", n)
	}
}

// Without a credential store, API-key credentials are not kept until an
// unlock takes them again and seals them under the user key.
func TestKeyringFreeAPIKeyLogin(t *testing.T) {
	h := newHarness(t, false)
	if err := h.open().LoginAPIKey(context.Background(), *fixtureKey); err != nil {
		t.Fatal(err)
	}
	if err := h.open().Sync(context.Background(), SyncRequest{}); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("locked sync without credentials = %v, want ErrNoCredentials", err)
	}
	if err := h.open().Sync(context.Background(), SyncRequest{APIKey: fixtureKey}); err != nil {
		t.Fatalf("locked sync with supplied API key: %v", err)
	}
	if slices.Contains(h.files(), credentialsFile) {
		t.Fatal("a locked sync stored the API key")
	}

	key := h.unlock(fixtureKey)
	raw, err := os.ReadFile(filepath.Join(h.dir, credentialsFile))
	if err != nil {
		t.Fatalf("unlock did not keep the API key: %v", err)
	}
	if strings.Contains(string(raw), fakeserver.ClientSecret) || strings.Contains(string(raw), "eyJ") {
		t.Fatal("credentials.json holds plaintext secrets")
	}
	if err := h.open().Sync(context.Background(), SyncRequest{}); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("locked sync = %v, want ErrNoCredentials", err)
	}
	if err := h.open().Sync(context.Background(), SyncRequest{SessionKey: key, Force: true}); err != nil {
		t.Fatalf("unlocked sync: %v", err)
	}
	if err := h.open().Logout(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.files(), credentialsFile) {
		t.Fatal("logout left credentials.json")
	}
}

func TestUnlockRejectsAWrongPasswordOffline(t *testing.T) {
	h := newHarness(t, true)
	h.loginPassword()
	h.srv.Close()
	_, err := h.open().Unlock(context.Background(), UnlockRequest{Password: []byte("wrong")})
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Unlock = %v, want ErrInvalidPassword", err)
	}
	h.unlock(nil)
}

// Unlocks, reads, syncs and a logout from concurrent processes leave
// either the account or nothing, never a mix.
func TestConcurrentTransitions(t *testing.T) {
	h := newHarness(t, true)
	key := h.loginPassword()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := h.open()
			switch i % 4 {
			case 0:
				_, _ = p.Unlock(context.Background(), UnlockRequest{Password: []byte(fakeserver.Password)})
			case 1:
				_ = p.Read(key, nil, func(v *Vault) error { return nil })
			case 2:
				_ = p.Sync(context.Background(), SyncRequest{Force: true})
			case 3:
				_ = p.Lock()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.open().Logout()
	}()
	wg.Wait()
	files := h.files()
	hasAccount := slices.Contains(files, accountFile)
	hasSnapshot := slices.ContainsFunc(files, func(n string) bool { return strings.HasPrefix(n, "vault_") })
	if hasAccount || hasSnapshot || h.ring.Len() != 0 {
		t.Fatalf("after logout: files %v, keyring items %d", files, h.ring.Len())
	}
}

// A login that fails at its last step leaves no active account: the
// account record is written last.
func TestLoginFailingAtTheLastStepLeavesNoAccount(t *testing.T) {
	h := newHarness(t, true)
	beforeAccountCommit = func() error { return errors.New("disk full") }
	defer func() { beforeAccountCommit = nil }()
	l, err := h.open().BeginPasswordLogin(context.Background(), fakeserver.Email, []byte(fakeserver.Password))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Complete(context.Background(), nil)
	l.Close()
	if err == nil {
		t.Fatal("the login succeeded")
	}
	p := h.open()
	if _, err := p.activeAccount(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after the failed login: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, credentialsFile)); err == nil {
		t.Fatal("the credentials of the failed login are still there")
	}
	beforeAccountCommit = nil
	h.loginPassword()
}
