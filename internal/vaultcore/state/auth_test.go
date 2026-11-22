package state

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/realtime"
	"github.com/txchen/govault/internal/vaultcore/store"
)

func newServiceWith(t *testing.T, env *vaultTestEnv, st store.Store, secrets store.SecretStore, trusted string) *Service {
	t.Helper()
	svc, err := NewService(ServiceConfig{Store: st, Secrets: secrets, TrustedServerURL: trusted, AccountID: env.profileID, HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestService_RefreshTokenIsBoundToItsServer(t *testing.T) {
	env := newVaultTestEnv(t)
	st := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	svc := newServiceWith(t, env, st, secrets, "")
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := secrets.Get(refreshTokenKeyPrefix + env.profileID)
	var bound boundRefreshToken
	if json.Unmarshal([]byte(raw), &bound) != nil || bound.Origin != serverOrigin(env.server.URL) || bound.Token != "ref-1" {
		t.Fatalf("stored refresh token = %q, want it bound to the server", raw)
	}

	// A replaced snapshot keeps the vault and account but points elsewhere.
	svc.Lock()
	snap, _ := st.LoadSnapshot(env.profileID)
	snap.ServerURL = "https://attacker.example"
	if err := st.SaveSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	other := newServiceWith(t, env, st, secrets, env.server.URL)
	if err := other.UnlockWithPassword(context.Background(), env.password); !errors.Is(err, ErrServerMismatch) {
		t.Fatalf("unlock with a snapshot for another server = %v, want ErrServerMismatch", err)
	}
}

func TestService_LegacyRefreshTokenIsBoundOnFirstUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trusted func(env *vaultTestEnv) string
		wantErr error
	}{
		{"same server", func(env *vaultTestEnv) string { return env.server.URL + "/" }, nil},
		{"other server", func(*vaultTestEnv) string { return "https://elsewhere.example" }, ErrServerMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newVaultTestEnv(t)
			st := store.NewFileStore(t.TempDir())
			secrets := newMemSecretStore()
			first := newServiceWith(t, env, st, secrets, "")
			if err := first.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
				t.Fatal(err)
			}
			first.Lock()
			_ = secrets.Set(refreshTokenKeyPrefix+env.profileID, "legacy-token")

			svc := newServiceWith(t, env, st, secrets, tc.trusted(env))
			err := svc.UnlockWithPassword(context.Background(), env.password)
			if !errors.Is(err, tc.wantErr) && !(tc.wantErr == nil && err == nil) {
				t.Fatalf("unlock = %v, want %v", err, tc.wantErr)
			}
			raw, _, _ := secrets.Get(refreshTokenKeyPrefix + env.profileID)
			var bound boundRefreshToken
			migrated := json.Unmarshal([]byte(raw), &bound) == nil && bound.Token == "legacy-token" && bound.Origin == serverOrigin(env.server.URL)
			if migrated != (tc.wantErr == nil) {
				t.Fatalf("stored token after unlock = %q", raw)
			}
		})
	}
}

func TestService_ConcurrentRefreshesUseTheRotatingTokenOnce(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	env.mu.Lock()
	env.rotateRefresh, env.refreshes = true, 0
	env.mu.Unlock()
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.forceSync(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrSyncDeferred) {
			t.Fatalf("sync = %v", err)
		}
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.refreshes != 1 {
		t.Fatalf("refreshes = %d, want one shared refresh", env.refreshes)
	}
}

type failingSecrets struct {
	*memSecretStore
	fail bool
}

func (f *failingSecrets) Set(account, value string) error {
	if f.fail {
		return errors.New("keychain locked")
	}
	return f.memSecretStore.Set(account, value)
}

func TestService_UnsavedRotatedTokenIsReportedAndKept(t *testing.T) {
	env := newVaultTestEnv(t)
	secrets := &failingSecrets{memSecretStore: newMemSecretStore()}
	svc := newServiceWith(t, env, store.NewFileStore(t.TempDir()), secrets, "")
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	env.rotateRefresh = true
	env.mu.Unlock()
	secrets.fail = true
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()

	if err := svc.forceSync(context.Background()); !errors.Is(err, ErrSignInNotSaved) {
		t.Fatalf("sync after an unsaved refresh = %v, want ErrSignInNotSaved", err)
	}
	if err := svc.forceSync(context.Background()); err != nil {
		t.Fatalf("the session stopped working: %v", err)
	}
	// The next refresh uses the token the server issued, not the spent one.
	svc.mu.Lock()
	svc.accessToken = ""
	svc.mu.Unlock()
	if err := svc.forceSync(context.Background()); !errors.Is(err, ErrSignInNotSaved) {
		t.Fatalf("second refresh = %v, want the unsaved token reported again", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.refreshes != 2 {
		t.Fatalf("refreshes = %d", env.refreshes)
	}
}

func TestService_LoginSnapshotIsNeverNewerThanItsData(t *testing.T) {
	env := newVaultTestEnv(t)
	env.mu.Lock()
	env.onSync = func() {
		env.mu.Lock()
		env.revDate = env.revDate.Add(time.Minute)
		c := env.ciphers["c-1"]
		c.Name = mustEncString(t, "Edited elsewhere", env.cipherKey)
		env.ciphers["c-1"] = c
		env.onSync = nil
		env.mu.Unlock()
	}
	env.mu.Unlock()
	svc := loggedInTestService(t, env)
	if err := svc.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.GetCipher("c-1"); c.Name != "Edited elsewhere" {
		t.Fatalf("a change made during login was never fetched: %q", c.Name)
	}
}

func TestService_UnlockStartedBeforeALockNeverPublishes(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	svc.Lock()

	gen := svc.attemptGen()
	svc.Lock() // the system sleeps while the unlock is still deriving keys
	if err := svc.unlock(context.Background(), env.userKey, gen); !errors.Is(err, ErrLocked) {
		t.Fatalf("unlock after a lock = %v, want ErrLocked", err)
	}
	if st := svc.Status(); st != StatusLocked {
		t.Fatalf("status = %v, want locked", st)
	}

	gen = svc.attemptGen()
	if err := svc.Logout(context.Background(), newMemSecretStore()); err != nil {
		t.Fatal(err)
	}
	if err := svc.unlock(context.Background(), env.userKey, gen); !errors.Is(err, ErrLocked) && !errors.Is(err, ErrLoggedOut) {
		t.Fatalf("unlock after logout = %v, want it refused", err)
	}
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if svc.status == StatusUnlocked || svc.snapshot != nil {
		t.Fatal("an unlock finished after logout")
	}
}

func TestService_RealtimeConnectCatchesUpOnMissedChanges(t *testing.T) {
	env := newVaultTestEnv(t)
	rt := &fakeRealtimeClient{events: make(chan realtime.Event), connect: true}
	svc, err := NewService(ServiceConfig{
		Store: store.NewFileStore(t.TempDir()), Secrets: newMemSecretStore(), HTTPClient: env.server.Client(),
		NewRealtimeClient: func(string) (realtime.Client, error) { return rt, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	// A change lands while the notification connection is down.
	env.mu.Lock()
	env.revDate = env.revDate.Add(time.Minute)
	c := env.ciphers["c-1"]
	c.Name = mustEncString(t, "Changed while offline", env.cipherKey)
	env.ciphers["c-1"] = c
	env.mu.Unlock()

	if err := svc.StartRealtime(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, _ := svc.GetCipher("c-1"); got != nil && got.Name == "Changed while offline" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("reconnecting did not fetch the change made while disconnected")
		}
		runtime.Gosched()
	}
}
