package state

import (
	"context"
	"errors"
	"testing"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/store"
)

// relockOffline locks, stops the server and unlocks from the encrypted
// snapshot alone, as a user would before the next sync.
func relockOffline(t *testing.T, svc *Service, env *vaultTestEnv) {
	t.Helper()
	svc.Lock()
	env.server.Close()
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
		t.Fatalf("offline unlock: %v", err)
	}
}

func TestService_ChangesReachTheSnapshotBeforeSuccess(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	c, _ := svc.GetCipher("c-1")
	c.Name, c.Favorite = "GitHub (edited)", true
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveCipher(ctx, &Cipher{Type: api.CipherTypeSecureNote, Name: "Created", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SoftDeleteCipher(ctx, "c-created"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveFolder(ctx, &Folder{Name: "Travel"}); err != nil {
		t.Fatal(err)
	}

	relockOffline(t, svc, env)
	if got, err := svc.GetCipher("c-1"); err != nil || got.Name != "GitHub (edited)" || !got.Favorite {
		t.Fatalf("saved item after unlock = %+v, %v", got, err)
	}
	if got, err := svc.GetCipher("c-created"); err != nil || got.DeletedDate == nil {
		t.Fatalf("soft-deleted item after unlock = %+v, %v", got, err)
	}
	found := false
	for _, f := range svc.Folders() {
		found = found || (f.ID == "f-new" && f.Name == "Travel")
	}
	if !found {
		t.Fatalf("new folder missing after unlock: %+v", svc.Folders())
	}
}

func TestService_RestoreDeleteAndFolderDeleteReachTheSnapshot(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	if _, err := svc.SaveCipher(ctx, &Cipher{Type: api.CipherTypeSecureNote, Name: "Created", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	f, err := svc.SaveFolder(ctx, &Folder{Name: "Travel"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := svc.GetCipher("c-1")
	c.FolderID = &f.ID
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := svc.SoftDeleteCipher(ctx, "c-created"); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreCipher(ctx, "c-created"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteFolder(ctx, f.ID); err != nil {
		t.Fatal(err)
	}

	relockOffline(t, svc, env)
	if got, err := svc.GetCipher("c-created"); err != nil || got.DeletedDate != nil {
		t.Fatalf("restored item after unlock = %+v, %v", got, err)
	}
	if got, _ := svc.GetCipher("c-1"); got.FolderID != nil {
		t.Fatalf("item still in the deleted folder after unlock: %v", *got.FolderID)
	}
	for _, f := range svc.Folders() {
		if f.ID == "f-new" {
			t.Fatal("deleted folder back after unlock")
		}
	}
}

func TestService_HardDeleteReachesTheSnapshot(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	if _, err := svc.SaveCipher(ctx, &Cipher{Type: api.CipherTypeSecureNote, Name: "Created", SecureNote: &SecureNote{}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.HardDeleteCipher(ctx, "c-created"); err != nil {
		t.Fatal(err)
	}
	relockOffline(t, svc, env)
	if _, err := svc.GetCipher("c-created"); err == nil {
		t.Fatal("hard-deleted item back after unlock")
	}
}

// flakyStore fails snapshot writes while fail is set.
type flakyStore struct {
	store.Store
	fail bool
}

func (f *flakyStore) SaveSnapshot(snap *store.Snapshot) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.SaveSnapshot(snap)
}

func TestService_FailedLocalCopyReturnsTheCommittedItem(t *testing.T) {
	env := newVaultTestEnv(t)
	fs := &flakyStore{Store: store.NewFileStore(t.TempDir())}
	svc, err := NewService(ServiceConfig{Store: fs, Secrets: newMemSecretStore(), HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Login(context.Background(), LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	fs.fail = true

	saved, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeSecureNote, Name: "Fresh", SecureNote: &SecureNote{}})
	var lc *LocalCopyError
	if !errors.As(err, &lc) || !errors.Is(err, ErrSnapshotNotUpdated) {
		t.Fatalf("SaveCipher error = %v, want *LocalCopyError", err)
	}
	if saved == nil || saved.ID != "c-created" || lc.Cipher == nil || lc.Cipher.ID != "c-created" {
		t.Fatalf("committed item not returned: saved=%+v, carried=%+v", saved, lc.Cipher)
	}
	if got, err := svc.GetCipher("c-created"); err != nil || got.Name != "Fresh" {
		t.Fatalf("memory lacks the committed item: %+v, %v", got, err)
	}
	env.mu.Lock()
	n := len(env.ciphers)
	env.mu.Unlock()

	// A retry is an update of the committed item, not a second create.
	saved.Name = "Fresh 2"
	if _, err := svc.SaveCipher(context.Background(), saved); !errors.As(err, &lc) {
		t.Fatalf("second save = %v", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.ciphers) != n || env.ciphers["c-created"].Name == "" {
		t.Fatalf("server now has %d items, want %d", len(env.ciphers), n)
	}
}

func TestService_SyncFetchedBeforeASaveDoesNotOverwriteIt(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// Another device renames the folder; the sync below fetches that.
	env.mu.Lock()
	f := env.folders["f-work"]
	f.Name = mustEncString(t, "Work (renamed elsewhere)", env.userKey)
	env.folders["f-work"] = f
	env.syncStarted, env.syncGate, env.syncStale = make(chan struct{}), make(chan struct{}), true
	started, gate := env.syncStarted, env.syncGate
	env.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- svc.forceSync(ctx) }()
	<-started
	env.mu.Lock()
	env.syncStarted, env.syncGate, env.syncStale = nil, nil, false
	env.mu.Unlock()

	// The sync holds a vault from before this save.
	c, _ := svc.GetCipher("c-1")
	c.Name = "GitHub (saved during sync)"
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	check := func(where string) {
		t.Helper()
		if got, _ := svc.GetCipher("c-1"); got == nil || got.Name != "GitHub (saved during sync)" {
			t.Fatalf("%s: the save was overwritten by an older sync: %+v", where, got)
		}
		renamed := false
		for _, f := range svc.Folders() {
			renamed = renamed || (f.ID == "f-work" && f.Name == "Work (renamed elsewhere)")
		}
		if !renamed {
			t.Fatalf("%s: the other device change was lost: %+v", where, svc.Folders())
		}
	}
	check("memory")
	relockOffline(t, svc, env)
	check("disk")
}
