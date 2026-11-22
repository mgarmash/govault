package state

import (
	"context"
	"testing"

	"github.com/txchen/govault/internal/vaultcore/api"
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
