package state_test

import (
	"context"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type memSecrets map[string]string

func (m memSecrets) Get(a string) (string, bool, error) { v, ok := m[a]; return v, ok, nil }
func (m memSecrets) Set(a, v string) error              { m[a] = v; return nil }
func (m memSecrets) Delete(a string) error              { delete(m, a); return nil }

// Moving items to a folder is one PUT /api/ciphers/move, after which the
// synced vault has them there.
func TestMoveCiphersToAFolder(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	svc, err := state.NewService(state.ServiceConfig{Store: store.NewFileStore(t.TempDir()), Secrets: memSecrets{}, DeviceID: "dev", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, state.LoginRequest{ServerURL: srv.URL(), Email: fakeserver.Email, MasterPassword: []byte(fakeserver.Password)}); err != nil {
		t.Fatal(err)
	}
	ids := []string{fakeserver.ItemGitHubEnt, fakeserver.ItemCard}
	folder := fakeserver.FolderWork
	if err := svc.MoveCiphers(ctx, ids, &folder); err != nil {
		t.Fatal(err)
	}
	if srv.Moves() != 1 {
		t.Fatalf("%d move requests, want 1", srv.Moves())
	}
	for _, id := range ids {
		c, err := svc.GetCipher(id)
		if err != nil || c.FolderID == nil || *c.FolderID != folder {
			t.Fatalf("%s after the move: %+v, %v", id, c, err)
		}
	}
	if err := svc.MoveCiphers(ctx, ids, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.GetCipher(fakeserver.ItemCard); c.FolderID != nil {
		t.Fatalf("moved to No Folder, the item has folder %v", *c.FolderID)
	}
}
