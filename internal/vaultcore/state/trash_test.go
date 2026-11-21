package state

import (
	"context"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func TestService_EmptyTrashSkipsReadOnly(t *testing.T) {
	env := newVaultTestEnv(t)
	deleted := time.Now().UTC().Add(-time.Hour)
	no := false
	name, _ := crypto.EncryptString("Shared Old Note", env.userKey)
	env.ciphers["c-trash-ro"] = api.EncryptedCipher{
		ID: "c-trash-ro", Type: api.CipherTypeSecureNote, Name: name,
		DeletedDate: &deleted, Edit: &no, SecureNote: &api.EncryptedSecureNote{},
	}
	svc := loggedInTestService(t, env)

	res, err := svc.EmptyTrash(context.Background())
	if err != nil || res.Deleted != 1 || res.ReadOnly != 1 {
		t.Fatalf("EmptyTrash = (%+v, %v)", res, err)
	}
	env.mu.Lock()
	_, gone := env.ciphers["c-trash"]
	_, kept := env.ciphers["c-trash-ro"]
	env.mu.Unlock()
	if gone || !kept {
		t.Fatalf("server state: c-trash present=%v, c-trash-ro present=%v", gone, kept)
	}
	trash := svc.Search("", SearchFilter{Category: FilterTrash})
	if len(trash) != 1 || trash[0].ID != "c-trash-ro" {
		t.Fatalf("trash after EmptyTrash = %+v", trash)
	}
	if active := svc.Search("", SearchFilter{}); len(active) != 1 {
		t.Fatalf("active items changed: %+v", active)
	}
}
