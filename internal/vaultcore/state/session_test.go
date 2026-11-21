package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/store"
)

func TestService_StaleSyncCannotCrossSessions(t *testing.T) {
	envA := newVaultTestEnv(t)
	envB := newVaultTestEnv(t)
	envB.profileID, envB.accessTok = "acct-b", "tok-b"

	fileStore := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	svc, err := NewService(ServiceConfig{Store: fileStore, Secrets: secrets, HTTPClient: envA.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: envA.server.URL, Email: envA.email, MasterPassword: envA.password}); err != nil {
		t.Fatalf("Login A: %v", err)
	}

	gate := make(chan struct{})
	defer close(gate)
	envA.mu.Lock()
	envA.revDate = envA.revDate.Add(time.Hour)
	envA.syncStarted, envA.syncGate = make(chan struct{}), gate
	started := envA.syncStarted
	envA.mu.Unlock()

	syncErr := make(chan error, 1)
	go func() { syncErr <- svc.SyncNow(ctx) }()
	<-started

	if err := svc.Logout(ctx, secrets); err != nil {
		t.Fatalf("Logout A: %v", err)
	}
	if err := svc.Login(ctx, LoginRequest{ServerURL: envB.server.URL, Email: envB.email, MasterPassword: envB.password}); err != nil {
		t.Fatalf("Login B: %v", err)
	}

	select {
	case err := <-syncErr:
		if err == nil {
			t.Fatal("stale sync of account A succeeded after logout")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale sync was not cancelled by logout")
	}

	if _, err := fileStore.LoadSnapshot("acct-1"); !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Fatalf("stale sync recreated the deleted snapshot of A: %v", err)
	}
	if snap, err := fileStore.LoadSnapshot("acct-b"); err != nil || snap.ServerURL != envB.server.URL {
		t.Fatalf("snapshot of B = (%+v, %v)", snap, err)
	}
	envA.mu.Lock()
	seen := append([]string(nil), envA.authSeen...)
	envA.mu.Unlock()
	for _, auth := range seen {
		if auth == "Bearer tok-b" {
			t.Fatal("token of account B was sent to the server of account A")
		}
	}
	svc.mu.RLock()
	accountID := svc.accountID
	svc.mu.RUnlock()
	if accountID != "acct-b" || len(svc.Search("", SearchFilter{})) == 0 {
		t.Fatalf("state of B was overwritten: account=%q", accountID)
	}
}
