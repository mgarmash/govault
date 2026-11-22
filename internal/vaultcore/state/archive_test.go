package state

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func ids(s []CipherSummary) []string {
	var out []string
	for _, c := range s {
		out = append(out, c.ID)
	}
	return out
}

func TestService_ArchiveHidesItemsEverywhereButArchive(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	if !svc.CanArchive() {
		t.Fatal("a premium account cannot archive")
	}
	c, _ := svc.GetCipher("c-1")
	if !c.Favorite {
		c.Favorite = true
		if _, err := svc.SaveCipher(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.ArchiveCipher(ctx, "c-1"); err != nil {
		t.Fatal(err)
	}
	env.mu.Lock()
	calls := slices.Clone(env.archiveCalls)
	env.mu.Unlock()
	if len(calls) != 1 || calls[0] != "PUT /api/ciphers/c-1/archive body=" {
		t.Fatalf("archive requests = %q", calls)
	}

	for name, f := range map[string]SearchFilter{
		"all items": {Category: FilterAll},
		"favorites": {Category: FilterFavorites},
		"folder":    {FolderID: "f-work"},
		"logins":    {Type: ptrType(api.CipherTypeLogin)},
	} {
		if slices.Contains(ids(svc.Search("", f)), "c-1") || slices.Contains(ids(svc.Search("GitHub", f)), "c-1") {
			t.Fatalf("an archived item shows in %s", name)
		}
	}
	got := svc.Search("", SearchFilter{Category: FilterArchive})
	if len(got) != 1 || got[0].ID != "c-1" || !got[0].Archived {
		t.Fatalf("Archive = %+v", got)
	}
	if found := ids(svc.Search("GitHub", SearchFilter{Category: FilterArchive})); !slices.Contains(found, "c-1") {
		t.Fatal("search in Archive misses the archived item")
	}

	// Editing an archived item keeps it archived: the update carries its
	// archive date, which the server would otherwise clear.
	c, _ = svc.GetCipher("c-1")
	c.Name = "GitHub (archived, renamed)"
	if _, err := svc.SaveCipher(ctx, c); err != nil {
		t.Fatal(err)
	}
	var sent map[string]json.RawMessage
	env.mu.Lock()
	_ = json.Unmarshal(env.lastBody, &sent)
	env.mu.Unlock()
	if string(sent["archivedDate"]) == "null" || len(sent["archivedDate"]) == 0 {
		t.Fatalf("an edit of an archived item sent archivedDate %s", sent["archivedDate"])
	}
	if c, _ := svc.GetCipher("c-1"); c.ArchivedDate == nil {
		t.Fatal("editing unarchived the item")
	}

	if err := svc.UnarchiveCipher(ctx, "c-1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids(svc.Search("", SearchFilter{Category: FilterAll})), "c-1") || len(svc.Search("", SearchFilter{Category: FilterArchive})) != 0 {
		t.Fatal("unarchive did not bring the item back")
	}
}

func ptrType(t api.CipherType) *api.CipherType { return &t }

func TestService_ArchiveSurvivesLockAndUnlockOffline(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatal(err)
	}
	relockOffline(t, svc, env)
	if got := ids(svc.Search("", SearchFilter{Category: FilterArchive})); !slices.Equal(got, []string{"c-1"}) {
		t.Fatalf("Archive after unlock = %v", got)
	}
}

func TestService_ArchiveRules(t *testing.T) {
	env := newVaultTestEnv(t)
	no := false
	rev := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	name, _ := crypto.EncryptString("Shared read-only", env.userKey)
	env.ciphers["c-ro"] = api.EncryptedCipher{ID: "c-ro", Type: api.CipherTypeSecureNote, Name: name, Edit: &no, RevisionDate: &rev, SecureNote: &api.EncryptedSecureNote{}}
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// Like a favorite, the archive is per user: read-only items qualify.
	if err := svc.ArchiveCipher(ctx, "c-ro"); err != nil {
		t.Fatalf("archiving a read-only item = %v", err)
	}
	if err := svc.ArchiveCipher(ctx, "c-trash"); !errors.Is(err, ErrCipherInTrash) {
		t.Fatalf("archiving an item in Trash = %v", err)
	}
	if err := svc.ArchiveCipher(ctx, "missing"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("archiving a missing item = %v", err)
	}
}

func TestService_ArchiveNeedsPremiumButUnarchiveDoesNot(t *testing.T) {
	env := newVaultTestEnv(t)
	env.noPremium = true
	archived := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	c := env.ciphers["c-1"]
	c.ArchivedDate = &archived
	env.ciphers["c-1"] = c
	svc := loggedInTestService(t, env)
	if svc.CanArchive() {
		t.Fatal("an account without premium can archive")
	}
	if err := svc.ArchiveCipher(context.Background(), "c-trash-x"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("archive of a missing item = %v", err)
	}
	if err := svc.UnarchiveCipher(context.Background(), "c-1"); err != nil {
		t.Fatalf("unarchive without premium = %v, want allowed", err)
	}
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrPremiumRequired) {
		t.Fatalf("archive without premium = %v, want ErrPremiumRequired", err)
	}
}

func TestService_ArchiveOnAnOlderServerIsReported(t *testing.T) {
	env := newVaultTestEnv(t)
	env.oldServer = true
	svc := loggedInTestService(t, env)
	if err := svc.ArchiveCipher(context.Background(), "c-1"); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("archive on an older server = %v, want ErrArchiveUnsupported", err)
	}
	if c, _ := svc.GetCipher("c-1"); c.ArchivedDate != nil {
		t.Fatal("the item looks archived after the server refused")
	}
}
