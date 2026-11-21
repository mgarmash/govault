package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func login(id, name, user, pw string) *state.Cipher {
	return &state.Cipher{ID: id, Type: api.CipherTypeLogin, Name: name, Login: &state.Login{Username: user, Password: pw, URIs: []state.LoginURI{{URI: "https://" + strings.ToLower(name) + ".com"}}}}
}

func TestEncryptedExportRoundTrip(t *testing.T) {
	work := "f-work"
	org := "org-1"
	trashed := login("c-old", "Old", "o", "x")
	now := time.Now()
	trashed.DeletedDate = &now
	shared := login("c-org", "Shared", "s", "y")
	shared.OrganizationID = &org
	gh := login("c-gh", "GitHub", "alice", "gh-secret")
	gh.FolderID = &work
	gh.Fields = []state.CustomField{{Name: "PIN", Value: "1234", Type: 1}}
	note := &state.Cipher{ID: "c-note", Type: api.CipherTypeSecureNote, Name: "Note", Notes: "body", SecureNote: &state.SecureNote{}}
	v := Build([]*state.Cipher{gh, note, shared, trashed}, []state.Folder{{ID: work, Name: "Work"}})
	if len(v.Items) != 2 {
		t.Fatalf("Build kept %d items, want personal active only", len(v.Items))
	}

	for _, cfg := range []crypto.KDFConfig{
		{Type: crypto.KDFPBKDF2, Iterations: 5000},
		{Type: crypto.KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1},
	} {
		data, err := EncryptWithPassword(v, []byte("backup pass"), cfg)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		_ = json.Unmarshal(data, &raw)
		for _, k := range []string{"encrypted", "passwordProtected", "salt", "kdfType", "kdfIterations", "kdfMemory", "kdfParallelism", "encKeyValidation_DO_NOT_EDIT", "data"} {
			if _, ok := raw[k]; !ok {
				t.Fatalf("export lacks %q", k)
			}
		}
		if strings.Contains(string(data), "gh-secret") {
			t.Fatal("export contains plaintext")
		}
		if need, err := NeedsPassword(data); !need || err != nil {
			t.Fatalf("NeedsPassword = (%v, %v)", need, err)
		}
		if _, err := Read(data, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("wrong password = %v", err)
		}
		got, err := Read(data, []byte("backup pass"))
		if err != nil || len(got.Items) != 2 || got.Encrypted {
			t.Fatalf("Read = (%+v, %v)", got, err)
		}
		it := got.Items[0]
		if it.Name != "GitHub" || val(it.Login.Password) != "gh-secret" || val(it.FolderID) != work || val(it.Fields[0].Value) != "1234" {
			t.Fatalf("round-trip item = %+v", it)
		}
	}

	plain, _ := json.Marshal(v)
	if got, err := Read(plain, nil); err != nil || len(got.Items) != 2 {
		t.Fatalf("plain export = (%v, %v)", got, err)
	}
	if _, err := Read([]byte(`{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"x","data":"y"}`), nil); !errors.Is(err, ErrAccountRestricted) {
		t.Fatalf("account-restricted export = %v", err)
	}
}

type fakeWriter struct {
	ciphers map[string]*state.Cipher
	folders []state.Folder
	saves   []string
	next    int
}

func (f *fakeWriter) GetCipher(id string) (*state.Cipher, error) {
	c, ok := f.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (f *fakeWriter) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	if c.ID == "" {
		f.next++
		c.ID = fmt.Sprintf("new-%d", f.next)
	}
	f.saves = append(f.saves, c.ID)
	f.ciphers[c.ID] = c
	return c, nil
}

func (f *fakeWriter) Folders() []state.Folder { return f.folders }

func (f *fakeWriter) SaveFolder(_ context.Context, fo *state.Folder) (*state.Folder, error) {
	fo.ID = "f-" + strings.ToLower(fo.Name)
	f.folders = append(f.folders, *fo)
	return fo, nil
}

func TestPlanClassifiesAndAppliesOnlyApproved(t *testing.T) {
	same := login("c-same", "Same", "u", "pw")
	changed := login("c-changed", "Changed", "u", "old")
	readOnly := login("c-ro", "Locked", "u", "old")
	readOnly.ReadOnly = true
	current := []*state.Cipher{same, changed, readOnly}

	backupChanged := FromCipher(login("other-id", "Changed", "u", "new"))
	backupChanged.Notes = opt("added")
	backupRO := FromCipher(login("c-ro", "Locked", "u", "new"))
	backup := &Vault{
		Folders: []Folder{{ID: "bf-1", Name: "Imported"}},
		Items: []Item{
			FromCipher(same),
			backupChanged,
			backupRO,
			FromCipher(login("c-brand-new", "Brand New", "n", "pw")),
		},
	}
	backup.Items[3].FolderID = opt("bf-1")

	p := BuildPlan(backup, current, nil)
	classes := []Class{ClassIdentical, ClassConflict, ClassConflict, ClassNew}
	for i, e := range p.Entries {
		if e.Class != classes[i] {
			t.Fatalf("entry %d (%s) class = %v, want %v", i, e.Item.Name, e.Class, classes[i])
		}
	}
	if d := strings.Join(p.Entries[1].Diff, ","); d != "Notes,Password" {
		t.Fatalf("conflict diff = %q", d)
	}
	if c := p.Counts(); c.Create != 1 || c.Update != 0 || c.Skip != 3 {
		t.Fatalf("default counts = %+v; conflicts must default to skip", c)
	}
	if p.Entries[2].CanUpdate || p.Entries[2].SetAction(ActionUpdate) {
		t.Fatal("read-only conflict accepted Update")
	}

	w := &fakeWriter{ciphers: map[string]*state.Cipher{}}
	for _, c := range current {
		cp := *c
		w.ciphers[c.ID] = &cp
	}
	res := Apply(context.Background(), w, p)
	if res.Created != 1 || res.Updated != 0 || res.Skipped != 3 || res.Err != nil {
		t.Fatalf("default apply = %+v", res)
	}
	if w.ciphers["c-changed"].Login.Password != "old" || w.ciphers["c-ro"].Login.Password != "old" {
		t.Fatal("a conflict was overwritten without approval")
	}
	created := w.ciphers["new-1"]
	if created == nil || created.Name != "Brand New" || created.FolderID == nil || *created.FolderID != "f-imported" {
		t.Fatalf("created = %+v", created)
	}

	p = BuildPlan(backup, current, nil)
	p.Entries[3].SetAction(ActionSkip)
	if !p.Entries[1].SetAction(ActionUpdate) {
		t.Fatal("editable conflict rejected Update")
	}
	p.Entries[2].SetAction(ActionCreate)
	res = Apply(context.Background(), w, p)
	if res.Created != 1 || res.Updated != 1 || res.Err != nil {
		t.Fatalf("approved apply = %+v", res)
	}
	if got := w.ciphers["c-changed"]; got.Login.Password != "new" || got.Notes != "added" || got.ID != "c-changed" {
		t.Fatalf("updated = %+v", got)
	}
	if w.ciphers["c-ro"].Login.Password != "old" || w.ciphers["new-2"].Login.Password != "new" {
		t.Fatal("read-only conflict was changed instead of copied")
	}
}
