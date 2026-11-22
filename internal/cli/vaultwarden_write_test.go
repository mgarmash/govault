package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writesEnabled turns on the write suite against real servers, which
// creates, edits and deletes items of its own.
func writesEnabled() bool { return os.Getenv("GV_WRITE_TESTS") == "1" }

// checkWrites changes only objects named with a prefix unique to this run
// and removes every one of them before it returns, also after a failure,
// then checks every other item kept its revision.
func (vw *vwRun) checkWrites(t *testing.T) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	prefix := "gv-write-test-" + hex.EncodeToString(b[:])
	before := vw.revisions(t)
	// A defer, not t.Cleanup: it runs on t.Fatal too, before the suite
	// locks and logs out.
	defer func() {
		vw.cleanUp(t, prefix)
		after := vw.revisions(t)
		for id, rev := range before {
			if after[id] != rev {
				t.Errorf("item %s that the suite did not create changed: revision %s, now %q", id, rev, after[id])
			}
		}
		for id := range after {
			if _, ok := before[id]; !ok {
				t.Errorf("item %s the suite created is still there", id)
			}
		}
		var folders []struct{ Name string }
		_ = json.Unmarshal([]byte(vw.must(t, "list", "folders")), &folders)
		for _, f := range folders {
			if strings.HasPrefix(f.Name, prefix) {
				t.Errorf("folder %q is still there", f.Name)
			}
		}
		t.Logf("ok: cleanup left no %s objects; %d other items unchanged", prefix, len(before))
	}()
	id := func(out string) string {
		var o struct{ ID string }
		if err := json.Unmarshal([]byte(out), &o); err != nil || o.ID == "" {
			t.Fatalf("no id in the output: %v", err)
		}
		return o.ID
	}

	folder := id(vw.must(t, "create", "folder", b64(`{"name":"`+prefix+` folder"}`)))
	item := id(vw.must(t, "create", "item", b64(`{"type":1,"name":"`+prefix+` login","folderId":"`+folder+`",`+
		`"fields":[{"name":"f","value":"v","type":0}],"login":{"username":"u","password":"p1","uris":[{"uri":"https://`+prefix+`.example.com"}]}}`)))
	if got := vw.must(t, "get", "password", item); got != "p1" {
		t.Fatal("the created item has the wrong password")
	}
	vw.must(t, "edit", "item", item, b64(`{"type":1,"name":"`+prefix+` edited","folderId":"`+folder+`","login":{"username":"u","password":"p2"}}`))
	if got := vw.must(t, "get", "password", item); got != "p2" {
		t.Fatal("the edit did not change the password")
	}
	vw.must(t, "edit", "folder", folder, b64(`{"name":"`+prefix+` folder renamed"}`))

	file := filepath.Join(t.TempDir(), prefix+".txt")
	if err := os.WriteFile(file, []byte("attachment of "+prefix), 0o600); err != nil {
		t.Fatal(err)
	}
	r := vw.run("create", "attachment", "--file", file, "--itemid", item)
	switch {
	case r.code == 0:
		var it struct{ Attachments []struct{ ID string } }
		_ = json.Unmarshal([]byte(r.out), &it)
		if len(it.Attachments) != 1 {
			t.Fatal("the attachment is missing")
		}
		if got := vw.must(t, "get", "attachment", prefix+".txt", "--itemid", item, "--raw"); got != "attachment of "+prefix {
			t.Fatal("the attachment does not round-trip")
		}
		vw.must(t, "delete", "attachment", it.Attachments[0].ID, "--itemid", item)
	case strings.Contains(r.err, "Premium"):
		t.Log("attachments skipped: the account has no premium")
	default:
		t.Fatalf("create attachment: %s", r.err)
	}

	switch r := vw.run("archive", "item", item); {
	case r.code == 0:
		vw.must(t, "restore", "item", item)
		t.Log("ok: archive and unarchive")
	case strings.Contains(r.err, "Premium"):
		t.Log("archive refused: the account has no premium")
	default:
		t.Fatalf("archive: %s", r.err)
	}
	vw.must(t, "delete", "item", item)
	vw.must(t, "restore", "item", item)
	vw.must(t, "sync", "-f")
	vw.must(t, "delete", "item", item, "--permanent")
	if r := vw.run("get", "item", item); r.err != "Not found." {
		t.Fatalf("after a permanent delete: %q", r.err)
	}
	vw.must(t, "delete", "folder", folder)
	t.Log("ok: create/edit/delete folder and item, attachment, trash, restore, permanent delete")
}

// cleanUp removes every item and folder named with prefix.
func (vw *vwRun) cleanUp(t *testing.T, prefix string) {
	_ = vw.run("sync", "-f")
	for _, args := range [][]string{{"list", "items", "--search", prefix}, {"list", "items", "--search", prefix, "--trash"}} {
		var items []struct{ ID, Name string }
		_ = json.Unmarshal([]byte(vw.run(args...).out), &items)
		for _, it := range items {
			if strings.HasPrefix(it.Name, prefix) {
				if r := vw.run("delete", "item", it.ID, "--permanent"); r.code != 0 {
					t.Errorf("cleanup of item %s: %s", it.ID, r.err)
				}
			}
		}
	}
	var folders []struct{ ID, Name string }
	_ = json.Unmarshal([]byte(vw.run("list", "folders", "--search", prefix).out), &folders)
	for _, f := range folders {
		if strings.HasPrefix(f.Name, prefix) {
			if r := vw.run("delete", "folder", f.ID); r.code != 0 {
				t.Errorf("cleanup of folder %s: %s", f.ID, r.err)
			}
		}
	}
}
