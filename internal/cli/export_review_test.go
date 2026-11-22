package cli

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// comparable reduces listed items to their decrypted content: what a
// restore must reproduce, without server-assigned IDs and dates.
func comparableItems(t *testing.T, g *gvTest) []string {
	t.Helper()
	folderNames := map[string]string{}
	var fs []struct{ ID, Name string }
	_ = json.Unmarshal([]byte(g.mustRun("list", "folders")), &fs)
	for _, f := range fs {
		folderNames[f.ID] = f.Name
	}
	var out []string
	for _, args := range [][]string{{"list", "items"}, {"list", "items", "--archived"}} {
		var items []map[string]any
		if err := json.Unmarshal([]byte(g.mustRun(args...)), &items); err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it["organizationId"] != nil {
				continue
			}
			if id, ok := it["folderId"].(string); ok {
				it["folderId"] = folderNames[id]
			}
			// The server dates an archive when it is made.
			if it["archivedDate"] != nil {
				it["archivedDate"] = "archived"
			}
			for _, k := range []string{"id", "revisionDate", "creationDate", "attachments", "collectionIds"} {
				delete(it, k)
			}
			if l, ok := it["login"].(map[string]any); ok {
				delete(l, "passwordRevisionDate")
			}
			raw, _ := json.Marshal(it)
			out = append(out, string(raw))
		}
	}
	sort.Strings(out)
	return out
}

// Each export restores to the same decrypted contents in an emptied vault.
func TestExportRestoresTheSameContents(t *testing.T) {
	for _, c := range []struct {
		name   string
		args   []string
		format string
	}{
		{"json", []string{"--format", "json"}, "bitwardenjson"},
		{"account", []string{"--format", "encrypted_json"}, "bitwardenjson"},
		{"password", []string{"--password", "pw-123"}, "bitwardenjson"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newGV(t)
			g.srv.Configure(func(cfg *fakeserver.Config) { cfg.Premium = true })
			g.login()
			before := comparableItems(t, g)
			file := filepath.Join(t.TempDir(), "export.json")
			g.mustRun(append([]string{"export", "--output", file}, c.args...)...)
			g.srv.Clear()
			g.mustRun("sync", "-f")
			g.env["PW_FILE"] = "pw-123"
			g.mustRun("import", c.format, file, "--passwordenv", "PW_FILE")
			g.mustRun("sync", "-f")
			after := comparableItems(t, g)
			if !slices.Equal(before, after) {
				t.Fatalf("restored contents differ:\nbefore %d items:\n%s\nafter %d items:\n%s", len(before), strings.Join(before, "\n"), len(after), strings.Join(after, "\n"))
			}
		})
	}
}

// A password never yields a plaintext file.
func TestExportPasswordMeansEncrypted(t *testing.T) {
	g := newGV(t)
	g.login()
	dir := t.TempDir()
	out := filepath.Join(dir, "default.json")
	g.mustRun("export", "--password", "pw-123", "--output", out)
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), `"passwordProtected": true`) || strings.Contains(string(data), "gh-secret") {
		t.Fatalf("--password without --format wrote: %.200s", data)
	}
	for _, format := range []string{"csv", "zip"} {
		target := filepath.Join(dir, format)
		r := g.run("export", "--format", format, "--password", "pw-123", "--output", target)
		if r.code != 1 || !strings.Contains(r.err, "cannot be password protected") {
			t.Fatalf("%s with a password = %+v", format, r)
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s with a password opened its output", format)
		}
	}
}

// Field-encrypted items with "data": null, as with a blob beside the
// fields, and every type's body are in the account-key export.
func TestAccountExportKeepsEveryItem(t *testing.T) {
	g := newGV(t)
	g.srv.Mutate(fakeserver.ItemNote, func(it map[string]any, _, _ func(string) any) { it["data"] = nil })
	g.srv.Mutate(fakeserver.ItemCard, func(it map[string]any, _, _ func(string) any) { it["data"] = `{"name":"legacy"}` })
	g.srv.Mutate(fakeserver.ItemEmpty, func(it map[string]any, _, personal func(string) any) {
		it["type"], it["login"] = 6, nil
		it["bankAccount"] = map[string]any{"bankName": personal("First Bank"), "accountNumber": personal("12345")}
	})
	g.login()
	file := filepath.Join(t.TempDir(), "account.json")
	g.mustRun("export", "--format", "encrypted_json", "--output", file)
	var f struct{ Items []map[string]any }
	data, _ := os.ReadFile(file)
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	seen := map[string]map[string]any{}
	for _, it := range f.Items {
		seen[it["id"].(string)] = it
	}
	for _, id := range []string{fakeserver.ItemNote, fakeserver.ItemCard, fakeserver.ItemEmpty} {
		if seen[id] == nil {
			t.Fatalf("item %s is missing from the export", id)
		}
	}
	if seen[fakeserver.ItemEmpty]["bankAccount"] == nil {
		t.Fatal("the bank account body is missing")
	}
}

// An item GoVault cannot read, or a passkey that does not fully decrypt,
// stops every export before anything is written.
func TestExportRefusesIncompleteVaults(t *testing.T) {
	g := newGV(t)
	g.srv.Mutate(fakeserver.ItemEmpty, func(it map[string]any, _, _ func(string) any) {
		it["name"], it["login"], it["data"] = "", nil, "2.blob"
	})
	g.login()
	dir := t.TempDir()
	for _, args := range [][]string{{"--format", "json"}, {"--password", "pw"}, {"--format", "encrypted_json"}, {"--format", "zip"}, {"--format", "csv"}} {
		target := filepath.Join(dir, strings.Join(args, ""))
		r := g.run(append([]string{"export", "--output", target}, args...)...)
		if r.code != 1 || !strings.Contains(r.err, "incomplete") || !strings.Contains(r.err, fakeserver.ItemEmpty) {
			t.Fatalf("export %v = %+v", args, r)
		}
		if _, err := os.Stat(target); err == nil {
			t.Fatalf("export %v wrote a file", args)
		}
	}

	g2 := newGV(t)
	g2.srv.Mutate(fakeserver.ItemGitHubEnt, func(it map[string]any, _, personal func(string) any) {
		it["login"].(map[string]any)["fido2Credentials"] = []map[string]any{{
			"credentialId": personal("cred"), "keyType": personal("public-key"), "keyAlgorithm": personal("ECDSA"), "keyCurve": personal("P-256"),
			"keyValue": "2.not|valid|cipher", "rpId": personal("example.com"), "counter": personal("0"), "discoverable": personal("false"),
			"creationDate": "2026-01-02T03:04:05.000Z",
		}}
	})
	g2.login()
	if r := g2.run("export", "--format", "json", "--output", filepath.Join(dir, "passkey.json")); r.code != 1 || !strings.Contains(r.err, "passkey") {
		t.Fatalf("export with a broken passkey = %+v", r)
	}
}

type failingWriter struct{ n int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		return w.n, errors.New("no space left on device")
	}
	return len(p), nil
}

// A raw export or attachment that cannot be written fails the command.
func TestRawOutputFailuresFail(t *testing.T) {
	g := newGV(t)
	g.login()
	g.stdout = &failingWriter{n: 10}
	if r := g.run("export", "--format", "json", "--raw"); r.code != 1 || !strings.Contains(r.err, "no space left") {
		t.Fatalf("export --raw to a full disk = %+v", r)
	}
	if r := g.run("get", "attachment", fakeserver.AttachmentName, "--itemid", fakeserver.ItemGitHub, "--raw"); r.code != 1 {
		t.Fatalf("attachment --raw to a full disk = %+v", r)
	}
}

// The ZIP export holds the attachments of exactly the items its data.json
// holds, at unique paths, and fails when one does not download.
func TestZipExportIsCompleteAndUnique(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.Premium = true })
	g.login()
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	_ = os.WriteFile(file, []byte("one"), 0o600)
	for _, name := range []string{"a/b", "a:b"} {
		var it struct{ ID string }
		_ = json.Unmarshal([]byte(g.mustRun("create", "item", b64(`{"type":2,"name":"`+name+`","secureNote":{"type":0}}`))), &it)
		g.mustRun("create", "attachment", "--file", file, "--itemid", it.ID)
	}
	// Policy restricts cards: a card's attachment stays out of the ZIP.
	g.srv.Configure(func(c *fakeserver.Config) {
		c.Policies = []map[string]any{{"organizationId": fakeserver.OrgID, "type": 15, "enabled": true, "data": nil}}
	})
	var card struct{ ID string }
	_ = json.Unmarshal([]byte(g.mustRun("get", "item", fakeserver.ItemCard)), &card)
	g.mustRun("create", "attachment", "--file", file, "--itemid", card.ID)
	g.mustRun("sync", "-f")
	zipFile := filepath.Join(dir, "export.zip")
	g.mustRun("export", "--format", "zip", "--output", zipFile)
	zr, err := zip.OpenReader(zipFile)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		if names[strings.ToLower(f.Name)] {
			t.Fatalf("duplicate archive path %s", f.Name)
		}
		names[strings.ToLower(f.Name)] = true
		if strings.HasPrefix(f.Name, "attachments/Visa") {
			t.Fatalf("a restricted item's attachment is in the ZIP: %s", f.Name)
		}
	}
	zr.Close()
	if !names["attachments/a_b/a.txt"] || !names["attachments/a_b_1/a.txt"] {
		t.Fatalf("archive paths = %v", names)
	}

	g.srv.DropAttachmentData(fakeserver.AttachmentID)
	if r := g.run("export", "--format", "zip", "--output", filepath.Join(dir, "broken.zip")); r.code != 1 || !strings.Contains(r.err, "did not download") {
		t.Fatalf("export with a failing attachment = %+v", r)
	}
}

// Import applies the item-type policy before it writes anything.
func TestImportAppliesPolicyBeforeWriting(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) {
		c.Policies = []map[string]any{{"organizationId": fakeserver.OrgID, "type": 15, "enabled": true, "data": nil}}
	})
	g.login()
	file := filepath.Join(t.TempDir(), "in.json")
	_ = os.WriteFile(file, []byte(`{"encrypted":false,"folders":[{"id":"f1","name":"New folder"}],"items":[`+
		`{"type":2,"name":"first","secureNote":{"type":0}},{"type":3,"name":"card","card":{"number":"4111"}}]}`), 0o600)
	before := len(g.srv.Items())
	r := g.run("import", "bitwardenjson", file)
	if r.code != 1 || !strings.Contains(r.err, "policy") {
		t.Fatalf("import = %+v", r)
	}
	if got := len(g.srv.Items()); got != before {
		t.Fatalf("the import created %d items before refusing", got-before)
	}
	for _, req := range g.srv.Requests() {
		if req.Method == "POST" && strings.Contains(req.Path, "folders") {
			t.Fatal("the import created a folder before refusing")
		}
	}
}

// Input files are bounded before they are read.
func TestInputFilesAreBoundedBeforeReading(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.Premium = true })
	g.login()
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(101 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if r := g.run("create", "attachment", "--file", big, "--itemid", fakeserver.ItemGitHub); r.code != 1 || !strings.Contains(r.err, "100 MiB") {
		t.Fatalf("oversize attachment = %+v", r)
	}
	if r := g.run("import", "bitwardenjson", big); r.code != 1 || !strings.Contains(r.err, "64 MiB") {
		t.Fatalf("oversize import = %+v", r)
	}
	if r := g.run("import", "bitwardenjson", dir); r.code != 1 || !strings.Contains(r.err, "not a regular file") {
		t.Fatalf("directory import = %+v", r)
	}
}

// No export is written that import would refuse for its size.
func TestExportRefusesFilesImportCannotRead(t *testing.T) {
	g := newGV(t)
	g.login()
	saved := maxExportSize
	maxExportSize = 1 << 20
	defer func() { maxExportSize = saved }()
	g.mustRun("create", "item", b64(`{"type":2,"name":"big","notes":"`+strings.Repeat("x", 1<<20)+`","secureNote":{"type":0}}`))
	target := filepath.Join(t.TempDir(), "big.json")
	if r := g.run("export", "--format", "json", "--output", target); r.code != 1 || !strings.Contains(r.err, "larger than 1 MiB") {
		t.Fatalf("oversize export = %+v", r)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("the oversize export was written")
	}
}
