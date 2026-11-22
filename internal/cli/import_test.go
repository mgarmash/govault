package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/bw-exports holds exports the official bw 2026.11.0 wrote of the
// fake server's account: gv must read every one of them.
func TestImportsExportsMadeByBW(t *testing.T) {
	for _, c := range []struct {
		format, file string
		items        int
		env          map[string]string
		args         []string
	}{
		{"bitwardenjson", "plain.json", 10, nil, nil},
		{"bitwardenjson", "account.json", 10, nil, nil},
		{"bitwardenpasswordprotected", "password-pw123.json", 10, map[string]string{"IMPORTPW": "pw123"}, []string{"--passwordenv", "IMPORTPW"}},
		{"bitwardencsv", "plain.csv", 7, nil, nil},
	} {
		t.Run(c.file, func(t *testing.T) {
			g := newGV(t)
			g.login()
			before := countItems(t, g)
			for k, v := range c.env {
				g.env[k] = v
			}
			path, _ := filepath.Abs(filepath.Join("testdata", "bw-exports", c.file))
			out := g.mustRun(append([]string{"import", c.format, path}, c.args...)...)
			if !strings.HasPrefix(out, "Imported "+path) {
				t.Fatalf("import = %q", out)
			}
			if got := countItems(t, g) - before; got != c.items {
				t.Fatalf("imported %d items, want %d", got, c.items)
			}
		})
	}
}

func TestImportRefusesAWrongPasswordAndForeignAccountKey(t *testing.T) {
	g := newGV(t)
	g.login()
	g.env["IMPORTPW"] = "wrong"
	path, _ := filepath.Abs(filepath.Join("testdata", "bw-exports", "password-pw123.json"))
	if r := g.run("import", "bitwardenjson", path, "--passwordenv", "IMPORTPW"); r.code != 1 || !strings.Contains(r.err, "incorrect") {
		t.Fatalf("wrong password = %+v", r)
	}
	if r := g.run("import", "keepass2xml", path); r.code != 1 || !strings.Contains(r.err, "gv cannot import keepass2xml") {
		t.Fatalf("unsupported format = %+v", r)
	}
	if out := g.mustRun("import", "--formats"); out != "Supported input formats:\nbitwardencsv\nbitwardenjson\nbitwardenpasswordprotected" {
		t.Fatalf("--formats = %q", out)
	}
}

func countItems(t *testing.T, g *gvTest) int {
	t.Helper()
	var items []any
	if err := json.Unmarshal([]byte(g.mustRun("list", "items")), &items); err != nil {
		t.Fatal(err)
	}
	var archived []any
	_ = json.Unmarshal([]byte(g.mustRun("list", "items", "--archived")), &archived)
	return len(items) + len(archived)
}
