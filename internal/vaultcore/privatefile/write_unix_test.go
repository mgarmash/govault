//go:build unix

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileIsPrivateAndReplacesAtomically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v", fi.Mode().Perm())
	}
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	got, _ := os.ReadFile(path)
	if fi.Mode().Perm() != 0o600 || string(got) != "new" {
		t.Fatalf("mode %v, content %q", fi.Mode().Perm(), got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left temporary files: %v", entries)
	}
}
