//go:build unix

package clitool

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type fixture struct {
	t    *testing.T
	root string
	tool *Tool
}

// bundle makes a GoVault.app with gv under dir and returns its gv.
func bundle(t *testing.T, dir string) string {
	gv := filepath.Join(dir, "GoVault.app", "Contents", "MacOS", "gv")
	if err := os.MkdirAll(filepath.Dir(gv), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gv, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return gv
}

func newFixture(t *testing.T) *fixture {
	root := t.TempDir()
	f := &fixture{t: t, root: root}
	f.tool = &Tool{
		Bundled:      bundle(t, filepath.Join(root, "Applications")),
		Link:         filepath.Join(root, "usr", "local", "bin", "gv"),
		HomebrewBins: []string{filepath.Join(root, "homebrew", "bin")},
		SearchDirs:   []string{filepath.Join(root, "usr", "local", "bin"), filepath.Join(root, "other", "bin")},
		// The script runs as the user here; macOS runs it as an administrator.
		RunPrivileged: func(script, prompt string) error {
			out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == exitChanged {
				return ErrChanged
			}
			if err != nil {
				t.Logf("%s", out)
			}
			return err
		},
	}
	return f
}

func (f *fixture) state() State { return f.tool.Inspect().State }

func TestInstallRepairUninstall(t *testing.T) {
	f := newFixture(t)
	if s := f.state(); s != NotInstalled {
		t.Fatalf("initial state = %v", s)
	}
	if err := f.tool.Apply(Install, "p"); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s != Installed {
		t.Fatalf("after install = %v", s)
	}
	// The app moved: the link now points into a bundle that is gone.
	moved := bundle(t, filepath.Join(f.root, "Elsewhere"))
	if err := os.RemoveAll(filepath.Join(f.root, "Applications")); err != nil {
		t.Fatal(err)
	}
	f.tool.Bundled = moved
	if s := f.state(); s != Broken {
		t.Fatalf("after moving the app = %v", s)
	}
	if err := f.tool.Apply(Repair, "p"); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s != Installed {
		t.Fatalf("after repair = %v", s)
	}
	if err := f.tool.Apply(Uninstall, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.tool.Link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link after uninstall: %v", err)
	}
}

func TestNeverReplacesAForeignGV(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.tool.Link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.tool.Link, []byte("someone else's gv"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := f.tool.Inspect()
	if r.State != Foreign || len(r.Actions()) != 0 {
		t.Fatalf("report = %+v, actions %v", r, r.Actions())
	}
	// Even a stale request finds the file and changes nothing.
	for _, a := range []Action{Install, Repair, Uninstall} {
		if err := f.tool.Apply(a, "p"); !errors.Is(err, ErrChanged) {
			t.Fatalf("action %d over a foreign gv = %v", a, err)
		}
	}
	if b, _ := os.ReadFile(f.tool.Link); string(b) != "someone else's gv" {
		t.Fatal("the foreign gv changed")
	}
}

func TestHomebrewAndShadowedInstalls(t *testing.T) {
	f := newFixture(t)
	brew := filepath.Join(f.tool.HomebrewBins[0], "gv")
	if err := os.MkdirAll(filepath.Dir(brew), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.tool.Bundled, brew); err != nil {
		t.Fatal(err)
	}
	if r := f.tool.Inspect(); r.State != Homebrew || r.Path != brew || len(r.Actions()) != 0 {
		t.Fatalf("Homebrew report = %+v", r)
	}
	other := filepath.Join(f.root, "other", "bin", "gv")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := f.tool.Inspect(); r.Shadow != other {
		t.Fatalf("shadow = %q, want %q", r.Shadow, other)
	}
}

func TestUnavailableWithoutBundledGV(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.tool.Bundled); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s != Unavailable {
		t.Fatalf("state = %v", s)
	}
}

func TestScriptsQuotePaths(t *testing.T) {
	f := newFixture(t)
	f.tool.Bundled = bundle(t, filepath.Join(f.root, "it's here"))
	if err := f.tool.Apply(Install, "p"); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(f.tool.Link); target != f.tool.Bundled {
		t.Fatalf("link target = %q", target)
	}
}
