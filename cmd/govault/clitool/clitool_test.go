//go:build darwin

package clitool

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		SearchDirs:   []string{filepath.Join(root, "first", "bin"), filepath.Join(root, "usr", "local", "bin"), filepath.Join(root, "other", "bin")},
		// The tests own their directories; macOS requires root or an
		// administrator.
		TrustedOwner: `[ "$1" = "$(/usr/bin/id -u)" ]`,
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
	// Searched after the link: another copy, which does not run instead.
	if r := f.tool.Inspect(); r.Shadow != "" || r.Later != other {
		t.Fatalf("report = %+v, want %q later on the PATH", r, other)
	}
	first := filepath.Join(f.root, "first", "bin", "gv")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := f.tool.Inspect(); r.Shadow != first {
		t.Fatalf("shadow = %q, want %q", r.Shadow, first)
	}
}

// An untrusted copy offers no install or repair, and Apply refuses them,
// but an installed link can still be removed.
func TestUntrustedCopiesCannotInstall(t *testing.T) {
	f := newFixture(t)
	f.tool.Trust = func(string, string) error { return ErrUntrusted }
	r := f.tool.Inspect()
	if r.Untrusted == nil || len(r.Actions()) != 0 {
		t.Fatalf("report = %+v, actions %v", r, r.Actions())
	}
	if err := f.tool.Apply(Install, "p"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("install = %v", err)
	}
	if _, err := os.Lstat(f.tool.Link); err == nil {
		t.Fatal("an untrusted copy was linked")
	}
	f.tool.Trust = nil
	if err := f.tool.Apply(Install, "p"); err != nil {
		t.Fatal(err)
	}
	f.tool.Trust = func(string, string) error { return ErrUntrusted }
	if a := f.tool.Inspect().Actions(); len(a) != 1 || a[0] != Uninstall {
		t.Fatalf("actions of an installed untrusted copy = %v", a)
	}
	if err := f.tool.Apply(Uninstall, "p"); err != nil {
		t.Fatal(err)
	}
}

// The real trust check refuses a bundle outside /Applications.
func TestTrustRequiresTheApplicationsBundle(t *testing.T) {
	t.Setenv(DeveloperOverride, "")
	f := newFixture(t)
	if err := trustInstall(f.tool.Bundled, filepath.Dir(f.tool.Link)); !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), TrustedBundle) {
		t.Fatalf("trust = %v", err)
	}
}

// Paths others can change are refused, as are their descendants.
func TestSafeAncestorsRefusesWritablePaths(t *testing.T) {
	trusted := func(uint32) bool { return true }
	root := t.TempDir()
	open := filepath.Join(root, "open")
	if err := os.MkdirAll(filepath.Join(open, "GoVault.app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := safeAncestors(filepath.Join(open, "GoVault.app"), trusted); !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), open) {
		t.Fatalf("world-writable ancestor = %v", err)
	}
	if err := safeAncestors(root, func(uint32) bool { return false }); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted owner = %v", err)
	}
}

// The privileged script refuses a link directory others can write, which
// it checks after entering it.
func TestScriptRefusesAWritableLinkDirectory(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Dir(f.tool.Link)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.tool.Apply(Install, "p"); !errors.Is(err, ErrChanged) {
		t.Fatalf("install into a world-writable directory = %v", err)
	}
	if _, err := os.Lstat(f.tool.Link); err == nil {
		t.Fatal("the link was made")
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
