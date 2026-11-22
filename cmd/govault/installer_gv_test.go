package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// launcherFunctions is install-linux.sh's gv launcher writer and what it
// needs, to run by itself.
func launcherFunctions(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../scripts/install-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "write_gv_launcher() {")
	const closing = "  } > \"$2\"\n}\n"
	end := strings.Index(text[start:], closing)
	if start < 0 || end < 0 {
		t.Fatal("write_gv_launcher is not in install-linux.sh")
	}
	return `gv_marker="# gv launcher installed by GoVault's install-linux.sh"` + "\n" + text[start:start+end+len(closing)]
}

type launcherFixture struct {
	t                 *testing.T
	dir, bin, image   string
	launcher, extract string
}

// newLauncher installs the launcher for an image under a directory whose
// name holds a quote, as a HOME can.
func newLauncher(t *testing.T) *launcherFixture {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := filepath.Join(t.TempDir(), "o'brien home")
	f := &launcherFixture{t: t, dir: dir, bin: filepath.Join(dir, "bin"), extract: filepath.Join(dir, "extractions")}
	if err := os.MkdirAll(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.image, f.launcher = filepath.Join(f.bin, "govault"), filepath.Join(f.bin, "gv")
	cmd := exec.Command("sh", "-c", launcherFunctions(t)+"\nwrite_gv_launcher \"$1\" \"$2\" && chmod 755 \"$2\"", "sh", f.image, f.launcher)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writing the launcher: %v\n%s", err, out)
	}
	return f
}

// writeImage makes an image whose --appimage-extract gv writes
// squashfs-root/gv printing version, counting extractions; fail makes the
// extraction fail.
func (f *launcherFixture) writeImage(version string, fail bool) {
	f.t.Helper()
	script := "#!/bin/sh\n# " + version + "\n[ \"$1\" = --appimage-extract ] && [ \"$2\" = gv ] || exit 9\n"
	if fail {
		script += "exit 3\n"
	}
	script += "echo x >> '" + strings.ReplaceAll(f.extract, "'", `'\''`) + "'\n" +
		"mkdir -p squashfs-root && printf '#!/bin/sh\\necho " + version + " \"$@\"\\n' > squashfs-root/gv && chmod 755 squashfs-root/gv\n"
	if err := os.WriteFile(f.image, []byte(script), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *launcherFixture) run() (string, error) {
	cmd := exec.Command(f.launcher, "--version")
	cmd.Env = append(os.Environ(), "HOME="+f.dir, "XDG_CACHE_HOME=")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (f *launcherFixture) extractions() int {
	b, _ := os.ReadFile(f.extract)
	return strings.Count(string(b), "x")
}

// The launcher extracts gv once, again after the image's contents change,
// and works under a path with a quote in it.
func TestInstallerGVLauncher(t *testing.T) {
	f := newLauncher(t)
	f.writeImage("v1", false)
	if out, err := f.run(); err != nil || out != "v1 --version" || f.extractions() != 1 {
		t.Fatalf("first run = %q, %v after %d extractions", out, err, f.extractions())
	}
	if out, _ := f.run(); out != "v1 --version" || f.extractions() != 1 {
		t.Fatalf("second run = %q after %d extractions, want no new one", out, f.extractions())
	}
	f.writeImage("v2", false)
	if out, _ := f.run(); out != "v2 --version" || f.extractions() != 2 {
		t.Fatalf("after an update = %q after %d extractions", out, f.extractions())
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".cache", "govault-gv", "gv")); err != nil {
		t.Fatalf("no private cache: %v", err)
	}
}

// A changed image whose gv does not extract is not answered by the gv of
// the old one.
func TestInstallerGVLauncherFailsClosed(t *testing.T) {
	f := newLauncher(t)
	f.writeImage("v1", false)
	if out, err := f.run(); err != nil || out != "v1 --version" {
		t.Fatalf("first run = %q, %v", out, err)
	}
	f.writeImage("v2", true)
	out, err := f.run()
	if err == nil || strings.Contains(out, "v1") || !strings.Contains(out, "was not run") {
		t.Fatalf("run after a failed refresh = %q, %v", out, err)
	}
}

// --uninstall removes the launcher and this user's cache, and leaves
// another program named gv.
func TestInstallerUninstallRemovesTheLauncher(t *testing.T) {
	f := newLauncher(t)
	f.writeImage("v1", false)
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	home := f.dir
	local := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher, _ := os.ReadFile(f.launcher)
	if err := os.WriteFile(filepath.Join(local, "gv"), launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	// The installer runs on Linux only; uname says it is.
	shims := filepath.Join(home, "shims")
	if err := os.MkdirAll(shims, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shims, "uname"), []byte("#!/bin/sh\necho Linux\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "HOME="+home, "XDG_DATA_HOME=", "XDG_CACHE_HOME=", "PATH="+shims+":/usr/bin:/bin")
	cmd := exec.Command("sh", "../../scripts/install-linux.sh", "--uninstall")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	for _, p := range []string{filepath.Join(local, "gv"), filepath.Join(home, ".cache", "govault-gv")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s is still there", p)
		}
	}
	if err := os.WriteFile(filepath.Join(local, "gv"), []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", "../../scripts/install-linux.sh", "--uninstall")
	cmd.Env = env
	_, _ = cmd.CombinedOutput()
	if _, err := os.Stat(filepath.Join(local, "gv")); err != nil {
		t.Fatal("uninstall removed another program named gv")
	}
}
