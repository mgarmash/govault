package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallerGVLauncher writes the gv launcher install-linux.sh installs
// beside the AppImage and checks it extracts gv once, then again after the
// image changes, as an update replaces it.
func TestInstallerGVLauncher(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	src, err := os.ReadFile("../../scripts/install-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, `      cat > "${work}/gv" << EOF`)
	end := strings.Index(text[start:], "\nEOF\n")
	if start < 0 || end < 0 {
		t.Fatal("the gv launcher is not in install-linux.sh")
	}
	heredoc := text[start : start+end+5]

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	shims := filepath.Join(dir, "shims")
	for _, d := range []string{bin, shims} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The image: --appimage-extract gv writes squashfs-root/gv printing
	// the image's version, and counts extractions.
	image := filepath.Join(bin, "govault")
	writeImage := func(version string) {
		script := "#!/bin/sh\n[ \"$1\" = --appimage-extract ] && [ \"$2\" = gv ] || exit 9\n" +
			"echo x >> " + filepath.Join(dir, "extractions") + "\n" +
			"mkdir -p squashfs-root && printf '#!/bin/sh\\necho " + version + " \"$@\"\\n' > squashfs-root/gv && chmod 755 squashfs-root/gv\n"
		if err := os.WriteFile(image, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		// stat as GNU stat answers -c '%s %Y': the image's identity.
		if err := os.WriteFile(filepath.Join(shims, "stat"), []byte("#!/bin/sh\necho "+version+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setup := `bin_dir='` + bin + `'; slug=govault; gv_dir='` + filepath.Join(dir, "share", "govault-gv") + `'; work='` + bin + `'
gv_marker="# gv launcher installed by GoVault's install-linux.sh"
` + heredoc + "\nchmod 755 \"$work/gv\"\n"
	if out, err := exec.Command("sh", "-c", setup).CombinedOutput(); err != nil {
		t.Fatalf("writing the launcher: %v\n%s", err, out)
	}
	run := func() string {
		t.Helper()
		cmd := exec.Command(filepath.Join(bin, "gv"), "--version")
		cmd.Env = append(os.Environ(), "PATH="+shims+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gv: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	extractions := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "extractions"))
		return strings.Count(string(b), "x")
	}

	writeImage("v1")
	if out := run(); out != "v1 --version" || extractions() != 1 {
		t.Fatalf("first run = %q after %d extractions", out, extractions())
	}
	if out := run(); out != "v1 --version" || extractions() != 1 {
		t.Fatalf("second run = %q after %d extractions, want no new one", out, extractions())
	}
	writeImage("v2")
	if out := run(); out != "v2 --version" || extractions() != 2 {
		t.Fatalf("after an update = %q after %d extractions", out, extractions())
	}
}
