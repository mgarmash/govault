package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestReleaseBuildInjectsTheVersion runs scripts/build-release.sh with a go
// command that records its arguments, then builds gv with the linker flags
// the script gave nsgo: gv reports nsgo.yaml's version.
func TestReleaseBuildInjectsTheVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script needs sh")
	}
	cfg, err := os.ReadFile("../govault/nsgo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^version:\s*(\S+)`).FindSubmatch(cfg)
	if m == nil {
		t.Fatal("nsgo.yaml has no version")
	}
	want := string(m[1])

	shims := t.TempDir()
	record := filepath.Join(shims, "args")
	shim := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + record + "\n"
	if err := os.WriteFile(filepath.Join(shims, "go"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	script := exec.Command("sh", "../../scripts/build-release.sh", "-target", "macos_arm64", "-output", t.TempDir())
	script.Env = append(os.Environ(), "PATH="+shims+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := script.CombinedOutput(); err != nil {
		t.Fatalf("build-release.sh: %v\n%s", err, out)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	var ldflags []string
	for i, a := range args {
		if a == "-ldflags" && i+1 < len(args) {
			ldflags = append(ldflags, args[i+1])
		}
	}
	if len(ldflags) != 1 || ldflags[0] != "-X main.version="+want {
		t.Fatalf("nsgo got %q", args)
	}

	bin := filepath.Join(t.TempDir(), "gv")
	if out, err := exec.Command("go", "build", "-ldflags", ldflags[0], "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("gv --version = %q, want %q", got, want)
	}
}

func TestUnreleasedBuildsSayDev(t *testing.T) {
	if version == "" && appVersion() != "0.0.0-dev" {
		t.Fatalf("appVersion() = %q", appVersion())
	}
}
