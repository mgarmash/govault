package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestInstallerVersionFloor runs version_at_least from install-linux.sh.
func TestInstallerVersionFloor(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	src, err := os.ReadFile("../../scripts/install-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "version_at_least() {")
	end := strings.Index(text[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("version_at_least not found")
	}
	fn := text[start : start+end+3]
	for v, want := range map[string]bool{
		"0.3.0": true, "0.3.1": true, "0.10.0": true, "1.0.0": true, "0.3.0+build.5": true, "0.3.1-rc.1": true,
		"0.3.0-rc.1": false, "0.3.0-beta": false, "0.2.8": false, "0.2.99": false, "0.2": false, "abc": false, "": false,
	} {
		err := exec.Command("sh", "-c", fn+"\nversion_at_least \"$1\" 0.3.0", "sh", v).Run()
		if got := err == nil; got != want {
			t.Errorf("version_at_least(%q) = %v, want %v", v, got, want)
		}
	}
}
