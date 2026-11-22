package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// gv must build without cgo and stay free of the desktop app's UI stack,
// so it runs on hosts with no display or GUI libraries.
var forbidden = []string{
	"github.com/nsgo-dev/",
	"github.com/txchen/govault/cmd/govault",
	"golang.org/x/image",
	"runtime/cgo",
}

func TestDependenciesExcludeGUIAndCgo(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list for every release target")
	}
	for _, target := range []string{"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64"} {
		goos, goarch, _ := strings.Cut(target, "/")
		cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{len .CgoFiles}} {{if .Error}}{{.Error}}{{end}}", ".")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: go list: %v\n%s", target, err, out)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			pkg := fields[0]
			for _, f := range forbidden {
				if strings.HasPrefix(pkg, f) {
					t.Errorf("%s: gv imports %s", target, pkg)
				}
			}
			if len(fields) > 1 && fields[1] != "0" {
				t.Errorf("%s: %s needs cgo", target, pkg)
			}
			if len(fields) > 2 {
				t.Errorf("%s: %s: %s", target, pkg, strings.Join(fields[2:], " "))
			}
		}
	}
}
