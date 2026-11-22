// Command gv is GoVault's command-line client, compatible with
// the official Bitwarden CLI (bw).
package main

import (
	"os"
	"runtime/debug"

	"github.com/txchen/govault/internal/cli"
)

// version is GoVault's: scripts/build-release.sh passes nsgo.yaml's as
// -ldflags "-X main.version=...". Other builds report a dev version.
var version = ""

func main() {
	os.Exit(cli.Run(cli.StdEnvironment(appVersion())))
}

func appVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "0.0.0-dev"
}
