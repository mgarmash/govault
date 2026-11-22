#!/bin/sh
# Builds GoVault's release packages.
#
#   scripts/build-release.sh [nsgo build flags]
#
# NSGo builds gv, nsgo.yaml's command, into every desktop package and the
# Linux files of linux.share; this script gives gv nsgo.yaml's version
# (-X main.version, which the app does not have). Flags go to nsgo build
# unchanged, such as -target, -installers and -output. Run it from
# anywhere in the repository.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
app="${root}/cmd/govault"

version="$(sed -n 's/^version:[[:space:]]*//p' "${app}/nsgo.yaml" | head -n 1)"
[ -n "$version" ] || { echo "build-release: no version in nsgo.yaml" >&2; exit 1; }

cd "$root"
exec go tool nsgo build -ldflags "-X main.version=${version}" "$@" ./cmd/govault
