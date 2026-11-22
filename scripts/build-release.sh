#!/bin/sh
# Builds GoVault's release packages with the gv command-line client inside.
#
#   scripts/build-release.sh [-target T,...] [other nsgo build flags]
#
# NSGo v0.2.0 packages only the app it compiles, so this script compiles gv
# for each target first (CGO_ENABLED=0, the app's version from nsgo.yaml),
# stages it as the app's resource for that target alone, and runs
# `go tool nsgo build` once per target. Resources are copied beside the
# app's executable, so gv lands in:
#
#   Windows  the installation directory, signed with the app and put on the
#            user's Path by the installer (nsgo.yaml windows.command_line)
#   Linux    /opt/govault/gv in the .deb and pacman packages, and the
#            AppImage's root, which scripts/install-linux.sh extracts
#
# macOS bundles get no gv yet: NSGo cannot place and sign a helper in
# GoVault.app/Contents/MacOS before it signs the app (docs/cli-design.md,
# Packaging status). Flags other than -target go to nsgo unchanged, such as
# -installers and -output. Run it from anywhere in the repository.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
app="${root}/cmd/govault"
resources="${app}/resources"

targets=""
while [ $# -gt 0 ]; do
  case "$1" in
    -target | --target)
      [ $# -ge 2 ] || { echo "build-release: -target needs a value" >&2; exit 2; }
      targets="$2"
      shift 2
      ;;
    -target=* | --target=*) targets="${1#*=}"; shift ;;
    *) break ;;
  esac
done

version="$(sed -n 's/^version:[[:space:]]*//p' "${app}/nsgo.yaml" | head -n 1)"
[ -n "$version" ] || { echo "build-release: no version in nsgo.yaml" >&2; exit 1; }
if [ -z "$targets" ]; then
  targets="$(sed -n 's/^[[:space:]]*targets:[[:space:]]*\[\(.*\)\]/\1/p' "${app}/nsgo.yaml" | tr -d ' ')"
fi
[ -n "$targets" ] || { echo "build-release: no targets" >&2; exit 1; }

# The resources directory exists only while this script stages gv in it.
if [ -e "$resources" ]; then
  echo "build-release: ${resources} exists; it is reserved for staging gv" >&2
  exit 1
fi
work="$(mktemp -d)"
cleanup() { rm -rf "$resources" "$work"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

for target in $(printf '%s' "$targets" | tr ',' ' '); do
  os="${target%%_*}"
  arch="${target#*_}"
  case "$os" in
    macos) goos="darwin" ;;
    linux | windows) goos="$os" ;;
    *) echo "build-release: unsupported target ${target}" >&2; exit 1 ;;
  esac
  case "$arch" in
    x64) goarch="amd64" ;;
    arm64) goarch="arm64" ;;
    *) echo "build-release: unsupported architecture in ${target}" >&2; exit 1 ;;
  esac
  exe="gv"
  [ "$goos" = "windows" ] && exe="gv.exe"

  echo "gv ${version} for ${target}"
  (cd "$root" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version}" -o "${work}/${target}/${exe}" ./cmd/gv)

  rm -rf "$resources"
  if [ "$goos" = "darwin" ]; then
    echo "  note: the macOS bundle does not include gv yet (see docs/cli-design.md)"
  else
    mkdir -p "$resources"
    install -m 755 "${work}/${target}/${exe}" "${resources}/${exe}"
  fi
  (cd "$root" && go tool nsgo build -target "$target" "$@" ./cmd/govault)
done
