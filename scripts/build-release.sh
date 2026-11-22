#!/bin/sh
# Builds GoVault's release packages.
#
#   scripts/build-release.sh [-target T,...] [other nsgo build flags]
#
# NSGo builds gv, nsgo.yaml's command, into every desktop package itself;
# this script gives it nsgo.yaml's version (-X main.version, which the app
# does not have). It also adds what NSGo has no per-target option for: Linux packages
# get the AppStream metadata and a copy of the desktop entry under
# usr/share, from cmd/govault/linux, where AppStream tools and the
# AppImage catalog look for them; NSGo writes only the entry at the AppDir
# root. It stages them as the app's resources for Linux targets alone and
# runs `go tool nsgo build` once per target. Flags other than -target go
# to nsgo unchanged, such as -installers and -output. Run it from anywhere
# in the repository.
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

# The resources directory exists only while this script stages in it.
if [ -e "$resources" ]; then
  echo "build-release: ${resources} exists; it is reserved for staging" >&2
  exit 1
fi
cleanup() { rm -rf "$resources"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

for target in $(printf '%s' "$targets" | tr ',' ' '); do
  case "$target" in
    macos_* | linux_* | windows_*) ;;
    *) echo "build-release: unsupported target ${target}" >&2; exit 1 ;;
  esac
  rm -rf "$resources"
  case "$target" in
    linux_*)
      mkdir -p "${resources}/usr/share/metainfo" "${resources}/usr/share/applications"
      install -m 644 "${app}/linux/dev.txchen.govault.appdata.xml" "${resources}/usr/share/metainfo/"
      install -m 644 "${app}/linux/dev.txchen.govault.desktop" "${resources}/usr/share/applications/"
      ;;
  esac
  (cd "$root" && go tool nsgo build -target "$target" -ldflags "-X main.version=${version}" "$@" ./cmd/govault)
done
