#!/bin/sh
# Builds GoVault's release packages.
#
#   scripts/build-release.sh [-target T,...] [other nsgo build flags]
#
# It runs `go tool nsgo build` once per target, so Linux targets alone get
# the AppStream metadata and a copy of the desktop entry from cmd/govault/linux
# under usr/share (usr/share/metainfo, usr/share/applications), where
# AppStream tools and the AppImage catalog look for them; NSGo writes only the
# entry at the AppDir root. NSGo copies resources beside the app, so they
# stage in cmd/govault/resources/, which exists only during the build.
# Flags other than -target go to nsgo unchanged, such as -installers, -sign,
# -notarize and -output. Run it from anywhere in the repository.
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

if [ -z "$targets" ]; then
  targets="$(sed -n 's/^[[:space:]]*targets:[[:space:]]*\[\(.*\)\]/\1/p' "${app}/nsgo.yaml" | tr -d ' ')"
fi
[ -n "$targets" ] || { echo "build-release: no targets" >&2; exit 1; }

if [ -e "$resources" ]; then
  echo "build-release: ${resources} exists; it is reserved for staging Linux metadata" >&2
  exit 1
fi
trap 'rm -rf "$resources"' EXIT
trap 'exit 1' INT TERM

for target in $(printf '%s' "$targets" | tr ',' ' '); do
  rm -rf "$resources"
  case "$target" in
    linux_*)
      mkdir -p "${resources}/usr/share/metainfo" "${resources}/usr/share/applications"
      install -m 644 "${app}/linux/dev.txchen.govault.appdata.xml" "${resources}/usr/share/metainfo/"
      install -m 644 "${app}/linux/dev.txchen.govault.desktop" "${resources}/usr/share/applications/"
      ;;
  esac
  (cd "$root" && go tool nsgo build -target "$target" "$@" ./cmd/govault)
done
