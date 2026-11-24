#!/bin/sh
# Installs GoVault on Linux from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/txchen/govault/v0.6.0/scripts/install-linux.sh | sh
#
# Arch-based systems get the pacman package, Debian-based systems the .deb,
# and everything else the AppImage with a desktop entry and icon. Every
# package carries gv, the command-line client: the packages at
# /opt/govault/gv, and the AppImage installs a gv launcher beside it that
# runs the gv inside the image, extracted again whenever the image changes,
# so it needs neither FUSE nor a display. Every
# download is checked against the release's checksums.txt, whose signature
# is first verified with ssh-keygen against the GoVault release key pinned
# below (scripts/release-signing-key.pub). Releases before v0.3.0 are not
# signed and are refused.
#
# Options (after "sh -s --" when piping):
#   --version <tag>  install a specific release, such as v0.3.0 (default: latest)
#   --appimage       install the AppImage on any distribution
#   --system         install the AppImage for all users under /usr/local
#   --uninstall      remove GoVault installed by any of the methods above
set -eu

repo="txchen/govault"
slug="govault"
app_id="dev.txchen.govault"
release_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRnNJkBBjIkZ5vb9gvNDW20LiRBLR4lLdgWAOEbbxdo"
release_namespace="govault-release"

version=""
mode=""
system=0
uninstall=0

say() { printf '%s\n' "$*"; }
fail() {
  printf 'govault-install: %s\n' "$*" >&2
  exit 1
}

usage() {
  say "Usage: install-linux.sh [--version <tag>] [--appimage] [--system] [--uninstall]"
  say ""
  say "  --version <tag>  install a specific release, such as v0.3.0 (default: latest)"
  say "  --appimage       install the AppImage on any distribution"
  say "  --system         install the AppImage for all users under /usr/local"
  say "  --uninstall      remove GoVault installed by any of these methods"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || fail "--version needs a tag, such as v0.3.0"
      version="$2"
      shift 2
      ;;
    --version=*)
      version="${1#--version=}"
      shift
      ;;
    --appimage) mode="appimage"; shift ;;
    --system) system=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    -h | --help) usage ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done

[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux; on macOS use: brew install --cask txchen/tap/govault"

as_root() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  elif command -v sudo > /dev/null 2>&1; then
    sudo "$@"
  else
    fail "this step needs root: run as root or install sudo"
  fi
}

if [ "$system" = 1 ]; then
  bin_dir="/usr/local/bin"
  share_dir="/usr/local/share"
else
  bin_dir="${HOME}/.local/bin"
  share_dir="${XDG_DATA_HOME:-${HOME}/.local/share}"
fi
desktop_file="${share_dir}/applications/${app_id}.desktop"
icon_file="${share_dir}/icons/hicolor/512x512/apps/${app_id}.png"
# The first line of the gv launcher; a gv without it is not ours.
gv_marker="# gv launcher installed by GoVault's install-linux.sh"

is_gv_launcher() { [ -f "$1" ] && [ "$(sed -n 2p "$1")" = "$gv_marker" ]; }

# write_gv_launcher IMAGE OUT writes the gv launcher for the AppImage at
# IMAGE. The launcher is a literal template; IMAGE is its only value, as a
# single-quoted shell word. Each user extracts gv into a private cache,
# again whenever the image's contents change, and never runs a gv
# extracted from other contents.
write_gv_launcher() {
  quoted="$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
  {
    printf '#!/bin/sh\n%s\n' "$gv_marker"
    printf "image='%s'\n" "$quoted"
    cat << 'LAUNCHER'
# Runs the gv inside the GoVault AppImage, extracted without FUSE into this
# user's cache, one immutable entry per image digest.
digest() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | cut -d ' ' -f 1
}
[ -f "$image" ] || { echo "gv: $image is missing; reinstall GoVault" >&2; exit 1; }
dir="${XDG_CACHE_HOME:-$HOME/.cache}/govault-gv"
# Root would run what a user's cache holds: gv runs as a normal user only.
if [ "$(id -u)" = 0 ]; then
  echo "gv: run gv as a normal user, not as root" >&2
  exit 1
fi
id="$(digest "$image")"
[ -n "$id" ] || { echo "gv: cannot read $image" >&2; exit 1; }
entry="$dir/$id"
if [ ! -x "$entry/gv" ]; then
  if (umask 077 && mkdir -p "$dir") && tmp="$(mktemp -d "$dir/.extract.XXXXXX")"; then
    if (cd "$tmp" && "$image" --appimage-extract gv > /dev/null 2>&1) && [ -x "$tmp/squashfs-root/gv" ] &&
      [ "$(digest "$image")" = "$id" ]; then
      # Publishing renames a whole directory: a concurrent refresh finds
      # either nothing or a complete entry, never a mix.
      # mv -T never moves into an existing entry; without it, publish only
      # where none exists.
      if mkdir "$tmp/entry" && mv "$tmp/squashfs-root/gv" "$tmp/entry/gv"; then
        mv -T "$tmp/entry" "$entry" 2> /dev/null || { [ -e "$entry" ] || mv "$tmp/entry" "$entry" 2> /dev/null; }
      fi
      # Entries of other images go once no launch can still be starting
      # them.
      find "$dir" -mindepth 1 -maxdepth 1 -type d ! -name "$id" ! -name '.extract.*' -mmin +60 -exec rm -rf {} + 2> /dev/null
    fi
    rm -rf "$tmp"
  fi
  [ -x "$entry/gv" ] || { echo "gv: could not extract gv from $image; it was not run" >&2; exit 1; }
fi
exec "$entry/gv" "$@"
LAUNCHER
  } > "$2"
}

run_maybe_root() {
  if [ "$system" = 1 ]; then as_root "$@"; else "$@"; fi
}

refresh_desktop() {
  if command -v update-desktop-database > /dev/null 2>&1; then
    run_maybe_root update-desktop-database "${share_dir}/applications" > /dev/null 2>&1 || true
  fi
  if command -v gtk-update-icon-cache > /dev/null 2>&1; then
    run_maybe_root gtk-update-icon-cache -q -t "${share_dir}/icons/hicolor" > /dev/null 2>&1 || true
  fi
}

do_uninstall() {
  removed=0
  if command -v pacman > /dev/null 2>&1 && pacman -Q "$slug" > /dev/null 2>&1; then
    as_root pacman -R --noconfirm "$slug"
    removed=1
  fi
  if command -v dpkg > /dev/null 2>&1 && dpkg -s "$slug" > /dev/null 2>&1; then
    if command -v apt-get > /dev/null 2>&1; then
      as_root apt-get remove -y "$slug"
    else
      as_root dpkg -r "$slug"
    fi
    removed=1
  fi
  for target in "user" "system"; do
    if [ "$target" = "system" ]; then
      b="/usr/local/bin"; s="/usr/local/share"; runner="as_root"
    else
      b="${HOME}/.local/bin"; s="${XDG_DATA_HOME:-${HOME}/.local/share}"; runner=""
    fi
    for f in "${b}/${slug}" "${s}/applications/${app_id}.desktop" "${s}/icons/hicolor/512x512/apps/${app_id}.png"; do
      if [ -e "$f" ] || [ -L "$f" ]; then
        if [ -n "$runner" ]; then as_root rm -f "$f"; else rm -f "$f"; fi
        removed=1
      fi
    done
    if is_gv_launcher "${b}/gv"; then
      if [ -n "$runner" ]; then as_root rm -rf "${b}/gv" "${s}/${slug}-gv"; else rm -rf "${b}/gv" "${s}/${slug}-gv"; fi
      removed=1
    fi
  done
  # This user's extracted gv; other users' caches are theirs.
  rm -rf "${XDG_CACHE_HOME:-${HOME}/.cache}/${slug}-gv"
  if [ "$removed" = 1 ]; then
    say "GoVault was uninstalled. Your vault cache in ~/.local/share and settings were left in place."
  else
    say "GoVault is not installed."
  fi
}

if [ "$uninstall" = 1 ]; then
  do_uninstall
  exit 0
fi

command -v curl > /dev/null 2>&1 || fail "curl is required"
command -v ssh-keygen > /dev/null 2>&1 ||
  fail "ssh-keygen (OpenSSH 8.1 or later) is required to verify the release signature; install openssh-client or openssh"

case "$(uname -m)" in
  x86_64 | amd64) arch="x64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) fail "unsupported architecture: $(uname -m) (GoVault ships x86_64 and arm64 builds)" ;;
esac

if [ -z "$version" ]; then
  latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")" ||
    fail "could not look up the latest release"
  version="${latest##*/}"
fi
case "$version" in
  v*) ;;
  *) version="v${version}" ;;
esac
number="${version#v}"
base="https://github.com/${repo}/releases/download/${version}"

# Releases before v0.3.0 have no signed checksums; refuse them by version
# too, not only by their missing signature.
min_version="0.3.0"
version_at_least() {
  printf '%s\n' "$1" | awk -v min="$2" '
    function part(v, i,   a) { split(v, a, "."); return a[i] + 0 }
    {
      v = $0
      sub(/\+.*/, "", v)
      pre = index(v, "-") > 0
      sub(/-.*/, "", v)
      if (v !~ /^[0-9]+(\.[0-9]+)*$/) exit 1
      for (i = 1; i <= 3; i++) {
        if (part(v, i) > part(min, i)) exit 0
        if (part(v, i) < part(min, i)) exit 1
      }
      # Equal to the floor: a prerelease of it comes before it (SemVer 11).
      exit pre ? 1 : 0
    }'
}
version_at_least "$number" "$min_version" ||
  fail "${version} is older than v${min_version}, the first release this installer can verify; install v${min_version} or later"

if [ -z "$mode" ]; then
  distro=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    distro="$(. /etc/os-release && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
  fi
  case " $distro " in
    *" arch "* | *" manjaro "* | *" endeavouros "*)
      command -v pacman > /dev/null 2>&1 && mode="pacman" ;;
    *" debian "* | *" ubuntu "*)
      command -v dpkg > /dev/null 2>&1 && mode="deb" ;;
  esac
  if [ -z "$mode" ]; then
    if command -v pacman > /dev/null 2>&1; then
      mode="pacman"
    elif command -v dpkg > /dev/null 2>&1 && command -v apt-get > /dev/null 2>&1; then
      mode="deb"
    else
      mode="appimage"
    fi
  fi
fi

case "$mode" in
  pacman) asset="${slug}-${number}-linux-${arch}.pkg.tar.gz" ;;
  deb) asset="${slug}-${number}-linux-${arch}.deb" ;;
  appimage) asset="${slug}-${number}-linux-${arch}.AppImage" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' INT TERM

say "Installing GoVault ${version} (${mode}, ${arch})"
curl -fL --progress-bar "${base}/${asset}" -o "${work}/${asset}" || fail "could not download ${asset} from ${version}"
curl -fsSL "${base}/checksums.txt" -o "${work}/checksums.txt" || fail "could not download checksums.txt from ${version}"
curl -fsSL "${base}/checksums.txt.sig" -o "${work}/checksums.txt.sig" ||
  fail "${version} has no signed checksums (checksums.txt.sig); nothing was installed"
printf 'govault-release namespaces="%s" %s\n' "$release_namespace" "$release_key" > "${work}/allowed_signers"
ssh-keygen -Y verify -f "${work}/allowed_signers" -I govault-release -n "$release_namespace" \
  -s "${work}/checksums.txt.sig" < "${work}/checksums.txt" > /dev/null 2>&1 ||
  fail "the signature on checksums.txt does not match the GoVault release key; nothing was installed"
say "Release signature verified."

expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "${work}/checksums.txt")"
[ -n "$expected" ] || fail "checksums.txt lists no ${asset}"
if command -v sha256sum > /dev/null 2>&1; then
  actual="$(sha256sum "${work}/${asset}" | awk '{ print $1 }')"
elif command -v shasum > /dev/null 2>&1; then
  actual="$(shasum -a 256 "${work}/${asset}" | awk '{ print $1 }')"
else
  fail "sha256sum or shasum is required to verify the download"
fi
[ "$actual" = "$expected" ] || fail "checksum mismatch for ${asset}; nothing was installed"
say "Checksum verified."

case "$mode" in
  pacman)
    as_root pacman -U --noconfirm "${work}/${asset}"
    ;;
  deb)
    if command -v apt-get > /dev/null 2>&1; then
      as_root apt-get install -y "${work}/${asset}"
    else
      as_root dpkg -i "${work}/${asset}"
    fi
    ;;
  appimage)
    run_maybe_root mkdir -p "$bin_dir" "${share_dir}/applications" "${share_dir}/icons/hicolor/512x512/apps"
    chmod 755 "${work}/${asset}"
    run_maybe_root install -m 755 "${work}/${asset}" "${bin_dir}/${slug}"

    icon_src=""
    if (cd "$work" && "./${asset}" --appimage-extract "*.png" > /dev/null 2>&1); then
      icon_src="$(find "${work}/squashfs-root" -maxdepth 3 -name "${app_id}.png" 2>/dev/null | head -n 1)"
    fi
    if [ -z "$icon_src" ]; then
      icon_src="${work}/icon.png"
      curl -fsSL "https://raw.githubusercontent.com/${repo}/${version}/cmd/govault/assets/Icon.png" -o "$icon_src" || icon_src=""
    fi
    if [ -n "$icon_src" ]; then
      run_maybe_root install -m 644 "$icon_src" "$icon_file"
    fi

    cat > "${work}/${app_id}.desktop" << EOF
[Desktop Entry]
Type=Application
Name=GoVault
Comment=Desktop client for Vaultwarden and Bitwarden servers
Exec="${bin_dir}/${slug}"
Icon=${app_id}
Terminal=false
Categories=Utility;Security;
StartupWMClass=${app_id}
EOF
    run_maybe_root install -m 644 "${work}/${app_id}.desktop" "$desktop_file"
    refresh_desktop

    if [ -e "${bin_dir}/gv" ] && ! is_gv_launcher "${bin_dir}/gv"; then
      say "Note: ${bin_dir}/gv is another program; it was left in place, so GoVault's gv was not installed."
    else
      write_gv_launcher "${bin_dir}/${slug}" "${work}/gv"
      run_maybe_root install -m 755 "${work}/gv" "${bin_dir}/gv"
      # The check runs gv as the installing user, never as root: a cache
      # the user can write must not run with root's rights.
      if [ "$(id -u)" = 0 ]; then
        say "Installed gv, the command-line client: ${bin_dir}/gv"
      elif "${bin_dir}/gv" --version > /dev/null 2>&1; then
        say "Installed gv, the command-line client: ${bin_dir}/gv"
      else
        say "Note: ${bin_dir}/gv could not extract gv from the AppImage."
      fi
    fi

    case ":${PATH}:" in
      *":${bin_dir}:"*) ;;
      *) say "Note: ${bin_dir} is not on your PATH; GoVault still appears in your app launcher." ;;
    esac
    say "AppImages need FUSE 2 (libfuse2 or fuse2) and GoVault needs GTK 4 from your distribution."
    ;;
esac

case "$mode" in
  pacman | deb) say "Its command-line client is gv (/usr/bin/gv)." ;;
esac
say "GoVault ${version} is installed. Open it from your app launcher or run: ${slug}"
