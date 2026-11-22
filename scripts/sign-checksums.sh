#!/bin/sh
# Signs a release's checksums.txt with the GoVault release key, writing
# checksums.txt.sig beside it, then verifies the signature against the
# public key in this repository. Upload both files with the release;
# install-linux.sh refuses a release without a valid signature.
#
#   scripts/sign-checksums.sh dist/releases/checksums.txt
#
# This runs:
#   ssh-keygen -Y sign -f <private key> -n govault-release checksums.txt
#
# The private key lives outside the repository; GOVAULT_RELEASE_KEY names
# it (default: the devportal project copy). Each release also updates the
# tag in the install-linux.sh URL in README.md and in the script header.
set -eu

checksums="${1:?usage: sign-checksums.sh <checksums.txt>}"
key="${GOVAULT_RELEASE_KEY:-${HOME}/code/vibe/devportal/projects/govault/release-signing-key}"
pub="$(dirname "$0")/release-signing-key.pub"

rm -f "${checksums}.sig"
ssh-keygen -Y sign -f "$key" -n govault-release "$checksums"

allowed="$(mktemp)"
trap 'rm -f "$allowed"' EXIT
printf 'govault-release namespaces="govault-release" %s\n' "$(cut -d' ' -f1,2 "$pub")" > "$allowed"
ssh-keygen -Y verify -f "$allowed" -I govault-release -n govault-release -s "${checksums}.sig" < "$checksums"
