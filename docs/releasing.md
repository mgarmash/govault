# Building release packages

Release packages carry the app and `gv`, its command-line client. Build them with the repository's script, which runs `nsgo build` per target and adds the Linux metadata below:

```sh
scripts/build-release.sh -installers            # every target in cmd/govault/nsgo.yaml
scripts/build-release.sh -target linux_x64 -installers -output /tmp/out
```

`nsgo.yaml` declares `gv` under `commands`, so `nsgo build` compiles it for each desktop target (`CGO_ENABLED=0`, the app's build tags, stripped and `-trimpath` for a release) and packages it with the app; a plain `go tool nsgo build` includes `gv` too.

| Package | `gv` |
| --- | --- |
| macOS app and DMG | `GoVault.app/Contents/MacOS/gv`, signed with the app's identity before the app (with the hardened runtime and a timestamp when notarizing), so the app's signature seals it |
| `.deb`, pacman | `/opt/govault/gv` and a package-owned `/usr/bin/gv` link |
| AppImage | `gv` at the image root, which `scripts/install-linux.sh` extracts |
| Windows installer | `gv.exe` in the installation folder, signed with the app; `windows.path` puts the folder on the user's Path and the uninstaller removes only that entry |

Store builds leave `gv` out. NSGo passes `gv` no version: a release changes `version` in `cmd/govault/nsgo.yaml` and `appRelease` in `cmd/gv/version.go` together, which `TestVersionMatchesTheApp` checks. Sign `checksums.txt` afterwards with `scripts/sign-checksums.sh` as before.

For Linux targets the script also stages `cmd/govault/linux/dev.txchen.govault.appdata.xml` (AppStream metadata) in `usr/share/metainfo/` and a copy of the desktop entry in `usr/share/applications/` as the app's resources in `cmd/govault/resources/`, which exists only during the build; AppStream tools and the AppImage catalog read them. Keep the copy in step with `linux.categories` in `nsgo.yaml` (a test checks it), and add each release to the metadata's `<releases>` when its version is bumped.

Check a build:

```sh
codesign --verify --deep --strict dist/GoVault-<version>-macos_arm64/GoVault.app
dist/GoVault-<version>-macos_arm64/GoVault.app/Contents/MacOS/gv --version
bsdtar -tvf dist/releases/govault-<version>-linux-x64.pkg.tar.gz | grep gv      # opt/govault/gv, usr/bin/gv
grep -n 'gv.exe\|UserPath' dist/GoVault-<version>-windows_x64/GoVault.nsi
```

## NSGo fork

Upstream NSGo v0.2.0 cannot package a command beside the app. Until a release of it can, `go.mod` replaces it with the fork that adds `commands` and `windows.path`:

```
replace github.com/nsgo-dev/nsgo => github.com/txchen/nsgo v0.2.1-0.20261122222217-8328a2f9a7c0
```

That is branch `govault/v0.2.0-companions` of [txchen/nsgo](https://github.com/txchen/nsgo), v0.2.0 plus the feature; the app and `go tool nsgo` both build with it. When upstream ships `commands`, require that release and remove the `replace` line.

## Homebrew cask

The tap's `govault` cask links `gv` with the cask `binary` stanza, so Homebrew creates and removes `$(brew --prefix)/bin/gv` and every cask upgrade updates it with the app:

```ruby
cask "govault" do
  # version, sha256, url, name, desc, homepage as today
  app "GoVault.app"
  binary "#{appdir}/GoVault.app/Contents/MacOS/gv"
end
```

Add the stanza with the first release built this way, whose DMG carries `GoVault.app/Contents/MacOS/gv`; `brew install` fails on a `binary` whose source is missing, so the casks of earlier releases must not have it.
