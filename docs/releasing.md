# Building release packages

Release packages carry the app and `gv`, its command-line client. Build them with the repository's script, which runs `nsgo build` with every flag it is given and gives `gv` the app's version:

```sh
scripts/build-release.sh -installers            # every target in cmd/govault/nsgo.yaml
scripts/build-release.sh -target linux_x64 -installers -output /tmp/out
```

`nsgo.yaml` declares `gv` under `commands`, so `nsgo build` compiles it for each desktop target (`CGO_ENABLED=0`, the app's build tags, stripped and `-trimpath` for a release) and packages it with the app. The script passes `-ldflags "-X main.version=<nsgo.yaml's version>"`, which NSGo links into its commands (the app has no `main.version`); a plain `go tool nsgo build` or `go build ./cmd/gv` makes a `gv` that reports `0.0.0-dev`.

| Package | `gv` |
| --- | --- |
| macOS app and DMG | `GoVault.app/Contents/MacOS/gv`, signed with the app's identity and the identifier `dev.txchen.govault.gv` before the app (with the hardened runtime and a timestamp when notarizing), so the app's signature seals it |
| `.deb`, pacman | `/opt/govault/gv` and a package-owned `/usr/bin/gv` link |
| AppImage | `gv` at the image root, which `scripts/install-linux.sh` extracts |
| Windows installer | `gv.exe` in the installation folder, signed with the app; `windows.path` puts the folder on the user's Path when it is not there yet and records that it did (`NsgoPathAdded` in the uninstall key), and the uninstaller removes the entry only when the installer added it |

Store builds leave `gv` out. Sign `checksums.txt` afterwards with `scripts/sign-checksums.sh` as before.

`linux.share` in `nsgo.yaml` is `cmd/govault/linux/share`, which the `.deb` and pacman packages install at `/usr/share` and the AppImage at its `usr/share`. It holds the AppStream metadata, `metainfo/dev.txchen.govault.metainfo.xml`, which replaces the one NSGo would generate; add each release to its `<releases>` when the version is bumped. NSGo writes the desktop entry itself (`/usr/share/applications` in the packages, the AppDir root in the AppImage), so `linux/share` must not hold one: a file NSGo writes too fails the build.

Check a build:

```sh
codesign --verify --deep --strict dist/GoVault-<version>-macos_arm64/GoVault.app
codesign -dv dist/GoVault-<version>-macos_arm64/GoVault.app/Contents/MacOS/gv      # Identifier=dev.txchen.govault.gv
dist/GoVault-<version>-macos_arm64/GoVault.app/Contents/MacOS/gv --version          # nsgo.yaml's version
bsdtar -tvf dist/releases/govault-<version>-linux-x64.pkg.tar.gz | grep -E 'gv|metainfo'   # opt/govault/gv, usr/bin/gv, usr/share/metainfo/dev.txchen.govault.metainfo.xml
appstreamcli validate --no-net cmd/govault/linux/share/metainfo/dev.txchen.govault.metainfo.xml
grep -n 'gv.exe\|UserPath\|NsgoPathAdded' dist/GoVault-<version>-windows_x64/GoVault.nsi
```

## NSGo fork

Upstream NSGo v0.2.0 cannot package a command beside the app. Until a release of it can, `go.mod` replaces it with the fork that adds `commands` and `windows.path`:

```
replace github.com/nsgo-dev/nsgo => github.com/txchen/nsgo v0.2.1-0.20261122235715-cae54e688488
```

That is branch `govault/v0.2.0-companions` of [txchen/nsgo](https://github.com/txchen/nsgo), v0.2.0 plus commands, their linker flags and signing identifiers, `linux.share`, and Windows Path entries removed only by the installer that added them; the app and `go tool nsgo` both build with it. When upstream ships `commands`, require that release and remove the `replace` line.

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
