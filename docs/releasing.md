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
| Windows installer | `gv.exe` in the installation folder, signed with the app; `windows.path` puts the folder on the user's Path when it is not there yet and records the folder it added (`NsgoPathAddedDir` in the uninstall key); an upgrade into another folder removes the recorded one first, and the uninstaller removes only the recorded folder, never an entry that was on Path before |

Store builds leave `gv` out. Sign `checksums.txt` afterwards with `scripts/sign-checksums.sh` as before.

`linux.share` in `nsgo.yaml` is `cmd/govault/linux/share`, which the `.deb` and pacman packages install at `/usr/share` and the AppImage at its `usr/share`. It holds the AppStream metadata, `metainfo/dev.txchen.govault.metainfo.xml`, which replaces the one NSGo would generate; add each release to its `<releases>` when the version is bumped. NSGo writes the desktop entry itself (`/usr/share/applications` in the packages, the AppDir root in the AppImage), so `linux/share` must not hold one: a file NSGo writes too fails the build.

macOS has two targets, `macos_arm64` (Apple silicon) and `macos_x64` (Intel), each with its own DMG (`govault-<version>-macos-arm64.dmg`, `govault-<version>-macos-x64.dmg`) and its own update feed (`appcast-macos_arm64.xml`, `appcast-macos_x64.xml`); upload both DMGs and both feeds. The app is not universal.

Check a build, for each macOS target (`<arch>` is `macos_arm64` or `macos_x64`):

```sh
codesign --verify --deep --strict dist/GoVault-<version>-<arch>/GoVault.app
codesign -dv dist/GoVault-<version>-<arch>/GoVault.app/Contents/MacOS/gv      # Identifier=dev.txchen.govault.gv
lipo -archs dist/GoVault-<version>-<arch>/GoVault.app/Contents/MacOS/GoVault dist/GoVault-<version>-<arch>/GoVault.app/Contents/MacOS/gv   # arm64, or x86_64
arch -x86_64 dist/GoVault-<version>-macos_x64/GoVault.app/Contents/MacOS/gv --version   # nsgo.yaml's version; Rosetta 2 runs the Intel build on Apple silicon
dist/GoVault-<version>-macos_arm64/GoVault.app/Contents/MacOS/gv --version     # nsgo.yaml's version
bsdtar -tvf dist/releases/govault-<version>-linux-x64.pkg.tar.gz | grep -E 'gv|metainfo'   # opt/govault/gv, usr/bin/gv, usr/share/metainfo/dev.txchen.govault.metainfo.xml
appstreamcli validate --no-net cmd/govault/linux/share/metainfo/dev.txchen.govault.metainfo.xml
grep -n 'gv.exe\|UserPath\|NsgoPathAddedDir' dist/GoVault-<version>-windows_x64/GoVault.nsi
```

## Homebrew cask

The tap's `govault` cask links `gv` with the cask `binary` stanza, so Homebrew creates and removes `$(brew --prefix)/bin/gv` and every cask upgrade updates it with the app. It installs the DMG of the Mac's architecture:

```ruby
cask "govault" do
  arch arm: "arm64", intel: "x64"

  version "<version>"
  sha256 arm:   "<sha256 of govault-<version>-macos-arm64.dmg>",
         intel: "<sha256 of govault-<version>-macos-x64.dmg>"

  url "https://github.com/txchen/govault/releases/download/v#{version}/govault-#{version}-macos-#{arch}.dmg"
  # name, desc, homepage, auto_updates and zap as today
  depends_on macos: :ventura

  app "GoVault.app"
  binary "#{appdir}/GoVault.app/Contents/MacOS/gv"
end
```

A build of both macOS targets together writes this form to `dist/releases/homebrew/govault.rb`, with both checksums, but with `depends_on :macos` and NSGo's description; keep the tap's `depends_on macos: :ventura`, `desc` and `zap`. A build of one target writes a single-architecture cask (`depends_on arch:`), which must not replace the tap's.

Add the stanza with the first release built this way, whose DMG carries `GoVault.app/Contents/MacOS/gv`; `brew install` fails on a `binary` whose source is missing, so the casks of earlier releases must not have it.
