# Building release packages

Release packages carry the app and `gv`, its command-line client. Build them with the repository's script, not `go tool nsgo build` directly, so every package includes `gv`:

```sh
scripts/build-release.sh -installers            # every target in cmd/govault/nsgo.yaml
scripts/build-release.sh -target linux_x64 -installers -output /tmp/out
```

The script takes `-target` and passes every other flag to `nsgo build`. For each target it compiles `gv` with `CGO_ENABLED=0` and the version in `nsgo.yaml`, stages it in `cmd/govault/resources/` for that target alone, runs `nsgo build`, and removes the staging directory again. The signing, notarization and update-feed settings work as they do for `nsgo build`. Sign `checksums.txt` afterwards with `scripts/sign-checksums.sh` as before.

Linux targets also get `cmd/govault/linux/dev.txchen.govault.appdata.xml` (AppStream metadata) in `usr/share/metainfo/` and a copy of the desktop entry in `usr/share/applications/`, which AppStream tools and the AppImage catalog read; keep the copy in step with `linux.categories` in `nsgo.yaml` (a test checks it), and add each release to the metadata's `<releases>` when its version is bumped.

Check a build:

```sh
bsdtar -tvf dist/releases/govault-<version>-linux-x64.pkg.tar.gz | grep gv      # opt/govault/gv
grep -n 'gv.exe\|UserPath' dist/GoVault-<version>-windows_x64/GoVault.nsi
```

See the packaging status in [cli-design.md](cli-design.md#packaging-status) for what each package does with `gv` and what NSGo does not support yet.

## Homebrew cask

The tap's `govault` cask links `gv` with the cask `binary` stanza, so Homebrew creates and removes `$(brew --prefix)/bin/gv` and every cask upgrade updates it with the app:

```ruby
cask "govault" do
  # version, sha256, url, name, desc, homepage as today
  app "GoVault.app"
  binary "#{appdir}/GoVault.app/Contents/MacOS/gv"
end
```

Add the stanza in the first release whose DMG carries `GoVault.app/Contents/MacOS/gv`; `brew install` fails on a `binary` whose source is missing.
