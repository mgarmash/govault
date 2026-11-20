# Official Bitwarden Desktop Client, Vaultwarden Protocol, and NSGo Capabilities

## Scope

Source-level analysis of the official Bitwarden desktop client (`bitwarden/clients`), Bitwarden's Rust crypto SDK (`bitwarden/sdk-internal`), the Vaultwarden server (`dani-garcia/vaultwarden`), and the NSGo desktop UI engine (`nsgo-dev/nsgo`) to ground GoVault's design.

Inspected repository commits (accessed 2026-11-20):

- `bitwarden/clients` @ `684522331102` (2026-11-20)
- `bitwarden/sdk-internal` @ `c5c08aebe883` (2026-11-20)
- `dani-garcia/vaultwarden` @ `baff1cabae39` (2026-11-19)
- `nsgo-dev/nsgo` @ `1099393de136` (2026-11-20)

## Findings

### 1. Official Bitwarden Desktop Client (`bitwarden/clients`)

- **Runtime and storage**: The official desktop client (`apps/desktop`) is an Electron + Angular + TypeScript application. Root `package.json` uses `electron-store` (`12.0.0`) and `lowdb` (`1.0.0`) rather than SQLite for desktop local persistence (storing encrypted vault data and client state in JSON files alongside browser storage).
- **Mobile contrast**: The retired Xamarin/MAUI repository (`bitwarden/mobile`) is archived; current official mobile apps are native Swift (`bitwarden/ios`) and native Kotlin (`bitwarden/android`), sharing a Rust core SDK (`bitwarden/sdk-internal`).
- **Desktop main-process subsystems** (`apps/desktop/src/main/`):
  - Window lifecycle (`window.main.ts`), system tray (`tray.main.ts`), application menus (`menu/`), power/sleep monitor (`power-monitor.main.ts`), auto-updater (`updater.main.ts`), custom URL protocol handler (`protocol.ts`), SSO cookie handling (`sso-cookie.main.ts`), and browser native messaging bridge (`native-messaging.main.ts`).
- **Desktop feature modules** (`apps/desktop/src/` and `app-routing.module.ts`):
  - **Authentication & multi-account**: Email/master password login, environment/self-hosted URL selector, 2FA, login with device / auth request, SSO, new device verification, multi-account switcher (`AccountSwitcherV2Component`), lock screen, session timeout (`key-management/session-timeout`), and biometric unlock (`key-management/biometrics`).
  - **Vault management**: Vault views (`vault`, `vault-v3`), personal items (`my-items`), folders (`my-folders`), organization/shared collections (`shared-folders`), trash/soft-delete, and cipher CRUD.
  - **Tools & auxiliary features**: Password/username generator, Bitwarden Send (`send`), importer (`import`), desktop autofill/FIDO2 assertion & creation flows (`autofill/`, `fido2-*` routes), and billing views.

### 2. Vaultwarden Server API & Crypto Protocol (`dani-garcia/vaultwarden` & `bitwarden/sdk-internal`)

- **Core API modules** (`src/api/`):
  - `identity.rs`: OAuth2 token endpoint (`/identity/connect/token`) and prelogin (`/identity/accounts/prelogin`, also exposed under `/api/accounts/prelogin`) returning KDF parameters (PBKDF2-SHA256 or Argon2id).
  - `core/accounts.rs`: Profile, revision date (`/api/accounts/revision-date`), keys, and device auth requests.
  - `core/ciphers.rs`: Full vault sync (`/api/sync`), cipher CRUD (`/api/ciphers`, `/api/ciphers/{id}`), soft-delete/restore/purge, attachments, and bulk operations.
  - `core/folders.rs`: Folder CRUD (`/api/folders`).
  - `core/organizations.rs`, `core/sends.rs`, `core/two_factor/`, `core/events.rs`, `icons.rs` (website favicon proxy `/icons/{domain}/icon.png`).
- **Cipher schema & crypto details** (`src/api/core/ciphers.rs`, `bitwarden/sdk-internal` `crates/bitwarden-crypto/src/`):
  - `CipherData` includes optional per-cipher `key` (encrypted symmetric key), `lastKnownRevisionDate` (optimistic concurrency), `archivedDate`, and cipher types 1–8 (`Login`, `SecureNote`, `Card`, `Identity`, `SshKey`, `BankAccount`, `DriversLicense`, `Passport`), plus an optional sealed `data` blob for future v2 accounts.
  - Key stretching uses RFC 5869 `HKDF-Expand(SHA-256, PRK=masterKey, info="enc"|"mac", 32)` directly without `HKDF-Extract` (`libs/legacy-crypto/src/services/default-key-generation.service.ts`).
  - Argon2id hashes the normalized email with SHA-256 to form the 32-byte salt; PBKDF2 minimum is 5,000 iterations and Argon2id minimums are 2 iterations / 16 MiB memory (`bitwarden/sdk-internal` `keys/kdf.rs`).
  - Bitwarden disables Type 0 (`AesCbc256_B64`) decryption for cipher fields (`encrypt.service.implementation.ts`), while still allowing Type 0 unwrap for legacy master-key-protected User Keys (`keys/master_key.rs`).
- **Real-time notifications** (`src/api/notifications.rs`):
  - Uses WebSockets with SignalR handshake (`{"protocol":"messagepack","version":1}\x1e`) and varint-length-prefixed MessagePack (`rmpv::Value`) binary frames.
  - Sends periodic pings every 15 seconds (`WS_PING_INTERVAL`) and enforces client timeout to clean up half-open connections.
  - Pushes `ReceiveMessage` invocations with `ContextId`, `Type` (`0`=SyncCipherUpdate, `1`=SyncCipherCreate, `2`=SyncLoginDelete, `3`=SyncFolderDelete, `4`=SyncCiphers, `5`=SyncVault, `6`=SyncOrgKeys, `7`=SyncFolderCreate, `8`=SyncFolderUpdate, `10`=SyncSettings, `11`=LogOut, `12..14`=Send), and `Payload`.

### 3. NSGo Desktop Capabilities (`nsgo-dev/nsgo`)

- **Rendering and styling**: Native platform views (macOS AppKit + Core Text, Linux GTK 4 + Pango + Cairo, Windows Direct2D + DirectWrite) driven by a Go reactive signal graph (`core.NewSignal`, `core.NewCollection`, `core.NewSelector`, `core.NewPersisted`), unified Flexbox/Grid layout (`core.Style`), and Tailwind CSS 4 class support.
- **Desktop integration** (`desktop/app.go`):
  - Multi-window (`desktop.OpenWindow`) and floating panel (`desktop.OpenPanel`).
  - System tray (`desktop.NewTray`), global hotkeys (`desktop.RegisterHotKey`), Dock visibility toggle (`desktop.SetDockVisible`), shutdown mode (`desktop.SetShutdownMode`), launch at login (`desktop.SetLaunchAtLogin`), and frontmost app info (`desktop.FrontmostAppInfo`).
- **Security & platform services — source-verified internals** (`internal/platform/apple/secrets.go`, `apple/biometric.go`, `macos/services.go`, `linux/tray.go`, `linux/hotkey.go`):
  - **macOS Keychain (`apple/secrets.go`)**: Uses `Security.framework` via `purego` (`kSecClassGenericPassword`). When `AccessGroup == ""`, uses the macOS login keychain (requires no entitlements and works on ad-hoc/unsigned dev builds, and `Accessible` is skipped). When `AccessGroup != ""`, switches to `kSecUseDataProtectionKeychain = true`, which requires a signed app with `keychain-access-groups` entitlement. Does **not** set `SecAccessControl` (`biometryCurrentSet`); biometric gating is performed at the app layer via `apple/biometric.go`.
  - **macOS Touch ID (`apple/biometric.go`)**: Uses `LocalAuthentication.framework` `LAContext` with policy `1` (`LAPolicyDeviceOwnerAuthenticationWithBiometrics` — strictly Touch ID/Face ID, no automatic passcode fallback) via `purego` + `objcblock`.
  - **macOS Clipboard (`macos/services.go`)**: `SetClipboard` writes standard `public.utf8-plain-text` without `org.nspasteboard.ConcealedType` / `TransientType`. Concealed clipboard therefore requires a small macOS-only `purego/objc` helper (`clipboard_darwin.go`).
  - **Linux Tray & Global Hotkeys (`linux/tray.go`, `linux/hotkey.go`)**: Tray implements `org.kde.StatusNotifierItem` + `com.canonical.dbusmenu` over GDBus (works on KDE Plasma and GNOME AppIndicator on both X11 and Wayland). Global hotkeys use X11 `XGrabKey` on X11 and XDG Desktop Portal GlobalShortcuts (`portalTokenID`) on Wayland.
- **Build & cross-compilation** (`cmd/nsgo/build.go`, `docs/public/en/building.md`):
  - `buildMacApp` compiles with `GOOS=darwin GOARCH=<arch> CGO_ENABLED=0`, then bundles `.app`, signs via macOS `codesign`, and builds `.dmg` via `hdiutil`.
  - From a single macOS host, `go tool nsgo build` can cross-compile and package macOS (`.dmg`), Linux (`.deb`, Arch `.pkg.tar.gz`, `.AppImage`), and Windows (`-setup.exe` with `makensis`).

## Sources

- `bitwarden/clients` (`684522331102`), `package.json`, `apps/desktop/src/`, `apps/desktop/src/app/app-routing.module.ts`, `libs/legacy-crypto/src/services/default-key-generation.service.ts`, `encrypt.service.implementation.ts`, `web-crypto-function.service.ts` — https://github.com/bitwarden/clients/tree/684522331102
- `bitwarden/sdk-internal` (`c5c08aebe883`), `crates/bitwarden-crypto/src/keys/kdf.rs`, `keys/master_key.rs`, `hazmat/symmetric_encryption/aes256_cbc_hmac_sha256_ae.rs` — https://github.com/bitwarden/sdk-internal/tree/c5c08aebe883
- `bitwarden/ios`, `bitwarden/android`, `bitwarden/mobile` — https://github.com/bitwarden/ios, https://github.com/bitwarden/android, https://github.com/bitwarden/mobile
- `dani-garcia/vaultwarden` (`baff1cabae39`), `src/api/core/mod.rs`, `src/api/core/ciphers.rs`, `src/api/core/folders.rs`, `src/api/identity.rs`, `src/api/notifications.rs` — https://github.com/dani-garcia/vaultwarden/tree/baff1cabae39
- `nsgo-dev/nsgo` (`1099393de136`), `desktop/app.go`, `core/biometric.go`, `cmd/nsgo/build.go`, `internal/platform/apple/secrets.go`, `internal/platform/apple/biometric.go`, `internal/platform/macos/services.go`, `internal/platform/linux/tray.go`, `internal/platform/linux/hotkey.go`, `docs/public/en/services.md`, `docs/public/en/building.md`, `docs/public/en/styles.md`, `docs/public/en/components.md` — https://github.com/nsgo-dev/nsgo/tree/1099393de136

## Related Documents

- [Architecture & MVP Design](../architecture.md)
- [`vaultcore` Interface, Protocol, and Test Vector Specification](../vaultcore-spec.md)
- [UI Wireframes, State Machine, and NSGo Signal Architecture](../ui-and-state-machine.md)
