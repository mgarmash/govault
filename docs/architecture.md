# GoVault Architecture and MVP Design

## Goal

Deliver a fast, low-memory, zero-CGO native desktop client for self-hosted Vaultwarden (Bitwarden-compatible) servers, targeting macOS (primary development host, with Touch ID unlock) and Linux desktop, built on a UI-agnostic Go core (`vaultcore`) and an NSGo (`nsgo.dev`) native-view frontend.

## Non-goals

- **Mobile apps (iOS / Android)**: Official Bitwarden mobile apps are already native Swift/Kotlin + Rust SDK with deep OS AutoFill and Passkey integration. GoVault focuses on replacing the heavy Electron desktop client.
- **Browser extension replacement**: Official browser extensions remain the recommended tool for in-browser autofill; both connect to the same Vaultwarden server.
- **OS-level FIDO2/Passkey provider & SSH Agent (in MVP)**: Deferred out of MVP; SSH Agent can be considered in a later phase.
- **Enterprise-only features**: SSO, Key Connector, billing, directory connector, and Vaultwarden admin panel.
- **Embedded SQLite database**: Explicitly excluded to keep zero-CGO cross-compilation, minimal binary size, and zero plaintext on disk.

## Scope and Constraints

- **Server compatibility**: Self-hosted Vaultwarden (Bitwarden API compatible).
- **Development host & platforms**: Developed primarily on macOS; targets macOS and Linux desktop (Windows remains feasible via the same zero-CGO build).
- **Performance & efficiency**: Fast startup/search and minimal CPU and memory footprint.
- **macOS Touch ID**: Fingerprint (Touch ID) unlock supported on macOS.
- **Storage**: No SQLite database; atomic encrypted JSON snapshots on disk and in-memory search.
- **MVP authentication**: Email + master password login in Phase 1 (2FA login flows planned for Phase 2); in-vault TOTP code generation is included in MVP.
- **MVP vault scope**: Personal vault (Login, Secure Note, Card, Identity, Folders, Trash, TOTP code generation, Password/Passphrase generator). Organizations/shared collections, Attachments, and Sends are planned for Phase 2.
- **macOS concealed clipboard**: Included in MVP (`org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`) so clipboard managers do not record copied secrets.
- **Quick Access floating panel**: Included in MVP with a **configurable** global hotkey (unset by default so it never hijacks keys unexpectedly).
- **UI framework**: NSGo (`nsgo.dev`) native-view engine, kept strictly isolated from `vaultcore` so the core remains reusable across any UI layer.

### Engineering Resource Targets

- Cold start to unlock screen: `< 300 ms` on Apple Silicon macOS.
- Idle tray-resident memory (locked / window closed): `< 30 MB` RSS.
- Active unlocked window memory (1,000–3,000 ciphers): `< 70 MB` RSS (excluding transient Argon2id spike, which is reclaimed).
- Idle CPU usage (window hidden or static): `~0.0%` (zero background UI timers).

## Design

### 1. High-Level Layered Architecture

Strict separation ensures `vaultcore` has **zero imports** of `nsgo` or any GUI package:

```text
+-------------------------------------------------------------------+
|  cmd/govault  (NSGo Desktop App Shell)                            |
|  - Tray, Global Hotkey, Main Window, Quick Access Panel           |
|  - Signals & Views (Unlock, Vault SplitView, Editor, Generator)   |
|  - Adapters: SecretsAdapter (cx.Secrets), BiometricAdapter,       |
|              ClipboardAdapter (with concealed/auto-clear),        |
|              Notification/Lifecycle hooks                         |
+-------------------------------+-----------------------------------+
                                | Go interfaces & domain structs
                                v
+-------------------------------------------------------------------+
|  internal/vaultcore  (Pure Go, Zero CGO, Zero UI Dependencies)    |
|  - crypto/     : KDF (PBKDF2, Argon2id), HKDF, AES-256-CBC-HMAC,  |
|                  RSA-OAEP, EncString parser/encoder, zeroize      |
|  - api/        : Prelogin, OAuth2 token + refresh, /api/sync,     |
|                  cipher/folder CRUD, revision-date, icons         |
|  - realtime/   : SignalR/MessagePack WebSocket (/notifications/hub)|
|  - store/      : Store interface + atomic encrypted JSON file     |
|  - state/      : Lock/Unlock state machine, in-memory decrypted   |
|                  vault, fuzzy search index, memory wipe on lock   |
|  - totp/       : RFC 6238 / otpauth:// URI parser & generator     |
|  - gen/        : CSPRNG password & EFF-style passphrase generator |
+-------------------------------------------------------------------+
```

### 2. Cryptography and Key Hierarchy (`internal/vaultcore/crypto`)

Follows the Bitwarden/Vaultwarden cryptographic specification (see [`vaultcore-spec.md`](vaultcore-spec.md) for full details and verified test vectors):

1. **Prelogin**: `POST /identity/accounts/prelogin` returns KDF type (`0` = PBKDF2-SHA256, `1` = Argon2id) and parameters.
2. **Master Key Derivation**:
   - Email is normalized (`strings.ToLower(strings.TrimSpace(email))`).
   - `PBKDF2`: `PBKDF2-HMAC-SHA256(password, email, iterations, 32)`.
   - `Argon2id`: `Argon2id(password, SHA256(email), time=iterations, memory=kdfMemory*1024 KiB, threads=kdfParallelism, keyLen=32)`.
   - **Memory reclamation**: After Argon2id completes and sensitive temporary buffers are zeroed, call `debug.FreeOSMemory()` so the working set is returned to the OS promptly.
3. **Master Password Hash (for login only)**:
   - `Base64(PBKDF2-HMAC-SHA256(masterKey, password, 1, 32))` sent to `/identity/connect/token`.
4. **Stretched Master Key**:
   - `encKey = HKDF-Expand(SHA256, masterKey, "enc", 32)` (no HKDF-Extract)
   - `macKey = HKDF-Expand(SHA256, masterKey, "mac", 32)`
5. **Protected Symmetric User Key**:
   - Server returns `Key` (EncString) in token/sync response; decrypting yields the 64-byte **User Key** (`userEncKey` 32B + `userMacKey` 32B).
   - **Invariant**: Never store the raw master password on disk or in Keychain. Only the decrypted User Key (and OAuth refresh token) is stored in Keychain when Touch ID unlock is enabled.
6. **CipherString (`EncString`) & Per-Cipher Key**:
   - Standard Type 2 (`AesCbc256_HmacSha256_B64`): verify HMAC-SHA256 (`MAC(iv || ct, macKey)`) in constant time before AES-256-CBC decryption.
   - If a cipher has a non-empty `cipher.key`, unwrap that 64-byte per-cipher symmetric key first and use it to decrypt the cipher's fields.
7. **Memory Hygiene**:
   - Overwrite sensitive `[]byte` key material on lock, logout, sleep, and session timeout.

### 3. macOS Touch ID Unlock & Lock Lifecycle

1. **Enrollment (opt-in in Settings after master-password unlock)**:
   - Check `cx.BiometricAvailability` returns `core.BiometricFingerprint` (Touch ID) or `core.BiometricFace`.
   - Prompt once with `cx.AuthenticateBiometric("Enable Touch ID for GoVault", ...)`.
   - On `core.BiometricSuccess`, store the 64-byte User Key (base64) in `cx.Secrets()` under `"userkey:" + accountID`.
2. **Unlock Flow**:
   - Run `cx.AuthenticateBiometric("Unlock GoVault", ...)` -> on success, fetch `userkey:<id>` off the UI goroutine via `cx.Secrets().Get(...)`, load encrypted snapshot from disk, decrypt into memory, and transition state to `Unlocked`.
   - If Touch ID fails, cancels, or is unavailable, seamlessly fall back to Master Password input.
3. **Keychain Enforcement Note (Verified)**:
   - Verified in `nsgo-dev/nsgo` (`internal/platform/apple/secrets.go` @ `1099393de136`): with empty `AccessGroup`, `core.Secrets` uses the macOS login Keychain (requires no entitlements and works on ad-hoc dev builds; `Accessible` only applies when `AccessGroup` is set on the Data Protection Keychain, which requires a signed app with `keychain-access-groups`). It does **not** set `SecAccessControl` (`biometryCurrentSet`), relying on app-level `LAContext` Touch ID gating (`apple/biometric.go`). Acceptable for MVP; hardware-enforced `SecAccessControl` can be added in Phase 2 for signed release builds.
4. **Lock Triggers**:
   - Manual lock (`Cmd+L` / tray menu), configurable idle timeout (default 15 minutes), and system sleep / screen lock (Phase 2).
   - On lock: zero in-memory User Key & decrypted cipher structs, stop all UI timers, and clear UI signals.

### 4. Storage, Sync, and Real-Time Updates

1. **Local Storage (Zero SQLite, Zero Plaintext on Disk)**:
   - **Encrypted Vault Snapshot**: `cx.DataDir()/vault_<accountID>.enc.json` — stores the raw encrypted `/api/sync` response payload plus local metadata (`lastSyncAt`, `revisionDate`, `serverURL`, `email`, `kdfParams`). Written atomically via temp file + `fsync` + `os.Rename` with `0600` permissions.
   - **Secrets (`cx.Secrets()`)**: OAuth `refresh_token` and (if Touch ID enabled) `user_key`.
   - **Preferences (`cx.Storage()`)**: Non-sensitive UI settings via `core.NewPersisted`.
   - **Favicon Cache (Phase 2)**: `cx.CacheDir()/icons/<domain>.png`, bounded disk cache + small in-memory LRU, optional privacy toggle.
2. **Sync Flow**:
   - On unlock: immediately decrypt local `vault_<accountID>.enc.json` so the UI is usable offline in `< 50 ms`.
   - In background: call `GET /api/accounts/revision-date`; only fetch full `GET /api/sync` if the server revision date is newer (or on manual sync `Cmd+R`).
   - Transparent access-token refresh via `POST /identity/connect/token` (`grant_type=refresh_token`).
3. **Real-Time Push (`internal/vaultcore/realtime`)**:
   - Connects to `wss://<host>/notifications/hub?access_token=<token>` using SignalR handshake + varint-framed MessagePack (matching Vaultwarden `src/api/notifications.rs`).
   - Handles cipher/folder/vault sync triggers and `LogOut` pushes with exponential backoff reconnect.

### 5. UI/UX & Resource-Efficiency Design (`cmd/govault`)

See [`ui-and-state-machine.md`](ui-and-state-machine.md) for complete wireframes, state machines, keyboard shortcuts, and NSGo signal wiring:

- **Main Window (`desktop.OpenWindow`)**: 3-pane split layout with sidebar filters/folders, virtualized `core.List` search, and detail/editor pane.
- **Quick Access Floating Panel (`desktop.OpenPanel` + `desktop.RegisterHotKey`)**: Keyboard-first Spotlight-style search overlay with user-configurable hotkey (unset by default).
- **Tray-Resident Lifecycle (`desktop.NewTray` + `desktop.SetShutdownMode`)**: Closing the main window releases window views while keeping the lightweight tray agent alive; optional macOS menu-bar-only mode via `desktop.SetDockVisible(false)`.
- **macOS Concealed Clipboard**: Dedicated zero-CGO `clipboard_darwin.go` helper via `purego/objc` setting `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` and checking `NSPasteboard.changeCount` before auto-clearing.
- **CPU & Memory Safeguards**: Visibility-gated 1s TOTP ticker (stopped when hidden/locked/non-TOTP), single `time.AfterFunc` idle lock timer, and `debug.FreeOSMemory()` post-Argon2id.

### 6. Phased Roadmap

| Phase | Scope |
| --- | --- |
| **Phase 0: Feasibility Spike** | macOS NSGo smoke test measuring cold-start time, idle/active RSS & CPU, Touch ID (`core.Biometric`), Keychain (`core.Secrets`), `desktop.OpenPanel`, and `clipboard_darwin.go`. |
| **Phase 1: MVP** | `vaultcore` (Prelogin, PBKDF2 & Argon2id, OAuth2 email+password login, AES-256-CBC-HMAC, `/api/sync`, encrypted JSON cache, personal Login/Note/Card/Identity CRUD, Folders, Trash, TOTP code generation, Password/Passphrase Generator, SignalR WS sync) + NSGo Main Window + Quick Access Panel (configurable hotkey) + macOS Touch ID + Auto-clearing concealed clipboard + macOS & Linux builds. |
| **Phase 2: Daily-Driver Polish** | 2FA login (TOTP/Email/WebAuthn), Organizations & shared collections (RSA-OAEP org key decryption), Attachments download/upload, Bitwarden Send, Multi-account switching, Favicon cache with privacy toggle, Lock on macOS sleep/screen-lock, Auto-update feed (`appcast`), Linux Secret Service + tray polish. |
| **Phase 3: Optional Power Features** | Local Vault Health / weak-password report, Optional SSH Agent (`ssh-agent` socket serving SSH Key ciphers), Windows packaging. |

### 7. Target Repository Layout

```text
govault/
├── go.mod
├── nsgo.yaml
├── docs/
│   ├── architecture.md
│   ├── vaultcore-spec.md
│   ├── ui-and-state-machine.md
│   └── research/
│       └── official-client-and-protocol.md
├── cmd/
│   └── govault/
│       ├── main.go
│       ├── app.go              # tray, hotkey, window/panel lifecycle
│       ├── adapters.go         # NSGo Secrets/Biometric/Clipboard bridges
│       ├── clipboard_darwin.go # concealed NSPasteboard helper (purego/objc)
│       └── ui/                 # Unlock, MainSplit, QuickPanel, Editor, Generator, Settings
├── internal/
│   └── vaultcore/
│       ├── crypto/             # KDF, HKDF, EncString, AES-CBC-HMAC, RSA, zeroize
│       ├── api/                # HTTP client, auth, sync, cipher/folder endpoints
│       ├── realtime/           # SignalR MessagePack WebSocket client
│       ├── store/              # Store interface + atomic encrypted JSON store
│       ├── state/              # Vault state machine, in-memory index, fuzzy search
│       ├── totp/               # RFC 6238 TOTP
│       └── gen/                # Password & passphrase generator
└── assets/
    └── Icon.png
```

## Acceptance Criteria

- [ ] `vaultcore` compiles with `CGO_ENABLED=0` and passes all 10 unit test vector suites in [`vaultcore-spec.md`](vaultcore-spec.md).
- [ ] Integration test against a local Vaultwarden instance succeeds for email+password login, `/api/sync`, cipher create/edit/soft-delete/restore, folder CRUD, and WebSocket push update.
- [ ] On macOS, Touch ID unlocks the vault without re-entering the master password, and locking clears decrypted keys/ciphers from memory.
- [ ] On macOS, copied secrets carry `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` pasteboard markers and auto-clear after the configured timeout.
- [ ] Quick Access floating panel opens via its user-configured global hotkey, filters 1,000+ ciphers with no perceptible lag, copies password with auto-clear, and dismisses cleanly.
- [ ] Resource targets verified on macOS: idle tray memory `< 30 MB` RSS, active window `< 70 MB` RSS, idle CPU `~0%`.
- [ ] `go tool nsgo build` from macOS produces runnable macOS (`.app`/`.dmg`) and Linux (`.AppImage`/`.deb`) packages with `CGO_ENABLED=0`.

## Risks

- **NSGo API churn & Linux desktop parity**: NSGo is pre-1.0; tray/hotkey behavior on Linux (especially Wayland) may have edge cases. *Mitigation*: Isolate all NSGo calls in `cmd/govault`, keep `vaultcore` 100% decoupled, and validate X11/Wayland behavior early.
- **Cryptography correctness bugs**: Subtle mistakes in MAC verification, padding, or key stretching can corrupt vault items on write. *Mitigation*: Test against official Bitwarden SDK test vectors and run write tests against a throwaway local Vaultwarden Docker instance first.
- **Keychain vs hardware-enforced Touch ID**: Without `SecAccessControl`, another process running as the same user with Keychain access could read the login Keychain item. *Mitigation*: Document this trade-off clearly for MVP and optionally add a macOS `SecAccessControl` wrapper in Phase 2 for signed release builds.
- **Argon2id memory retention**: Go's GC may retain 64 MiB after Argon2id unlock. *Mitigation*: Explicitly zero buffers and call `debug.FreeOSMemory()` post-derivation.

## Related Documents

- [`vaultcore` Interface, Protocol, and Test Vector Specification](vaultcore-spec.md)
- [UI Wireframes, State Machine, and NSGo Signal Architecture](ui-and-state-machine.md)
- [Official Bitwarden Desktop Client, Vaultwarden Protocol, and NSGo Research](research/official-client-and-protocol.md)
