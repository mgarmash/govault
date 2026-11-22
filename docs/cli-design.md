# gv CLI design

## Goals and non-goals

Install GoVault once and run `gv` from a terminal, including on a Linux host without a display, desktop session or keyring. A script using the supported subset of `bw` should need only a binary-name change and a fresh login. V1 reads vault data. It may authenticate, request an email code, update its own cache, generate a password, and save a requested attachment. It has no vault mutation commands.

**Decision:** The CLI has its own sign-in, session keys, device ID, credentials and cache. Logging out of either GoVault client leaves the other signed in. The user can revisit this decision. The on-disk format and session keys are private to each client, including official `bw`.

## Command reference

The reference is Bitwarden clients revision `ad5a8f316667`, using its collection terminology. Support the following spellings, including global options before or after a subcommand. Other commands and options fail explicitly. [Bitwarden user guide](https://bitwarden.com/help/cli/) · [Command registration][program] · [Vault command registration][vault]

| Command | V1 behavior and limits |
| --- | --- |
| `login [email] [password]` | Password login returns an unlocked session. Support `--check`, `--passwordenv NAME`, `--passwordfile PATH`, `--method N` and `--code CODE`. Offer only server-advertised, supported methods: 0 authenticator, 1 email, 3 YubiKey OTP. Preserve leading zeros and submit the YubiKey's complete OTP. Use the core email challenge flow. In noninteractive mode report required inputs and exit. |
| `login --apikey` | Personal API credentials from the environment or a hidden secret prompt. Separate authentication from vault unlock. SSO, device login, organization API keys, Duo, FIDO and recovery flows are outside v1. |
| `unlock [password]` | Positional password, else first line of `--passwordfile PATH`, else variable named by `--passwordenv NAME`, else masked prompt. `--raw` emits only the new key. `--check` tests the supplied session without rotating it or prompting. |
| `lock`, `logout`, `status` | Invalidate all CLI sessions for this profile, remove local sign-in, or report local state, respectively. No network required. |
| `sync [-f\|--force]`, `sync --last` | Pull encrypted changes, optionally force a full pull. Advance the timestamp only on successful commit. Return last successful sync time in ISO UTC format, or empty output before first sync. Locked sync can run with an available authentication credential. |
| `config server [value]` | Show or set the base URL while logged out. Support Bitwarden US/EU service origins and a self-hosted base including its path prefix. Resolve the cloud API and identity hosts explicitly. Defer independent endpoint overrides and Key Connector. |
| `list items` | `--search`, `--url`, `--folderid`, `--collectionid`, `--organizationid`, `--trash`, `--archived`. Apply URI match rules and equivalent domains, then state and search filters. Multiple ID filters match **any** supplied ID condition. Honor literal `null` and `notnull`. Default to active items. |
| `list folders\|collections\|organizations` | Search names with `--search`. Collections also take `--organizationid`. Use cached, accessible objects. |
| `list org-collections` | Require `--organizationid GUID`. Use the authorized server collection endpoint for that membership and apply optional `--search` after decrypting. The upstream list returns ordinary collection objects. [List implementation][list] |
| `get item\|username\|password\|uri\|totp\|notes ID-OR-QUERY` | Match upstream ID lookup, text lookup, ambiguity, missing fields and permission checks. Generate TOTP locally at request time. |
| `get folder\|collection\|organization ID-OR-QUERY` | Return the corresponding local object. |
| `get attachment ID-OR-NAME --itemid ID [--output PATH]` | Fetch and authenticate the attachment, then save it. With `--raw` and no output path, write exact bytes to stdout. A trailing directory separator selects the suggested filename inside that directory. [File output][files] |
| `get fingerprint me\|USER-GUID` | Derive the Bitwarden fingerprint phrase from the account ID and public key. A peer lookup requires the server. Verify against upstream vectors. [Fingerprint lookup][fingerprint] |
| `generate` | Local password or passphrase. Support `-u/--uppercase`, `-l/--lowercase`, `-n/--number`, `-s/--special`, `--length`, `--minNumber`, `--minSpecial`, `--ambiguous`, `-p/--passphrase`, `--words`, `--separator`, `-c/--capitalize`, `--includeNumber`. Match defaults, count limits and ambiguous-character semantics. |
| `encode` | Base64 of piped UTF-8 text including its final newline, if present. No sign-in. |
| Global | `--session KEY`, `--raw`, `--response`, `--pretty`, `--quiet`, `--nointeraction`, `--cleanexit`, help and version. Report the GoVault version. |
| Deferred reads | `get exposed` involves an external breach service. `get template` primarily supports writes. Defer `get org-collection`, member administration, shared-folder aliases, reports, completion and update commands. |
| Excluded | Create, edit, delete, restore, archive, move, share, import and other writes. Defer bulk export even though it is read-only. Exclude Send and the long-running `serve` HTTP API. Updates come with the desktop package. |

Use upstream environment names only. Explicit `--session` takes precedence over `BW_SESSION`. Honor `BW_CLIENTID`, `BW_CLIENTSECRET` and the output/interaction variables set by the global flags in [program.ts][program]. `BW_PASSWORD` is an example name for `--passwordenv BW_PASSWORD`; setting it alone does not select it. Honor `BITWARDENCLI_APPDATA_DIR` as a profile root, with gv-owned filenames in a dedicated subdirectory. This lets both programs use the override safely.

## Session and storage model

In an automation shell, use `BW_SESSION=$(gv unlock --raw --passwordenv BW_PASSWORD) && export BW_SESSION`. Each invocation independently proves it has the active key. A fresh shell without it sees a locked vault. The session key cannot authenticate to the server.

Upstream creates a fresh random AES-256-CBC/HMAC key (64 bytes, base64) at unlock. Its Node secure storage encrypts selected values, including the auto-unlock user key, under that session key and persists protected entries in Lowdb's `data.json`. The vault retains its ordinary encrypted Bitwarden fields. A headless CLI can do this entirely with its data file and environment. Lock drops the saved unlock capability. A child process cannot erase its parent shell's environment. [Key generation][unlock] · [Protected storage][secure] · [Storage wiring and paths][paths] · [Lock][lock]

Upstream looks first for portable `bw-data`, then its directory override, then `Bitwarden CLI` under macOS `~/Library/Application Support`, Windows `%APPDATA%`, or Linux `$XDG_CONFIG_HOME` (default `~/.config`). Use the same OS parents with the distinct name `GoVault CLI`. Skip executable-relative discovery. One active account per profile.

Persist the encrypted sync snapshot, email, account ID, KDF parameters, password-protected user key and last-sync time. A separate versioned session record contains the **user key** sealed with authenticated encryption under a fresh random session secret. Bind profile, account, configured service endpoints and generation as authenticated data. Never persist the session secret. On unlock validate the master password by unwrapping the protected key, atomically replace the session record, then print the new secret. On read, open that record and use the recovered user key for local decryption. Missing or invalid sessions leave the vault locked. Interactive reads may prompt as upstream does.

Use an OS-released interprocess profile lock for state transitions. Read commands hold a shared lock through sensitive output. Long network operations may release the lock during I/O but must recheck generation, identity and revision before publishing results. Lock removes the session record and advances the generation. Logout invalidates the generation first, then erases credentials, tokens, session record and snapshot; interrupted cleanup resumes before another login. A stale process must never recreate logged-out state. Lock cannot revoke plaintext or a copied session record and its matching key already taken by another process.

## API key authentication

1. Send `grant_type=client_credentials`, scope `api`, personal client ID and secret to the configured identity endpoint, with the CLI device fields. Store the returned protected key/KDF and encrypted initial sync so a later password unlock works offline. The API key alone cannot decrypt items.
2. Persist grant kind, account, trusted endpoints, client ID/secret, bearer token and expiry. For password grants persist the refresh token and rotate it when returned. For API keys there is no refresh token. Honor `expires_in` (normally one hour on Bitwarden and two on Vaultwarden). On expiry repeat the client-credentials exchange. On a 401 renew and retry a read at most once. Coordinate refresh across processes and verify the subject before replacing cached credentials. A rejected or revoked secret requires fresh sign-in. [Bitwarden server grant](https://github.com/bitwarden/server/blob/f0bcb2c70914f1e11a9b335e5c0bae59da599d48/src/Identity/IdentityServer/ClientProviders/UserClientProvider.cs#L70-L80) · [Vaultwarden grant](https://github.com/dani-garcia/vaultwarden/blob/1.37.5/src/api/identity.rs#L620-L749)
3. Official token storage is account-scoped. Its service selects disk or memory for client ID and secret, explicitly disabling secure storage for the secret. Access and refresh token placement depends on platform and timeout policy. CLI disk state is Lowdb. Persisting the client secret is intentional because renewal needs it. [Token service][tokens] · [Client-secret storage][secretsetter] · [Grant renewal and subject validation](https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/services/api.service.ts#L1317-L1416)
4. For gv, use a CLI-only Keychain item, Windows Credential Manager entry or Linux Secret Service entry where available. Store the trusted server binding inside the protected record and verify it against the requested destination before every exchange. Snapshot metadata cannot authorize a different host. Logout deletes records in every backend used by the profile.
5. Without a keyring, seal the credential file with AEAD under a domain-separated key derived from the vault user key. For headless API login, fetch the encrypted snapshot using the initial grant. If no master password is available yet, commit only the encrypted snapshot and locked account metadata. At first unlock, confirm the destination from a trusted configuration supplied by the caller before sending credentials. Take the API credentials again from the environment or prompt, validate the account and persist them encrypted. Local unlock still works without credentials. Locked online sync on this backend requires supplied API credentials or an unlock; `sync --last` stays local. This is a deliberate headless parity limit. Never store a plaintext wrapping key beside the file or downgrade a failing keyring silently.

## Output and exit codes

Treat stdout, stderr, exit status and JSON types as the script interface. Normal list output is an array, get-object output a single object and scalar output the value alone. Preserve upstream field spelling, null versus absent, numeric enums, UTC timestamps and array order. Folder fields include `object`, `id` and `name`; collections include `organizationId`; organizations include numeric `status`, `type` and boolean `enabled`. Item output includes type-specific nested fields, IDs, dates, fields, attachments and password history as applicable. Omit decrypted item keys. Apply upstream hidden-password restrictions to nested values, history, hidden fields and scalar lookups. Fail closed if permission metadata is unavailable. Status uses `serverUrl`, `lastSync`, `userEmail`, `userId` and `status` with upstream omission rules and the values `unauthenticated`, `locked`, `unlocked`. [Item projection][item] · [Status projection][status]

An empty list with `--response` is `{"success":true,"data":{"object":"list","data":[]}}`. Scalars wrap as `{"object":"string","data":"…"}` inside the envelope. Status wraps in `{"object":"template","template":{…}}`. Messages carry title, message, noColor and optional raw value. A missing match yields `{"success":false,"message":"Not found."}`. Ambiguous lookups include the candidate IDs in both message and data. Preserve upstream stable error text, including “Vault is locked.” for a failed unlock check. User-facing shell examples may name gv. [Response constructors][responses] · [Output selection][output]

Success exits 0, handled failure normally exits 1 and prints to stderr. With `--response`, handled errors use stdout. `--cleanexit` makes handled failures exit 0; parser errors and fatal exceptions retain failure status. `--pretty` uses two spaces. `--raw` selects the message's raw value. Preserve upstream precedence: quiet suppresses ordinary output and handled failures, but successful response envelopes still print with both flags. Piped final text has no appended newline. Prompts use stderr and `--nointeraction` never waits for terminal input. [Renderer][output] · [Stream writer][files]

## Packaging and PATH

Build `cmd/gv` separately with `CGO_ENABLED=0` for each desktop artifact's OS and CPU, with the same version. Include it before signing, checksumming or generating updater payloads. Require a dependency check excluding NSGo, GUI and cgo packages. No second download.

| Distribution | Installation and upgrade |
| --- | --- |
| macOS DMG | Stage executable `GoVault.app/Contents/MacOS/gv`, sign the helper with Developer ID, hardened runtime and timestamp, then sign the enclosing app. Verify nested signatures before notarizing and stapling final deliverables. Dragging an app cannot install a PATH entry, so Settings offers **Install command-line tool**: one administrator authorization creates `/usr/local/bin/gv -> <app bundle>/Contents/MacOS/gv`. Settings shows the state (installed, installed by Homebrew, broken link, another `gv` on PATH) with Install, Repair and Uninstall, and never replaces a foreign `gv`. The link points into the bundle, so in-app updates and Homebrew upgrades update `gv` with the app. |
| Homebrew cask | Install the same app and declare `binary "#{appdir}/GoVault.app/Contents/MacOS/gv"`. Homebrew owns the link under its prefix. [Cask binary stanza](https://docs.brew.sh/Cask-Cookbook#stanza-binary) |
| Debian and Arch | Stage the helper beside the app under `/opt` and add a package-owned `/usr/bin/gv` link in both manifests. Package manager upgrade and removal cover both. |
| AppImage | Include executable `gv` in the AppDir. Extend `scripts/install-linux.sh` to extract it from the verified image and install it in the chosen bin directory alongside the image. This allows headless use without GTK or FUSE. Use a PATH directory for the advertised install, or show the exact PATH addition for a custom prefix. Standalone image downloads need this integration step. Replace both during updates, including updates initiated by the GUI. |
| Windows NSIS | Include console-subsystem `gv.exe` under the installation directory. Add its directory once to the current user's PATH, preserve other entries and broadcast the environment change. New shells resolve it. On removal delete only the installer-owned PATH entry. Match the desktop signing policy. |

NSGo v0.2.0 copies executable resource modes, but a resource copy does not sign nested code or create PATH entries. Its macOS signer explicitly handles libraries, Sparkle and extensions before signing the app. Linux package generation creates one GUI link; AppRun targets the GUI. NSIS recursively stages payload files. Add an explicit companion-binary staging step or extend these packagers before final assembly. Detect foreign `gv` commands/links and report the conflict without overwriting them. [Resources](https://github.com/nsgo-dev/nsgo/blob/v0.2.0/cmd/nsgo/resources.go#L18-L44) · [Signing](https://github.com/nsgo-dev/nsgo/blob/v0.2.0/cmd/nsgo/sign.go#L133-L178) · [Linux layout](https://github.com/nsgo-dev/nsgo/blob/v0.2.0/cmd/nsgo/linuxpkg.go#L210-L218) · [AppDir](https://github.com/nsgo-dev/nsgo/blob/v0.2.0/cmd/nsgo/appimage.go#L75-L103) · [NSIS](https://github.com/nsgo-dev/nsgo/blob/v0.2.0/cmd/nsgo/nsis.go#L495-L499)

## Core reuse and security boundaries

| Reuse | Add or adapt |
| --- | --- |
| `internal/vaultcore/crypto` KDF, authenticated decryption, key unwrap and buffer wiping; `totp` and `gen` primitives | Session record codec, credential wrapping and CLI generator option mapping. Verify upstream fingerprints and URI matching separately. |
| `api/client.go:62–78,106–190,312ff` password and refresh grants, guarded HTTP, sync and retry; `api/twofactor.go` provider negotiation | Personal API grant, fixed regional endpoint routing, authorized collection/public-key reads, and domain data for URI matching (current sync requests `excludeDomains=true`). Reuse the shared YubiKey OTP validation in commit `61a3fb7`. |
| `state/service.go:395–487` password/user-key unlock, organization-key and item decryption; `state/attachments.go` attachment handling | Add narrow read projections for CLI metadata and access rules, a session-sealing boundary that keeps raw keys out of presentation code, and encrypted sync while locked. Reuse origin checks in `state/sealed.go:181–236`. |
| `store/store.go:23–52,79–140` snapshot schema, file persistence and secret-store interface | CLI-specific OS backends, profile locks, generation checks and crash-safe transitions. Keep parsing, prompts, environment and response DTOs in CLI packages. Keep vaultcore UI-free. |
| `export/format.go` documents common decrypted fields | Compare mappings for shared field types. Export format lacks the CLI response and permission contract; project from the authorized view. |

Prefer a masked prompt or a private password file. Positional passwords, OTPs and `--session` can appear in process listings and shell history. Environment variables can reach child processes and diagnostics. Scope them to the needed shell and unset them after use. Never log grant bodies, bearer headers, session keys, decrypted objects or signed attachment URLs. Use private directories (0700), files (0600), user-only Windows ACLs and same-directory atomic replacement. Treat server filenames as untrusted basenames; prevent traversal and symlink writes. Authenticate attachment bytes before exposing output. Wipe owned mutable key and plaintext buffers promptly; Go strings, OS copies and caller output cannot be reliably erased.

Use desktop HTTP origin checks, normal TLS verification and its non-loopback HTTP warning. Display the warning when configuring such a server, including in unattended operation. Keep bearer tokens on their trusted origin and reject credential-bearing cross-origin redirects. Validate attachment targets through the shared restricted download path. Bind the exact configured base path as well as normalized origin to credentials. Cached list/get, status, unlock, TOTP, generate and encode require no network. Login, sync, peer fingerprint, org-collection enumeration and attachment download have explicit network dependencies. An offline failure preserves the last complete snapshot.

## Testing and acceptance

- Run pinned official bw and gv as subprocesses with separate empty profiles against the same disposable fixture account. Capture both streams and exit status through pipes and a pseudo-terminal. Compare parsed JSON including absent keys, plus exact scalar bytes and stable error strings. Normalize only documented volatile fields such as timestamps and random keys. Check empty, duplicate, personal, organization, restricted, trashed and archived items; all URI match modes; nullable ID filters; attachment binary output; and combinations of global flags.
- Run disposable Vaultwarden with password and personal API-key accounts. Exercise email via a local mail sink, authenticator via a test seed, and YubiKey OTP via an authorized device/validator when available. Record simulated challenges separately from real-provider acceptance. Shorten expiry with a test clock or force a 401 and observe a second grant with no refresh token. Check user-key unlock offline after both grant types.
- On headless Linux with no display, D-Bus or keyring, run API login, unlock, renew, sync, lock and logout across separate processes. Test stale sessions, concurrent unlock/sync/logout, invalid secrets, redirect/origin substitution, edited snapshots, interrupted cleanup and disk contents after logout. Verify reads generate no vault mutation requests.
- Install, upgrade and uninstall every packaged format on its target OS. Invoke `gv --version` and a supported command by name in a new shell; inspect signed macOS artifacts and the actual installed PATH entry. Exercise in-app updates as well as package-manager upgrades. Check unrelated PATH entries and existing commands survive removal.
- Accept v1 when supported contract fixtures pass, a real server completes both sign-in flows, offline reads work with a valid session, old sessions fail after lock/rotation/logout, and each advertised installer passes the PATH test. Track untested servers, hardware providers and package formats explicitly.

## Implementation

| Part | Where |
| --- | --- |
| Binary | `cmd/gv`: version from `-ldflags -X main.version`, else the module version |
| Commands, parsing, prompts, output DTOs | `internal/cli` |
| Profile files, locks, sessions, credentials, login, unlock, sync | `internal/vaultcore/profile` |
| Read projection of a sync snapshot, attachment decryption | `state.OpenVault` (`internal/vaultcore/state/view.go`) |
| OS credential stores | `internal/vaultcore/keyring`: login Keychain (purego), Credential Manager, Secret Service (godbus) |
| Split API/identity hosts, API-key grant, public keys, collections | `internal/vaultcore/api` |
| Fake Bitwarden server for tests | `internal/fakeserver`, shaped after Vaultwarden 1.37.5 |

The profile directory is `GoVault CLI` under the OS parent, or under `BITWARDENCLI_APPDATA_DIR`. It holds `profile.json` (profile and device IDs, server, session generation), `account.json`, the encrypted snapshot `vault_<id>.enc.json`, `session.json`, and `credentials.json` on keyring-free hosts, plus `state.lock` and `credentials.lock`. A session key is 64 random bytes in base64, like bw's; `session.json` holds the user key sealed with AES-256-GCM under a key HKDF-derived from it, with the profile, account, login, endpoints and generation as associated data. Every unlock, lock and logout advances the generation. Token renewal runs under `credentials.lock`, so concurrent processes renew a rotating refresh token once.

gv sends `Bitwarden-Client-Name: cli` and `Bitwarden-Client-Version: 2026.11.0`, the bw release it follows; Vaultwarden withholds SSH keys from clients that send no version.

### Contract fixtures

`internal/cli/testdata/bw` holds the stdout, stderr and exit status of the official bw 2026.11.0 release (the closest release to the reference revision) for 169 invocations in 19 scenarios against the fake server. `TestContractMatchesBW` runs gv through the same steps and compares the bytes, after replacing the server address, session keys, temporary paths, sync times and TOTP codes. Two documented differences are normalized: session messages show `$ gv` examples, and bw's SDK writes internal `ERROR` lines to stderr before a wrong-password message. Regenerate the fixtures with `BW_BINARY=/path/to/bw go test ./internal/cli -run TestCaptureBWFixtures`; it runs bw with private profile directories only.

`TestVaultwarden` runs sign-in, reads, lock, unlock, sync, renewal and logout against a real disposable account when `GV_VAULTWARDEN_URL`, `GV_VAULTWARDEN_EMAIL` and `GV_VAULTWARDEN_PASSWORD` are set (optionally `GV_VAULTWARDEN_TOTP_SEED`, `GV_VAULTWARDEN_CLIENT_ID`, `GV_VAULTWARDEN_CLIENT_SECRET`). The same suite runs against the fake server in every test run.

### Differences from the design and from bw

- **No equivalent domains.** bw's CLI requests `/sync?excludeDomains=true` (its platform reports no autofill), so `--url` applies match rules without equivalent domains. gv does the same, to return the same items.
- **Prompts need a terminal.** bw's prompts also read piped stdin; gv prompts only when stdin is a terminal and otherwise reports the missing input, as with `--nointeraction`.
- **Wrong master password** prints bw 2026.11's SDK message, `Cryptography error, The decryption operation failed`, without its internal log lines.
- **API-key login** prints a session key that unlocks nothing, as bw does; `unlock` provides the usable one.
- **Attachments of items whose passwords are hidden** are refused, as in the GoVault app; bw downloads them.
- **Password generator policies** of organizations are not applied to `generate`.
- **Regular-expression URI matching** uses Go's RE2 syntax, which lacks lookaround and backreferences.
- **Not supported:** Bitwarden cloud's new-device verification, `get exposed`, `get template`, `get org-collection`, `list org-members`, `config server --api` and the other endpoint overrides, and view event logging. Each fails with an explicit message.

## Decisions

1. **macOS PATH:** no installer package in the DMG. Settings installs, repairs and uninstalls the `/usr/local/bin/gv` link into the app bundle, as described under Packaging, and Homebrew's cask links it with the `binary` stanza. The README documents both installs and their removal.
2. **Keyring-free hosts:** credentials are sealed under a key derived from the vault user key. Online sync while locked therefore needs an unlock (`BW_SESSION`) or re-supplied API credentials (`BW_CLIENTID`, `BW_CLIENTSECRET`); `sync --last` and all cached reads stay local.
3. **Independent clients:** the desktop app and `gv` keep separate sign-in and data in v1.

[program]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/program.ts#L29-L490
[vault]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/vault.program.ts#L80-L209
[list]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/commands/list.command.ts#L87-L260
[files]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/utils.ts#L21-L165
[fingerprint]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/commands/get.command.ts#L696-L720
[unlock]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/key-management/commands/unlock.command.ts#L127-L150
[secure]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/platform/services/node-env-secure-storage.service.ts#L28-L119
[paths]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/service-container/service-container.ts#L404-L446
[lock]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/auth/commands/lock.command.ts#L15-L23
[item]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/vault/models/cipher.response.ts#L13-L55
[status]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/commands/status.command.ts#L25-L75
[output]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/base-program.ts#L24-L105
[responses]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/apps/cli/src/models/response.ts#L29-L72
[tokens]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/auth/services/token.service.ts#L172-L229
[secretsetter]: https://github.com/bitwarden/clients/blob/ad5a8f316667f875737c01ec77b6632ab4884430/libs/common/src/auth/services/token.service.ts#L835-L881
