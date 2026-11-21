# GoVault UI Wireframes, State Machine, and NSGo Signal Architecture

## Goal

Define the desktop user interface wireframes, application/view state machines, keyboard shortcuts, and NSGo reactive signal graph for `govault` MVP so `cmd/govault` can be implemented directly against `internal/vaultcore` with minimal ambiguity and strict CPU/memory discipline.

## Non-goals

- Visual branding assets, custom illustrations, or marketing pages.
- Screens not built yet: Attachment uploader, Bitwarden Send list, multi-account switcher, moving items between organizations.
- Mobile/responsive phone layouts (desktop macOS and Linux only).

## Requirements and Constraints

- Built with NSGo (`nsgo-dev/nsgo`) native views (`core.View`, `core.Text`, `core.Input`, `core.Scroll`, `core.List`, `ui.Button`, `ui.ToastContent`, `desktop.*`) styled uniformly with `core.Style` and Tailwind CSS 4 classes (avoiding Linux-unsupported backdrop filters for critical contrast).
- Strictly event-driven: zero timers when locked or when no visible view displays a TOTP item.
- All `vaultcore` I/O, KDF derivation, and `cx.Secrets()` calls run off the NSGo engine goroutine and marshal UI state updates back via `cx.Post(...)`.
- Touch ID on macOS is first-class on the Lock Screen, with seamless Master Password fallback.
- There is no Quick Access panel or global hotkey; `Cmd+F` in the main window is the quick-search path.

## Design

### 1. Application & Window Lifecycle State Machine

GoVault runs as a desktop app with an optional menu bar icon (`desktop.SetShutdownMode` keeps the process alive when the window closes while the icon is shown):

```text
                    +-----------------------------+
   Process Start -->|  Bootstrap (App Scope)      |
                    |  - Load persisted Prefs     |
                    |  - Menu bar icon (optional) |
                    |  - Sleep/lock observers     |
                    |  - Check saved Snapshot     |
                    +--------------+--------------+
                                   |
          +------------------------+------------------------+
          | Launched at login + icon on                     | Otherwise
          v                                                 v
  +---------------+                               +-------------------+
  | Menu bar only |<--- Main Window Closed -------| Main Window Open  |
  | (No Windows)  |---- Icon/Dock/Reopen -------->| (Active Surface)  |
  +---------------+                               +-------------------+
```

**Memory rule on window close**:
- Closing the Main Window destroys its window surface (releasing native view allocations) while the menu bar icon, if shown, keeps the app reachable.
- Locking (`Cmd+L`, idle timeout, menu bar Lock Now, or macOS sleep/screen lock when enabled) immediately invokes `vaultcore.Lock()`, zeroes the User Key and org keys, wipes decrypted signals (`ciphers`, `folders`, `collections`, `selectedCipher`), stops the TOTP ticker, and releases Secure Event Input.

---

### 2. Authentication & Vault State Machine

```text
  +------------+   Login(url, email, pw)   +----------------+
  | LoggedOut  |-------------------------->| Authenticating |<--+ Verify(code, remember)
  +-----+------+                           +---+--------+---+   |
        ^                                      |        |       |
        | Logout()                     Success |        +-> 2FA challenge -> TwoFactor step
        | or WS LogOut(11)                     v        +---> Auth Error (inline, back to LoggedOut)
        |                               +------+-----+
        +-------------------------------|  Unlocked  |<-------------------------+
        |                               |  (Active)  |                          |
        |                               +------+-----+                          |
        |                                      | Lock() / Idle Timeout / Sleep  |
        |                                      v                                |
        |                               +------+-----+   UnlockWithUserKey()    |
        +-------------------------------|   Locked   |--- (Touch ID success) ---+
            Logout()                    | (Snapshot  |                          |
                                        |  on disk)  |--- UnlockWithPassword() -+
                                        +------------+   (Derive KDF -> Unwrap)
```

**Sub-states while `Unlocked` (Main Window)**:
- `RouteVault` (default 3-pane split):
  - `DetailEmpty` (no item selected)
  - `DetailView` (read-only item view + copy/reveal/live TOTP)
  - `DetailEdit` (create new or edit existing cipher; dirty-state guard on switch/close)
- `RouteGenerator` (standalone Password / Passphrase generator with quick copy)
- `RouteSettings` (Account, Security, Privacy, Clipboard, Menu Bar & Startup, About)

**Sync status orthogonal signal** (`SyncState`):
- `SyncIdle` (shows `Last synced: 2m ago`)
- `SyncInProgress` (subtle spinner in sidebar footer)
- `SyncOffline` (subtle amber pill: `Offline — showing cached vault`; read/copy/TOTP still work normally; writes disabled with clear tooltip)
- `SyncAuthExpired` (refresh token failed -> banner prompting re-login without erasing cached offline vault)

---

### 3. Screen Wireframes (Desktop MVP)

#### Screen A: Login View (`StatusLoggedOut`)
Centered card (`420px` wide) inside Main Window:

```text
+------------------------------------------------------------------+
|  o o o                      GoVault                              |
+------------------------------------------------------------------+
|                                                                  |
|               +----------------------------------+               |
|               |           [ GoVault ]            |               |
|               |     Sign in to Vaultwarden       |               |
|               |                                  |               |
|               |  Server URL                      |               |
|               |  [ https://vault.example.com   ] |               |
|               |                                  |               |
|               |  Email                           |               |
|               |  [ alice@example.com           ] |               |
|               |                                  |               |
|               |  Master Password                 |               |
|               |  [ ••••••••••••••••••••  (eye) ] |               |
|               |                                  |               |
|               |  [! Inline error message area  ] |               |
|               |                                  |               |
|               |  [       Sign In (Primary)     ] |               |
|               +----------------------------------+               |
|                                                                  |
+------------------------------------------------------------------+
```
- Pressing `Enter` in Master Password submits; button shows spinner + disabled state during KDF + login (`Argon2id` may take 200–600 ms).
- **Two-step verification step**: if the server answers with a 2FA challenge, the same card switches to a verification step: an Authenticator App / Email selector (when both are enabled), Send/Resend Code for email, a monospace code field (`Enter` verifies), a "Remember this device" checkbox, Verify, and Back to Sign In. A wrong code shows an inline error; unsupported-only providers show a message naming them.

#### Screen B: Lock Screen (`StatusLocked`)

```text
+------------------------------------------------------------------+
|  o o o                      GoVault                              |
+------------------------------------------------------------------+
|                                                                  |
|               +----------------------------------+               |
|               |          [ Lock Icon ]           |               |
|               |         Vault is Locked          |               |
|               |   alice@example.com              |               |
|               |   vault.example.com              |               |
|               |                                  |               |
|               |  [ (Fingerprint) Unlock with     |  <-- Shown only if
|               |         Touch ID               ] |      Touch ID enabled
|               |                                  |               |
|               |  ---------- or password -------  |               |
|               |                                  |               |
|               |  Master Password                 |               |
|               |  [ ••••••••••••••••••••  (eye) ] |               |
|               |  [        Unlock (Enter)       ] |               |
|               |                                  |               |
|               |              [ Log out ]         |               |
|               +----------------------------------+               |
|                                                                  |
+------------------------------------------------------------------+
```
- Optional setting: `Auto-prompt Touch ID when window opens` (default `true` when Touch ID is enabled).
- If Touch ID is cancelled or fails, focus immediately lands in the Master Password input with zero modal friction.

#### Screen C: Main Window — 3-Pane Vault Workspace (`StatusUnlocked`, `RouteVault`)
Default window size `980 x 640`, minimum `780 x 500`.

```text
+-----------------------------------------------------------------------------------------+
| o o o  GoVault                                        [ Sync ] [ Lock ] [ + New Item ] |
+-------------------+----------------------------+----------------------------------------+
| VAULT             | [ Search vault... (Cmd+F) ]|  GitHub                  [★] [ Edit ]  |
| > All Items (412) |----------------------------|  Login · Work · Acme · Engineering     |
|   Favorites (18)  | * GitHub                   |----------------------------------------|
|                   |   alice@example.com        |  Username                              |
| TYPES             |----------------------------|  alice@example.com            [ Copy ] |
|   Login (340)     |   AWS Production           |                                        |
|   Card (12)       |   admin@corp.com           |  Password                              |
|   Identity (4)    |----------------------------|  ••••••••••••••••••     [Eye] [ Copy ] |
|   Secure Note (56)|   Cloudflare               |                                        |
|                   |   alice@example.com        |  Verification Code (TOTP)              |
| FOLDERS       [+] |----------------------------|  482 910   (21s ○)             [ Copy ] |
|   Personal (120)  |   Tailscale                |                                        |
|   Work (85)       |   alice@example.com        |  Websites                              |
|   Servers (42)    |   ... (core.List           |  https://github.com     [Open] [ Copy ] |
|   No Folder (165) |        virtualized)        |                                        |
| COLLECTIONS       |                            |                                        |
|   Engineering (9) |                            |                                        |
|                   |                            |  Custom Fields                         |
| Trash (3)         |                            |  Recovery Email: ...          [ Copy ] |
|-------------------|                            |                                        |
| Generator         |                            |  Notes                                 |
| Settings          |                            |  Main personal & OSS account...        |
|-------------------|                            |----------------------------------------|
| ● Synced 2m ago   |                            |  Updated 2026-11-18   [ Move to Trash ]|
+-------------------+----------------------------+----------------------------------------+
                                                   [ Toast: Password copied · clears 30s ]
```

- **Panes**: the sidebar and list widths are draggable and persist. Rows and the detail header show the site icon from the Vaultwarden icon service when "Show website icons" is on, falling back to the monogram badge.
- **Collections**: shown only when the vault has collections; selecting one filters the list. Shared items show organization and collection pills; read-only items cannot be edited or trashed, and hidden passwords cannot be revealed or copied. Search stays global across personal and organization items.
- **Middle list (`core.List`)** is backed by `core.NewCollection` + `core.NewSelector`: selecting another item updates only the two affected rows.
- **Trash view**: replaces `[ Edit ]` / `[ Move to Trash ]` with `[ Restore ]` and `[ Delete Permanently ]` (latter gated by `cx.ShowAlert` with `core.AlertDestructive`).
- **TOTP row**: only appears if `cipher.Login.TOTP != ""`; mounts a visibility-aware 1-second ticker that stops immediately when switching to an item without TOTP, hiding the window, or locking the vault.

#### Screen D: Cipher Create / Edit Pane (`DetailEdit`)

```text
+----------------------------------------+
|  Edit Login       [ Cancel ] [ Save ]  |
|----------------------------------------|
|  Type: [ Login v ] (new item only)     |
|  Name *                                |
|  [ GitHub                            ] |
|  Folder                                |
|  [ Work v ]                 [★] Fav    |
|                                        |
|  Username                              |
|  [ alice@example.com                 ] |
|  Password                              |
|  [ •••••••••••••••••  ] [Eye] [Gen ↻]  |
|  Authenticator Key (TOTP)              |
|  [ otpauth://... or Base32           ] |
|                                        |
|  URIs                        [ + Add ] |
|  [ https://github.com          ] [ x ] |
|                                        |
|  Custom Fields               [ + Add ] |
|  [ Text v ] [ Key ] [ Value    ] [ x ] |
|                                        |
|  Notes                                 |
|  [ multiline textarea                ] |
+----------------------------------------+
```
- `[Gen ↻]` fills a newly generated password using persisted generator preferences.
- Saving encrypts fields in `vaultcore` (preserving `cipher.key` if present, sending `lastKnownRevisionDate`), calls `POST /api/ciphers` or `PUT /api/ciphers/{id}`, updates the encrypted snapshot, and refreshes the in-memory index.

#### Screen E: Settings View (`RouteSettings`)
Single scrollable column inside the main content area:
1. **Account**: server, email, KDF summary, last sync, `[ Sync Now ]`, `[ Log Out ]`.
2. **Security**: Touch ID unlock and auto-prompt (macOS), auto-lock timeout (`1 min`, `5 min`, `15 min` default, `1 hour`, `Never`), `Lock on sleep or screen lock` (macOS, on by default).
3. **Privacy**: `Show website icons` (on by default) and `[ Clear Icon Cache ]`.
4. **Clipboard**: clear-after timeout (`15s`, `30s` default, `60s`, `Never`) and concealed clipboard status.
5. **Menu Bar & Startup**: show menu bar icon, launch at login, hide Dock icon (macOS).
6. **About**: version and `[ Check for Updates… ]`.

#### Menu Bar Menu (`desktop.NewTray`)
- `Open GoVault`
- `Check for Updates…`
- `---`
- `Sync Now` (disabled if locked/offline)
- `Lock Now` (only when unlocked)
- `---`
- `Quit GoVault`

---

### 4. NSGo Reactive Signal Graph & Threading Model

All shared app state lives in `AppModel` created once inside `App(app *core.Scope)` (simplified):

```go
type AppModel struct {
	Core      state.VaultService
	Prefs     *core.Persisted[UserPrefs] // Stored in cx.Storage() as versioned JSON

	// Core reactive state (all mutated ONLY on NSGo engine goroutine via cx.Post)
	LockState *core.Signal[state.LockStatus]
	SyncState *core.Signal[SyncStatus]
	LastSync  *core.Signal[time.Time]
	Route     *core.Signal[MainRoute] // RouteVault | RouteGenerator | RouteSettings

	// Vault navigation & virtualized list
	SidebarFilter *core.Signal[state.SearchFilter]
	SearchQuery   *core.Signal[string]
	Folders       *core.Signal[[]state.Folder]
	Collections   *core.Signal[[]state.Collection]
	FilteredItems *core.Collection[string, state.CipherSummary] // Keyed by cipher ID
	SelectedID    *core.Selector[string]                        // O(1) selection updates
	ActiveCipher  *core.Signal[*state.Cipher]                   // Full decrypted detail
	EditMode      *core.Signal[bool]

	// Visibility-gated TOTP state (nil ticker when hidden or non-TOTP item)
	TOTPCode      *core.Signal[string]
	TOTPRemaining *core.Signal[int]
	TOTPPeriod    *core.Signal[int]

	// Two-step login and feedback
	TwoFactor     *core.Signal[*TwoFactorPrompt]
	Toaster       *ui.Toaster
}
```

**Concurrency & Resource Guarantees**:
1. **No blocking on engine goroutine**: `Login`, `UnlockWithPassword`, `SyncNow`, `SaveCipher`, and `cx.Secrets().Get/Set` run in spawned goroutines and post results back with `cx.Post(...)`.
2. **Search responsiveness**: Typing in `SearchQuery` calls `Core.Search(query, filter)` synchronously if `< 5,000` items (takes `< 1 ms` in memory) and diffs into `FilteredItems` (`core.Collection`).
3. **TOTP ticker gating**: A single `totpController` watches `MainWin visible && ActiveCipher has TOTP`. Only while that predicate is `true` does a 1-second `time.Ticker` run; closing the window, switching to a non-TOTP cipher, or locking stops it.
4. **Idle lock timer**: Reset on user input/window focus/vault actions; runs a single `time.AfterFunc` (zero periodic polling).

---

### 5. Keyboard Shortcuts Matrix

| Shortcut (macOS / Linux) | Context | Action |
| --- | --- | --- |
| `Cmd+F` / `Ctrl+F` | Main Window | Focus search input |
| `Cmd+N` / `Ctrl+N` | Main Window (Unlocked) | Create new cipher |
| `Cmd+E` / `Ctrl+E` | Main Window (DetailView) | Edit selected cipher |
| `Cmd+S` / `Ctrl+S` | Main Window (DetailEdit) | Save cipher |
| `Esc` | DetailEdit | Cancel edit (confirm if dirty) |
| `Cmd+C` / `Ctrl+C` (no text selected) | DetailView | Copy password (concealed + auto-clear) |
| `Cmd+Shift+U` / `Ctrl+Shift+U` | DetailView | Copy username |
| `Cmd+Shift+T` / `Ctrl+Shift+T` | DetailView | Copy TOTP code |
| `Cmd+L` / `Ctrl+L` | Main Window (Unlocked) | Lock vault immediately |
| `Cmd+R` / `Ctrl+R` | Main Window (Unlocked) | Sync vault now |
| `Cmd+,` / `Ctrl+,` | Main Window | Open Settings view |
| `↑` / `↓` | List | Move selection |

---

### 6. Edge Cases & Failure UX

- **Offline unlock**: If the server is unreachable on startup/unlock, `UnlockWithPassword` or Touch ID decrypts the local `vault_<id>.enc.json` snapshot immediately and sets `SyncState = SyncOffline`. Full read/search/copy/TOTP remains available.
- **Stale revision conflict (`409` / revision mismatch on save)**: Show `cx.ShowAlert` explaining the item changed on another device, offering `Reload Latest` or `Cancel`.
- **Dirty edit guard**: Switching ciphers, locking, or closing the window with unsaved edits prompts `Discard unsaved changes?` via `cx.ShowAlert` (except forced idle lock / `LogOut` push, which prioritizes security and locks immediately).
- **Empty states**: Clean empty states for empty vault, zero search results, and empty Trash.
- **Reprompt flag (`cipher.reprompt == 1`)**: Before revealing or copying password/TOTP on an item marked with master-password reprompt, gate with Touch ID (if enabled) or a master-password verification dialog.

## Acceptance Criteria

- [ ] Every screen (Login and 2FA, Lock with Touch ID, 3-Pane Vault, Create/Edit, Generator, Settings, Menu Bar Menu) has a clear state transition path with no dead ends.
- [ ] TOTP ticker is provably stopped when locked, minimized/closed to tray, or viewing a non-TOTP item (`0%` idle CPU).
- [ ] `nsgotest` headless UI tests cover Login -> Vault search -> Detail view -> Edit/Save -> Lock -> Unlock state transitions using mock `vaultcore.VaultService`.

## Risks

- **Dirty form vs idle lock**: Auto-locking while mid-edit discards unsaved changes. *Mitigation*: Reset the idle lock timer on every keystroke in `DetailEdit`.

## Related Documents

- [Architecture & MVP Design](architecture.md)
- [`vaultcore` Interface, Protocol, and Test Vector Specification](vaultcore-spec.md)
- [Official Bitwarden Desktop Client, Vaultwarden Protocol, and NSGo Research](research/official-client-and-protocol.md)
