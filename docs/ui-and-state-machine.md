# GoVault UI Wireframes, State Machine, and NSGo Signal Architecture

## Goal

Define the desktop user interface wireframes, application/view state machines, keyboard shortcuts, and NSGo reactive signal graph for `govault` MVP so `cmd/govault` can be implemented directly against `internal/vaultcore` with minimal ambiguity and strict CPU/memory discipline.

## Non-goals

- Visual branding assets, custom illustrations, or marketing pages.
- Phase 2 screens (2FA verification prompt, Organization/Collection picker, Attachment uploader, Bitwarden Send list, multi-account switcher).
- Mobile/responsive phone layouts (desktop macOS and Linux only).

## Requirements and Constraints

- Built with NSGo (`nsgo-dev/nsgo`) native views (`core.View`, `core.Text`, `core.Input`, `core.Scroll`, `core.List`, `ui.Button`, `ui.ToastContent`, `desktop.*`) styled uniformly with `core.Style` and Tailwind CSS 4 classes (avoiding Linux-unsupported backdrop filters for critical contrast).
- Strictly event-driven: zero timers when locked or when no visible view displays a TOTP item.
- All `vaultcore` I/O, KDF derivation, and `cx.Secrets()` calls run off the NSGo engine goroutine and marshal UI state updates back via `cx.Post(...)`.
- Touch ID on macOS is first-class on both the Lock Screen and Quick Access Panel, with seamless Master Password fallback.
- Quick Access global hotkey is **user-configurable** (unset by default so it never hijacks an existing shortcut unexpectedly).

## Design

### 1. Application & Window Lifecycle State Machine

GoVault runs as a tray-resident desktop app (`nsgo.Run(App, ...)` with `desktop.SetShutdownMode` keeping the process alive when windows close):

```text
                    +-----------------------------+
   Process Start -->|  Bootstrap (App Scope)      |
                    |  - Load persisted Prefs     |
                    |  - Init Tray + Optional HK  |
                    |  - Check saved Snapshot     |
                    +--------------+--------------+
                                   |
          +------------------------+------------------------+
          | desktop.LaunchedAtLogin()                       | User launched directly
          v                                                 v
  +---------------+                               +-------------------+
  | Tray-Resident |<--- Main Window Closed -------| Main Window Open  |
  | (No Windows)  |---- Tray/Dock/Reopen -------->| (Active Surface)  |
  +-------+-------+                               +---------+---------+
          |                                                 |
          | Configured Global Hotkey                        | Esc / Focus Lost / Action
          v                                                 |
  +---------------------+                                   |
  | Quick Access Panel  |-----------------------------------+
  | (desktop.OpenPanel) | (dismiss destroys/hides panel)
  +---------------------+
```

**Memory rule on window close**:
- Closing the Main Window hides or destroys its window surface (releasing native view allocations) while preserving the tray icon and configured hotkey.
- Locking (`Cmd+L`, idle timeout, or Tray -> Lock Now) immediately invokes `vaultcore.Lock()`, wipes all decrypted signals (`ciphers`, `folders`, `selectedCipher`), stops the TOTP ticker, and pauses writes until unlocked.

---

### 2. Authentication & Vault State Machine

```text
  +------------+   Login(url, email, pw)   +----------------+
  | LoggedOut  |-------------------------->| Authenticating |
  +-----+------+                           +---+--------+---+
        ^                                      |        |
        | Logout()                     Success |        | Auth Error
        | or WS LogOut(11)                     v        +---> (back to LoggedOut + inline error)
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
- `RouteSettings` (Security, Touch ID, Clipboard, Quick Access Hotkey, Startup & Tray, Sync & Account)

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
| > All Items (412) |----------------------------|  Login · Work                          |
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
1. **Security**:
   - `Unlock with Touch ID` toggle (macOS, shown when `BiometricAvailability != BiometricNone`).
   - `Auto-prompt Touch ID on lock screen` toggle.
   - `Auto-lock timeout` select (`1 min`, `5 min`, `15 min` default, `1 hour`, `Never`).
   - `Lock on system sleep / screen lock` toggle (Phase 2).
2. **Clipboard**:
   - `Clear clipboard after` select (`15s`, `30s` default, `60s`, `Never`).
   - `Conceal copied secrets from clipboard managers (macOS)` status indicator (always active via `clipboard_darwin.go`).
3. **Quick Access & Tray**:
   - `Quick Access global shortcut` key recorder / clear button (default: **None / Disabled**; user-configurable).
   - `Launch at login` toggle (`desktop.SetLaunchAtLogin`).
   - `Hide Dock icon (menu bar only)` toggle on macOS (`desktop.SetDockVisible`).
4. **Account & Sync**:
   - Server URL, Email, KDF summary (`Argon2id` or `PBKDF2`), Last sync time, `[ Sync Now ]`, `[ Log Out ]`.

#### Screen F: Quick Access Floating Panel (`desktop.OpenPanel`)
Compact borderless floating panel (`560px` wide, dynamic height up to `400px`), opened via user-configured global hotkey or Tray -> `Quick Search`:

```text
Unlocked state:
+------------------------------------------------------+
| [ > Search logins, notes, cards...             Esc ] |
|------------------------------------------------------|
| > GitHub · alice@example.com       [TOTP]  [Enter ↵] |
|   AWS Production · admin@corp.com                    |
|   Cloudflare · alice@example.com   [TOTP]            |
|   Tailscale · alice@example.com                      |
|------------------------------------------------------|
| ↵ Copy Password   ⌘↵ Copy User   ⌘T Copy TOTP   ⌘O Open |
+------------------------------------------------------+

Locked state:
+------------------------------------------------------+
| [ Lock ] GoVault is locked — Press Touch ID or type: |
| [ Master Password...               ] [ Touch ID ]    |
+------------------------------------------------------+
```
- Keyboard-only flow: `↑/↓` selects row, `Enter` copies password (concealed + auto-clear) and closes panel, `Cmd+Enter` copies username and closes, `Cmd+T` copies TOTP and closes, `Cmd+O` opens full Main Window on that item, `Esc` or blur dismisses panel.

#### Tray Menu (`desktop.NewTray`)
- `Open GoVault`
- `Quick Search` (shows configured hotkey hint if set)
- `---`
- `Sync Now` (disabled if locked/offline)
- `Lock Now` (only when unlocked)
- `---`
- `Quit GoVault`

---

### 4. NSGo Reactive Signal Graph & Threading Model

All shared app state lives in `AppModel` created once inside `App(app *core.Scope)` and shared by Main Window and Quick Access Panel:

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
	FilteredItems *core.Collection[string, state.CipherSummary] // Keyed by cipher ID
	SelectedID    *core.Selector[string]                        // O(1) selection updates
	ActiveCipher  *core.Signal[*state.Cipher]                   // Full decrypted detail
	EditMode      *core.Signal[bool]

	// Visibility-gated TOTP state (nil ticker when hidden or non-TOTP item)
	TOTPCode      *core.Signal[string]
	TOTPRemaining *core.Signal[int]
	TOTPPeriod    *core.Signal[int]

	// Feedback & lifecycle
	Toast         *core.Signal[*ToastMessage]
	MainWin       *desktop.Window
	QuickPanel    *desktop.Window
	HotKey        *desktop.HotKey
}
```

**Concurrency & Resource Guarantees**:
1. **No blocking on engine goroutine**: `Login`, `UnlockWithPassword`, `SyncNow`, `SaveCipher`, and `cx.Secrets().Get/Set` run in spawned goroutines and post results back with `cx.Post(...)`.
2. **Search responsiveness**: Typing in `SearchQuery` calls `Core.Search(query, filter)` synchronously if `< 5,000` items (takes `< 1 ms` in memory) and diffs into `FilteredItems` (`core.Collection`).
3. **TOTP ticker gating**: A single `totpController` watches `(MainWin visible && ActiveCipher has TOTP) || (QuickPanel visible && selected item has TOTP)`. Only while that predicate is `true` does a 1-second `time.Ticker` run. The instant the window closes, blurs out of Quick Panel, switches to a non-TOTP cipher, or locks, `ticker.Stop()` executes.
4. **Idle lock timer**: Reset on user input/window focus/vault actions; runs a single `time.AfterFunc` (zero periodic polling).

---

### 5. Keyboard Shortcuts Matrix

| Shortcut (macOS / Linux) | Context | Action |
| --- | --- | --- |
| `Cmd+F` / `Ctrl+F` | Main Window | Focus search input |
| `Cmd+N` / `Ctrl+N` | Main Window (Unlocked) | Create new cipher |
| `Cmd+E` / `Ctrl+E` | Main Window (DetailView) | Edit selected cipher |
| `Cmd+S` / `Ctrl+S` | Main Window (DetailEdit) | Save cipher |
| `Esc` | DetailEdit / Quick Panel | Cancel edit (confirm if dirty) / Dismiss Quick Panel |
| `Cmd+C` / `Ctrl+C` (no text selected) | DetailView | Copy password (concealed + auto-clear) |
| `Cmd+Shift+U` / `Ctrl+Shift+U` | DetailView | Copy username |
| `Cmd+Shift+T` / `Ctrl+Shift+T` | DetailView | Copy TOTP code |
| `Cmd+L` / `Ctrl+L` | Main Window (Unlocked) | Lock vault immediately |
| `Cmd+R` / `Ctrl+R` | Main Window (Unlocked) | Sync vault now |
| `Cmd+,` / `Ctrl+,` | Main Window | Open Settings view |
| `↑` / `↓` | List / Quick Panel | Move selection |
| User-configured (default unset) | Global OS | Toggle Quick Access floating panel |

---

### 6. Edge Cases & Failure UX

- **Offline unlock**: If the server is unreachable on startup/unlock, `UnlockWithPassword` or Touch ID decrypts the local `vault_<id>.enc.json` snapshot immediately and sets `SyncState = SyncOffline`. Full read/search/copy/TOTP remains available.
- **Stale revision conflict (`409` / revision mismatch on save)**: Show `cx.ShowAlert` explaining the item changed on another device, offering `Reload Latest` or `Cancel`.
- **Dirty edit guard**: Switching ciphers, locking, or closing the window with unsaved edits prompts `Discard unsaved changes?` via `cx.ShowAlert` (except forced idle lock / `LogOut` push, which prioritizes security and locks immediately).
- **Empty states**: Clean empty states for empty vault, zero search results, and empty Trash.
- **Reprompt flag (`cipher.reprompt == 1`)**: Before revealing or copying password/TOTP on an item marked with master-password reprompt, gate with Touch ID (if enabled) or a master-password verification dialog.

## Acceptance Criteria

- [ ] Every MVP screen (Login, Lock with Touch ID, 3-Pane Vault, Create/Edit, Generator, Settings, Quick Access Panel, Tray Menu) has a clear state transition path with no dead ends.
- [ ] TOTP ticker is provably stopped when locked, minimized/closed to tray, or viewing a non-TOTP item (`0%` idle CPU).
- [ ] `nsgotest` headless UI tests cover Login -> Vault search -> Detail view -> Edit/Save -> Lock -> Unlock state transitions using mock `vaultcore.VaultService`.
- [ ] Quick Access global hotkey is unset by default and can be bound, persisted, rebound, and cleared in Settings without restarting the app.

## Risks

- **Linux Wayland floating panel placement**: Verified from NSGo docs (`components.md`) that `desktop.CanPlaceWindows` is false on Wayland because Wayland compositors control window placement. *Mitigation*: Quick Access Panel opens as a centered/compositor-placed floating window without assuming exact pixel coordinates on Wayland.
- **Dirty form vs idle lock**: Auto-locking while mid-edit discards unsaved changes. *Mitigation*: Reset the idle lock timer on every keystroke in `DetailEdit`.

## Related Documents

- [Architecture & MVP Design](architecture.md)
- [`vaultcore` Interface, Protocol, and Test Vector Specification](vaultcore-spec.md)
- [Official Bitwarden Desktop Client, Vaultwarden Protocol, and NSGo Research](research/official-client-and-protocol.md)
