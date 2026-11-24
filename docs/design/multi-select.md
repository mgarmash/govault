# Multi-select and bulk actions for GoVault 0.6.0

Select items directly in the middle pane. One selected item opens its detail. Two or more replace that detail with a count and actions for the selection. The same list serves All Items, categories, folders, organizations, collections, search results, Archive and Trash.

## Using the list

| Gesture | Result |
| --- | --- |
| Click | Select only that row. Cmd-click on macOS or Ctrl-click on Windows/Linux toggles membership and sets the range anchor. |
| Shift-click or Shift-arrow | Select the inclusive range from the anchor in the current sort and search order. Reversing direction shrinks the range. Without an anchor, select the target alone. |
| Cmd/Ctrl-A | Select every matching item, including rows scrolled offscreen. In a text field it selects text. |
| Esc | Dismiss the current menu or dialog first. In the list, clear the selection. Preserve the editor’s existing cancel and unsaved-draft behavior. |
| Delete, including the Mac backward Delete key | With list focus, confirm Move to Trash for the selection. In Trash this key does nothing. Permanent deletion requires its named action. |
| Secondary click | On a selected row, open the menu for the entire selection. On another row, select it alone and open its single-item menu. |

For example, search for “conference”, select all matches and choose **Move to Folder…**. The picker lists personal folders and **No Folder**. Its **Move** button commits the choice. In Trash, select a range and choose **Restore** to bring it back, or **Delete Permanently…** to review the count and confirm. **Empty Trash** continues to target the whole Trash.

Center “3 items selected” and a compact group of labeled buttons in the existing detail pane. Let buttons wrap at narrow widths. Use the existing light/dark list surface, selected accent and contrasting row text in each theme. Outline the keyboard cursor separately so focus stays visible within a selected range. Use the destructive button style for permanent deletion. Keep the list width and row contents stable.

## Selection and focus

Replace the current `core.List` plus single-ID row press with `base.List` and one list-owned `base.NewSelection(cx, true)`, keyed by cipher ID. NSGo 0.3.0 supplies the cursor, anchor, modifier handling, keyboard ranges, Select All and virtualized listbox/option semantics. Remove the competing window-level arrow bindings. Keep the row’s `OnContextMenu` and open `desktop.PopupMenu` at the event position. The pane can use `base.Toolbar` for its action group. [List input](https://github.com/nsgo-dev/nsgo/blob/a287494396df563f6ae372c53da4ff3cc96b5c08/base/list.go#L253-L327) · [Selection](https://github.com/nsgo-dev/nsgo/blob/a287494396df563f6ae372c53da4ff3cc96b5c08/base/selection.go#L5-L118) · [Menu](https://github.com/nsgo-dev/nsgo/blob/a287494396df563f6ae372c53da4ff3cc96b5c08/desktop/menu.go#L58-L63) · [Toolbar](https://github.com/nsgo-dev/nsgo/blob/a287494396df563f6ae372c53da4ff3cc96b5c08/base/toolbar.go#L9-L50)

- Derive the active detail ID only when exactly one ID is selected. Otherwise clear `ActiveCipher`, reveal state and the detail TOTP display. Single-item copy/edit shortcuts then have no target. Run row changes through the existing dirty-draft decision. If the user keeps editing, restore the previous selection and anchor.
- Clear selection and anchor on route, sidebar, query or search-scope change, lock and logout. Back/Forward may reopen one item from history. Keep bulk selections out of history. On resort or sync, keep selected IDs still in the filtered list, prune missing IDs and repair a missing cursor or anchor from the survivors. A newly matching row never joins an earlier Select All.
- Keep focus in the list while selecting. Give each option its item name and selected state. Announce the count once per gesture with `Scope.Announce` when the count changes. Tab reaches the labeled actions. After a dialog closes, restore focus to the invoking control, or to the list if that control disappeared.

## Which items an action affects

Apply each action to its eligible subset. The pane, menu and shortcuts use the same counts. Disable an action with zero eligible items. For mixed selections, show the affected and skipped counts before dispatch, including in the folder picker or destructive confirmation. For example, “Move 3 items to Trash? 2 read-only items will be skipped.” Restore and Archive need only the counts beside their buttons or in their menu labels.

| Action | Eligible items |
| --- | --- |
| Move to Folder | Any accessible item outside Trash, including an archived or read-only organization item. Folder placement is personal. Count items already in the destination as unchanged in the picker. |
| Move to Trash | Writable items outside Trash, including archived items. Confirm once. |
| Restore / Delete Permanently | Writable items in Trash. For permanent deletion, name the action and count, state that recovery is impossible, and default to Cancel. |
| Archive | Unarchived items outside Trash when `CanArchive()` is true. Archive is per user, including for read-only organization items. |
| Unarchive | Archived items outside Trash, even after premium expires. |

For shared-item writes use `state.EffectiveAccess`. An item is read-only if its own flag says so or every known collection containing it is read-only. A hidden password alone does not prevent these metadata operations. For Archive/Unarchive, if any eligible item requires the existing biometric or master-password reprompt, authenticate once for that action and those IDs in this unlocked session. Cancel leaves the entire selection untouched.

Offline, local-only and expired sessions allow selection and inspection. Disable writes and use the existing sync/sign-in status to explain why. During sync, keep the list interactive and recheck eligibility before dispatch. Freeze the reviewed IDs when opening a prompt. Recheck only those IDs. Skip items that lost eligibility or now require an archive reprompt the user has not completed. Run writes under the existing session context. Lock cancels outstanding work and clears names, selection and dialogs.

## Server calls and results

All paths below are relative to `/api/ciphers`. For bulk routes the JSON body contains `ids`. **`PUT /delete` trashes items. `POST /delete` permanently deletes them.** The canonical bulk hard-delete endpoint is `DELETE /api/ciphers`. Neither server uses `/delete-permanent` here.

| Action | Bulk route on both servers | GoVault 0.6.0 |
| --- | --- | --- |
| Move to Folder | `PUT /move` with `folderId` (UUID or null) | Add a narrow move API. Send eligible IDs in groups of at most 500, the hosted Bitwarden limit. This changes only the user’s folder mapping and avoids resaving encrypted fields. [Bitwarden route](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1471-L1482) · [Per-user update](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Sql/dbo/Vault/Stored%20Procedures/Cipher/Cipher_Move.sql#L9-L35) · [Vaultwarden](https://github.com/dani-garcia/vaultwarden/blob/07c6b00da778ff6903a9a40c0f24f77daf93bea4/src/api/core/ciphers.rs#L2190-L2279) |
| Trash / Restore | `PUT /delete`, `PUT /restore` | Call `SoftDeleteCipher` or `RestoreCipher` per ID (`PUT /{id}/delete` or `/{id}/restore`). Each result identifies the item and the existing service updates its encrypted snapshot. [Bitwarden trash](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1286-L1322) · [Bitwarden restore](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1392-L1439) · [Vaultwarden](https://github.com/dani-garcia/vaultwarden/blob/07c6b00da778ff6903a9a40c0f24f77daf93bea4/src/api/core/ciphers.rs#L2028-L2188) |
| Delete Permanently | `DELETE /api/ciphers` or `POST /delete` | Pass only the confirmed IDs and their revisions to the existing `EmptyTrash` loop. For each, GET the current cipher, check it is still trashed, editable and at the confirmed revision, then `DELETE /{id}`. Keep its final sync. The server’s delete is unconditional, so a restore between GET and DELETE can still race. [Bitwarden](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1192-L1251) · [Vaultwarden](https://github.com/dani-garcia/vaultwarden/blob/07c6b00da778ff6903a9a40c0f24f77daf93bea4/src/api/core/ciphers.rs#L2049-L2101) |
| Archive / Unarchive | `PUT /archive`, `PUT /unarchive` | Call `ArchiveCipher` or `UnarchiveCipher` per ID (`PUT /{id}/archive` or `/{id}/unarchive`). Reuse the service’s handling of unsupported servers, ambiguous 404s and concurrent sync. [Bitwarden archive](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1149-L1190) · [Bitwarden unarchive](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1349-L1390) · [Vaultwarden](https://github.com/dani-garcia/vaultwarden/blob/07c6b00da778ff6903a9a40c0f24f77daf93bea4/src/api/core/ciphers.rs#L2357-L2385) |

Vaultwarden can move some items before returning an error. Bitwarden can update only the IDs still accessible to the user. After the move requests, force one sync even after a partial response. Compare each submitted ID’s synced folder with the destination. Treat missing IDs or an unavailable sync as unconfirmed. For the per-item paths, process sequentially, keep confirmed successes, and continue past individual permission errors. Stop on session loss, offline failure or an unsupported action. Distinguish unattempted items and ambiguous network outcomes. A local snapshot save failure after a confirmed write warrants the existing local-copy warning. [Vaultwarden partial move](https://github.com/dani-garcia/vaultwarden/blob/07c6b00da778ff6903a9a40c0f24f77daf93bea4/src/api/core/ciphers.rs#L2224-L2269)

Disable duplicate dispatch while an action runs. Refresh the filtered results and sidebar counts from the service. In the originating selection, release successful IDs and leave failed, skipped or unconfirmed IDs selected wherever still visible. Preserve any newer user selection. Show one result, for example “3 restored. Payroll could not be restored because access changed.” Use a single dismissible, scrollable result for multiple failures so each affected item and reason can be read.

## Implementation and verification

- **Desktop.** `cmd/govault/ui/{vault,model,mainview,nav,trash_clone}.go` owns the rows, detail, key scope, history and confirmations. Add count, picker and result strings in `cmd/govault/locales`. Omit row checkboxes, a selection mode, a second action bar and new settings. The row gestures and detail actions cover the same work.
- **Core.** In `internal/vaultcore/{api/client.go,state}`, add the folder move and reconciliation, expose effective read-only status on list summaries, and return per-ID outcomes from the shared Trash loop. Update the desktop service interface, demo and test doubles. Keep selection in the UI. Omit undo, offline queues, replay and progress dialogs. Trash already supports Restore, and automatic replay after a lost response could repeat a completed write.
- **Focused tests.** Drive the list through toggle, range after sort, Select All in filtered results, right-click inside/outside the selection, Esc, and pruning after sync. Check that editing text consumes Select All/Delete. Table-test effective permissions across two collections, personal folder placement, archive entitlement/reprompt and offline/local-only gates. In `internal/fakeserver`, exercise one client path per action through vaultcore. Assert the verb, body/target and resulting snapshot. Include a partial move and a selected Trash item restored elsewhere before confirmation.
- **Open verification question.** Does each desktop backend deliver the labeled Delete key and return keyboard or screen-reader focus correctly after a native menu or alert? Check AppKit with VoiceOver, Windows and GTK 4 with their native input. Inspect the selected and focused rows in both themes. This is a UI acceptance check for implementation.
