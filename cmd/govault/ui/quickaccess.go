package ui

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

// QuickField is one credential value Quick Access can copy or fill.
type QuickField uint8

const (
	QuickUsername QuickField = iota
	QuickPassword
	QuickTOTP
	// QuickLogin is the username/password pair: Fill receives the username,
	// the password and tab true, and the target types a Tab between them
	// without submitting.
	QuickLogin
)

// QuickTarget is the app, window and optional browser origin Quick Access
// fills. App and Window are human-readable and shown before every fill.
// Origin is empty for a native target, or a browser HTTPS origin; it only
// ranks search results and never authorizes or blocks a fill.
// Fill receives a single field's value as its first argument, an empty
// second argument and tab false, or the QuickLogin pair as username and
// password with tab true. It must verify the destination and fail closed.
// Errors must be static, user-safe text; the panel shows them as-is.
type QuickTarget struct {
	App, Window, Origin string
	Fill                func(user, password string, tab bool) error
}

const quickMaxRows = 200

var errQuickAccessCanceled = errors.New("quick access canceled")

type quickDenied string

func (e quickDenied) Error() string { return string(e) }

type quickFacts struct {
	Valid       bool
	HasUsername bool
	HasPassword bool
	HasTOTP     bool
	Hidden      bool
}

type quickAccess struct {
	m       *AppModel
	target  QuickTarget
	dismiss func()
	win     *desktop.Window
	// permitted is the platform's fill permission, read once when the panel
	// opens; the target re-checks it before each write.
	permitted bool
	origin    string

	query  *core.Signal[string]
	sel    *base.Selection
	notice *core.Signal[string]
	items  *core.Memo[[]state.CipherSummary]
	facts  *core.Memo[quickFacts]

	listRef core.Ref
	closed  atomic.Bool
}

// QuickAccessView is the native Quick Access panel: a search field over
// login summaries, a keyboard-selected list, and explicit copy/fill
// actions for the selected item. It owns no decrypted cipher: actions
// re-read the item after any reprompt and re-check the lock and access
// immediately before use. dismiss closes the panel; the owner disposes it.
func QuickAccessView(cx *core.Scope, m *AppModel, target QuickTarget, dismiss func()) core.Node {
	cx.SetTheme(GovaultTheme())
	qa := &quickAccess{
		m:         m,
		target:    target,
		dismiss:   dismiss,
		win:       desktop.CurrentWindow(cx),
		permitted: m.QuickAccessPermission == nil || m.QuickAccessPermission(),
		origin:    QuickWebOrigin(target.Origin),
		query:     core.NewSignal(cx, ""),
		sel:       base.NewSelection(cx, false),
		notice:    core.NewSignal(cx, ""),
	}
	qa.items = core.NewMemoFunc(cx, qa.loadItems, nil)
	qa.facts = core.NewMemo(cx, qa.loadFacts)

	cx.Effect(func() {
		list := qa.items.Get()
		if m.LockState.Get() != state.StatusUnlocked {
			return
		}
		cur, _ := qa.sel.Cursor().(string)
		for _, s := range list {
			if s.ID == cur {
				return
			}
		}
		if len(list) == 0 {
			if qa.sel.Len() > 0 {
				qa.sel.Clear()
			}
			return
		}
		qa.sel.Set(list[0].ID)
	})
	cx.Effect(func() {
		if m.LockState.Get() != state.StatusUnlocked {
			qa.notice.Set("")
			qa.cancelReprompt()
		}
	})
	cx.Effect(func() {
		// The panel owns the shared reprompt only while its password dialog
		// is open. Closing it by any path releases the main window's copy.
		if !m.quickReprompt.Get() {
			return
		}
		if !m.Reprompt.Get().Open && !m.RepromptBusy.Get() {
			m.quickReprompt.Set(false)
		}
	})
	cx.Cleanup(func() {
		qa.closed.Store(true)
		qa.cancelReprompt()
	})

	cx.OnKeyWith("escape", core.KeyOptions{When: core.KeyAlways}, qa.escape)
	cx.OnKeyWith("up", core.KeyOptions{When: core.KeyAlways, Repeat: true}, func() { qa.move(-1) })
	cx.OnKeyWith("down", core.KeyOptions{When: core.KeyAlways, Repeat: true}, func() { qa.move(1) })
	cx.OnKeyWith("shift+enter", core.KeyOptions{When: core.KeyAlways}, func() { qa.fillField(QuickPassword) })
	cx.OnKeyWith("mod+1", core.KeyOptions{When: core.KeyAlways}, func() { qa.fillField(QuickUsername) })
	cx.OnKeyWith("mod+2", core.KeyOptions{When: core.KeyAlways}, func() { qa.fillField(QuickPassword) })
	cx.OnKeyWith("mod+3", core.KeyOptions{When: core.KeyAlways}, func() { qa.fillField(QuickTOTP) })

	return core.Dynamic(func(cx *core.Scope) core.Node {
		if m.LockState.Get() != state.StatusUnlocked {
			return quickLockedView()
		}
		return qa.content(cx)
	})
}

func quickLockedView() core.Node {
	return core.View{
		TestID: "quick-locked",
		Class:  "flex-1 flex-col items-center justify-center gap-2 p-8 bg-gv-canvas",
		Children: []core.Node{
			core.Text{Class: "text-[15px] font-semibold text-gv-fg", Content: "GoVault is locked"},
			core.Text{Class: "text-[12px] text-gv-fg2 text-center", Content: "Unlock GoVault to use Quick Access."},
		},
	}
}

func (qa *quickAccess) loadItems() []state.CipherSummary {
	if qa.m.LockState.Get() != state.StatusUnlocked {
		return nil
	}
	qa.m.vaultRev.Get()
	loginType := api.CipherTypeLogin
	list := qa.m.Core.Search(strings.TrimSpace(qa.query.Get()), state.SearchFilter{Category: state.FilterAll, Type: &loginType})
	out := make([]state.CipherSummary, 0, min(len(list), quickMaxRows))
	for _, s := range list {
		if s.Type == api.CipherTypeLogin && !s.Deleted && !s.Archived {
			out = append(out, s)
		}
	}
	out = quickRankByOrigin(out, qa.origin)
	if len(out) > quickMaxRows {
		out = out[:quickMaxRows]
	}
	return out
}

func (qa *quickAccess) loadFacts() quickFacts {
	id, _ := qa.sel.Cursor().(string)
	if id == "" || qa.m.LockState.Get() != state.StatusUnlocked {
		return quickFacts{}
	}
	qa.m.vaultRev.Get()
	c, err := qa.m.Core.GetCipher(id)
	if err != nil || !quickLoginUsable(c) {
		return quickFacts{}
	}
	return quickFacts{
		Valid:       true,
		HasUsername: strings.TrimSpace(c.Login.Username) != "",
		HasPassword: c.Login.Password != "",
		HasTOTP:     strings.TrimSpace(c.Login.TOTP) != "",
		Hidden:      qa.m.PasswordHidden(c),
	}
}

func (qa *quickAccess) content(cx *core.Scope) core.Node {
	return core.View{
		TestID: "quick-access",
		Class:  "flex-1 flex-col gap-2.5 p-3 bg-gv-canvas",
		Children: []core.Node{
			core.View{Class: "flex-col gap-[2px]", Children: []core.Node{
				core.Text{Class: "text-[15px] font-semibold text-gv-fg", Content: "Quick Access"},
				core.Text{TestID: "quick-target", Class: "text-[12px] text-gv-fg2", MaxLines: 2, ContentFunc: qa.targetLine},
			}},
			core.Show{
				When: func() bool { return qa.m.QuickAccessPermission != nil },
				Then: func(cx *core.Scope) core.Node { return quickAccessPermissionRow(cx, qa.m) },
			},
			searchField(cx, base.Input{
				TestID:        "quick-search",
				Placeholder:   locales.SearchVault(cx),
				AutoFocus:     true,
				NoAutoCorrect: true,
				Role:          core.RoleSearchField,
				Value:         qa.query.Get,
				OnChange: func(q string) {
					qa.m.ResetIdleTimer()
					qa.notice.Set("")
					qa.query.Set(q)
				},
				OnSubmit: func(string) { qa.fillLogin() },
			}, "", nil),
			core.Show{
				When: func() bool { return qa.notice.Get() != "" },
				Then: func(*core.Scope) core.Node {
					return core.Text{TestID: "quick-notice", Class: "text-[12px] text-gv-danger", ContentFunc: qa.notice.Get}
				},
			},
			ui.List{
				TestID:    "quick-results",
				Label:     "Quick Access results",
				Ref:       &qa.listRef,
				Count:     func() int { return len(qa.items.Get()) },
				Key:       func(i int) any { return qa.itemAt(i).ID },
				RowLabel:  func(i int) string { s := qa.itemAt(i); return strings.TrimSpace(s.Name + " " + s.Subtitle) },
				Selection: qa.sel,
				OnSelectionChange: func(*ui.Selection) {
					qa.m.ResetIdleTimer()
					qa.notice.Set("")
				},
				OnActivate: func(i int) {
					if i >= 0 && i < len(qa.items.GetUntracked()) {
						qa.sel.Set(qa.itemAt(i).ID)
					}
					qa.fillLogin()
				},
				Row: func(cx *core.Scope, row core.ListRow) core.Node {
					s := qa.itemAt(row.Index())
					return core.View{
						Class: "flex-row items-center gap-2 min-w-0",
						Children: []core.Node{
							core.View{Class: "flex-1 flex-col gap-[2px] min-w-0", Children: []core.Node{
								core.Text{Class: "text-[13px] font-medium text-gv-fg", MaxLines: 1, Content: s.Name},
								core.Show{
									When: func() bool { return s.Subtitle != "" },
									Then: func(*core.Scope) core.Node {
										return core.Text{Class: "text-[11.5px] text-gv-fg2", MaxLines: 1, Content: s.Subtitle}
									},
								},
							}},
							quickMatchBadge(qa.origin, s.URIs),
							core.Show{
								When: func() bool { return s.HasTOTP },
								Then: func(*core.Scope) core.Node {
									return ui.Badge{Text: "TOTP", Variant: ui.BadgeNeutral}
								},
							},
						},
					}
				},
				Empty: core.Text{Class: "p-4 text-center text-[12px] text-gv-fg2", Content: "No logins match."},
				Style: core.Style{FlexGrow: 1, FlexShrink: 1, FlexBasis: core.Pt(0), MinHeight: core.Pt(100)},
			},
			qa.details(cx),
			core.View{Class: "flex-col gap-[2px]", Children: []core.Node{
				core.Text{Class: "text-[11.5px] text-gv-fg3", Content: "↑↓ choose · Enter login · ⇧Enter password"},
				core.Text{Class: "text-[11.5px] text-gv-fg3", Content: "⌘1/2/3 user · password · code · Esc close"},
			}},
			core.Show{
				When: func() bool { return qa.m.quickReprompt.Get() },
				Then: func(*core.Scope) core.Node { return repromptDialog(qa.m) },
			},
		},
	}
}

func (qa *quickAccess) targetLine() string {
	app, window := qa.target.App, qa.target.Window
	if app == "" {
		app = "Unconfirmed app"
	}
	if window == "" {
		window = "Unconfirmed window"
	}
	line := app + " — " + window
	switch {
	case qa.origin != "":
		line += " · " + qa.origin
	case qa.target.Origin != "":
		line += " · origin unavailable"
	default:
		line += " · Native app"
	}
	return line
}

func (qa *quickAccess) itemAt(i int) state.CipherSummary {
	list := qa.items.GetUntracked()
	if i < 0 || i >= len(list) {
		return state.CipherSummary{}
	}
	return list[i]
}

func (qa *quickAccess) selected() *state.CipherSummary {
	list := qa.items.GetUntracked()
	cur, _ := qa.sel.Cursor().(string)
	for i := range list {
		if list[i].ID == cur {
			return &list[i]
		}
	}
	return nil
}

func (qa *quickAccess) details(cx *core.Scope) core.Node {
	return core.Dynamic(func(cx *core.Scope) core.Node {
		s := qa.selected()
		f := qa.facts.Get()
		if s == nil || !f.Valid {
			return core.View{}
		}
		var note string
		switch {
		case !qa.permitted:
			note = "Quick Access needs Accessibility permission to fill. Copy still works."
		case qa.target.Fill == nil:
			note = "Fill is unavailable for this app. Copy still works."
		case f.Hidden:
			note = locales.HiddenByOrganization(cx)
		}
		fill := func(id, label string, field QuickField) core.Node {
			return ui.Button{
				TestID:   id,
				Text:     label,
				Variant:  ui.ButtonSecondary,
				Size:     ui.SizeSmall,
				Disabled: func() bool { return !qa.fillAllowed(f, field) },
				OnPress:  func() { qa.fillField(field) },
			}
		}
		copyBtn := func(id, label string, field QuickField, disabled bool) core.Node {
			return ui.Button{
				TestID:   id,
				Text:     label,
				Variant:  ui.ButtonGhost,
				Size:     ui.SizeSmall,
				Disabled: func() bool { return disabled },
				OnPress:  func() { qa.perform(s.ID, field, true) },
			}
		}
		return core.View{
			TestID: "quick-actions",
			Class:  "flex-col gap-2 p-2.5 rounded-[8px] bg-gv-card border border-gv-line",
			Children: []core.Node{
				core.Text{Class: "text-[13px] font-medium text-gv-fg", MaxLines: 1, Content: s.Name},
				core.Show{
					When: func() bool { return note != "" },
					Then: func(*core.Scope) core.Node {
						return core.Text{TestID: "quick-action-note", Class: "text-[11.5px] text-gv-warn", Content: note}
					},
				},
				core.View{Class: "flex-row flex-wrap gap-1.5", Children: []core.Node{
					fill("quick-fill-login", "Fill login", QuickLogin),
					fill("quick-fill-username", "Fill user", QuickUsername),
					fill("quick-fill-password", "Fill password", QuickPassword),
					fill("quick-fill-totp", "Fill code", QuickTOTP),
				}},
				core.View{Class: "flex-row flex-wrap gap-1.5", Children: []core.Node{
					copyBtn("quick-copy-username", "Copy user", QuickUsername, !f.HasUsername),
					copyBtn("quick-copy-password", "Copy password", QuickPassword, !f.HasPassword || f.Hidden),
					copyBtn("quick-copy-totp", "Copy code", QuickTOTP, !f.HasTOTP),
				}},
			},
		}
	})
}

func (qa *quickAccess) fillAllowed(f quickFacts, field QuickField) bool {
	if !qa.permitted || !f.Valid || qa.target.Fill == nil {
		return false
	}
	switch field {
	case QuickUsername:
		return f.HasUsername
	case QuickPassword:
		return f.HasPassword && !f.Hidden
	case QuickTOTP:
		return f.HasTOTP
	case QuickLogin:
		return f.HasUsername && f.HasPassword && !f.Hidden
	}
	return false
}

// fillField fills one explicit field selected by a button or shortcut.
func (qa *quickAccess) fillField(field QuickField) {
	if !qa.live() {
		return
	}
	qa.m.ResetIdleTimer()
	s := qa.selected()
	if s == nil {
		return
	}
	f := qa.loadFacts()
	if !qa.fillAllowed(f, field) {
		qa.notice.Set(qa.blockedReason(f, field))
		return
	}
	qa.notice.Set("")
	qa.perform(s.ID, field, false)
}

// fillLogin runs Enter: the username/password pair with a Tab, or just the
// password when the item has no username.
func (qa *quickAccess) fillLogin() {
	if !qa.live() {
		return
	}
	qa.m.ResetIdleTimer()
	s := qa.selected()
	if s == nil {
		return
	}
	f := qa.loadFacts()
	switch {
	case qa.fillAllowed(f, QuickLogin):
		qa.notice.Set("")
		qa.perform(s.ID, QuickLogin, false)
	case f.Valid && !f.HasUsername && f.HasPassword && !f.Hidden:
		qa.fillField(QuickPassword)
	default:
		qa.notice.Set(qa.blockedReason(f, QuickLogin))
	}
}

func (qa *quickAccess) blockedReason(f quickFacts, field QuickField) string {
	switch {
	case !f.Valid:
		return "This item is no longer available."
	case !qa.permitted:
		return "Quick Access needs Accessibility permission to fill. Use Copy instead."
	case qa.target.Fill == nil:
		return "Fill is unavailable for this app. Use Copy instead."
	case f.Hidden:
		return "The password is hidden by the organization."
	}
	switch field {
	case QuickUsername:
		return "This item has no username."
	case QuickPassword:
		return "This item has no password."
	case QuickTOTP:
		return "This item has no verification code."
	case QuickLogin:
		switch {
		case !f.HasUsername && !f.HasPassword:
			return "This item has no username or password."
		case !f.HasUsername:
			return "This item has no username."
		default:
			return "This item has no password."
		}
	}
	return "This field is empty."
}

func (qa *quickAccess) move(delta int) {
	if qa.m.LockState.Get() != state.StatusUnlocked {
		return
	}
	list := qa.items.GetUntracked()
	if len(list) == 0 {
		return
	}
	qa.m.ResetIdleTimer()
	cur, _ := qa.sel.Cursor().(string)
	at := -1
	for i := range list {
		if list[i].ID == cur {
			at = i
			break
		}
	}
	switch {
	case at < 0 && delta > 0:
		at = 0
	case at < 0:
		at = len(list) - 1
	default:
		at = min(max(at+delta, 0), len(list)-1)
	}
	qa.sel.Set(list[at].ID)
	qa.listRef.ScrollToIndex(at, true)
	qa.notice.Set("")
}

func (qa *quickAccess) escape() {
	qa.close()
}

func (qa *quickAccess) live() bool {
	if qa.closed.Load() {
		return false
	}
	return qa.win == nil || (!qa.win.Closed() && qa.win.Visible())
}

func (qa *quickAccess) close() {
	if qa.closed.Swap(true) {
		return
	}
	qa.cancelReprompt()
	if qa.dismiss != nil {
		qa.dismiss()
	}
}

func (qa *quickAccess) cancelReprompt() {
	if !qa.m.quickReprompt.Get() {
		return
	}
	if qa.m.Reprompt.Get().Open {
		qa.m.CloseReprompt()
	}
	qa.m.quickReprompt.Set(false)
}

func (qa *quickAccess) perform(id string, field QuickField, copy bool) {
	if !qa.live() || qa.m.LockState.Get() != state.StatusUnlocked || id == "" {
		return
	}
	qa.m.ResetIdleTimer()
	gen := qa.m.LockGeneration()
	c, reason := qa.check(id, field, !copy)
	if reason != "" {
		qa.notice.Set(reason)
		return
	}
	gated := c.Reprompt == 1 && quickGated(field)
	if gated {
		action := RepromptCopyPassword
		if field == QuickTOTP {
			action = RepromptCopyTOTP
		}
		qa.gate(action, func() {
			if copy {
				qa.copyValue(id, field, gen, true)
			} else {
				qa.fillValue(id, field, gen, true)
			}
		})
		return
	}
	if copy {
		qa.copyValue(id, field, gen, false)
	} else {
		qa.fillValue(id, field, gen, false)
	}
}

func (qa *quickAccess) gate(action RepromptAction, allow func()) {
	// Quick Access uses the password dialog, never Touch ID: the panel is
	// non-activating and a system biometric prompt can withdraw it.
	if !qa.live() {
		return
	}
	gen := qa.m.LockGeneration()
	if !qa.m.StillUnlocked(gen) {
		return
	}
	qa.m.Scope.Batch(func() {
		qa.m.quickReprompt.Set(true)
		qa.m.openRepromptDialog(action, func() {
			qa.m.quickReprompt.Set(false)
			if qa.m.StillUnlocked(gen) {
				allow()
			}
		})
	})
}

// check re-reads the record and applies the access and destination rules
// shared by copy and fill. It keeps no cipher after returning.
func (qa *quickAccess) check(id string, field QuickField, fill bool) (*state.Cipher, string) {
	c, err := qa.m.Core.GetCipher(id)
	if err != nil || !quickLoginUsable(c) {
		return nil, "This item is no longer available."
	}
	if (field == QuickPassword || field == QuickLogin) && qa.m.PasswordHidden(c) {
		return nil, "The password is hidden by the organization."
	}
	if fill {
		if reason := qa.fillDenied(c, field); reason != "" {
			return nil, reason
		}
	}
	return c, ""
}

// quickGated reports whether a field's value needs the item's master
// password reprompt.
func quickGated(field QuickField) bool {
	return field == QuickPassword || field == QuickTOTP || field == QuickLogin
}

// currentValue re-reads the item and applies current lock, access,
// reprompt and (for fill) destination rules. It never keeps the cipher.
func (qa *quickAccess) currentValue(id string, field QuickField, fill, gated bool) (string, error) {
	c, reason := qa.check(id, field, fill)
	if reason != "" {
		return "", quickDenied(reason)
	}
	if quickGated(field) && c.Reprompt == 1 && !gated {
		return "", quickDenied("This item now requires verification. Reopen Quick Access.")
	}
	return quickFieldValue(c, field)
}

// currentFill re-reads the item and returns the arguments for Fill. It
// never keeps the cipher.
func (qa *quickAccess) currentFill(id string, field QuickField, gated bool) (string, string, bool, error) {
	c, reason := qa.check(id, field, true)
	if reason != "" {
		return "", "", false, quickDenied(reason)
	}
	if quickGated(field) && c.Reprompt == 1 && !gated {
		return "", "", false, quickDenied("This item now requires verification. Reopen Quick Access.")
	}
	return quickFillArgs(c, field)
}

func (qa *quickAccess) copyValue(id string, field QuickField, gen uint64, gated bool) {
	if !qa.live() || !qa.m.StillUnlocked(gen) {
		return
	}
	value, err := qa.currentValue(id, field, false, gated)
	if err != nil {
		qa.notice.Set(err.Error())
		return
	}
	switch field {
	case QuickUsername:
		qa.m.CopyPlainValue(locales.UsernameCopied(qa.m.Scope), value)
	case QuickPassword:
		qa.m.CopySecretValue(locales.PasswordCopied(qa.m.Scope), value)
	case QuickTOTP:
		qa.m.CopySecretValue(locales.VerificationCodeCopied(qa.m.Scope), value)
	}
	qa.close()
}

func (qa *quickAccess) fillValue(id string, field QuickField, gen uint64, gated bool) {
	ok, err := qa.m.publishIfUnlocked(gen, func() error {
		if !qa.live() {
			return errQuickAccessCanceled
		}
		user, password, tab, err := qa.currentFill(id, field, gated)
		if err != nil {
			return err
		}
		return qa.target.Fill(user, password, tab)
	})
	if err != nil {
		var denied quickDenied
		if errors.Is(err, errQuickAccessCanceled) {
			return
		}
		if errors.As(err, &denied) {
			qa.notice.Set(string(denied))
			return
		}
		// The target returns static, user-safe errors, such as a changed
		// app or a missing permission, so the user can tell them apart.
		if msg := strings.TrimSpace(err.Error()); msg != "" {
			qa.notice.Set(msg)
		} else {
			qa.notice.Set("Couldn't fill the field.")
		}
		return
	}
	if !ok {
		return // a lock won the race; the panel closes with it
	}
	qa.close()
}

// fillDenied re-checks the record and target. It returns "" when the
// field may be filled.
func (qa *quickAccess) fillDenied(c *state.Cipher, field QuickField) string {
	if c == nil || c.Login == nil || c.Type != api.CipherTypeLogin {
		return "This item is not a login."
	}
	if c.DeletedDate != nil || c.ArchivedDate != nil {
		return "This item is no longer available."
	}
	if !qa.permitted {
		return "Quick Access needs Accessibility permission to fill. Use Copy instead."
	}
	if qa.target.Fill == nil {
		return "Fill is unavailable for this app. Use Copy instead."
	}
	switch field {
	case QuickUsername:
		if strings.TrimSpace(c.Login.Username) == "" {
			return "This item has no username."
		}
	case QuickPassword:
		if c.Login.Password == "" {
			return "This item has no password."
		}
	case QuickTOTP:
		if strings.TrimSpace(c.Login.TOTP) == "" {
			return "This item has no verification code."
		}
	case QuickLogin:
		if strings.TrimSpace(c.Login.Username) == "" || c.Login.Password == "" {
			return "This item has no username or password."
		}
	}
	return ""
}

func quickLoginUsable(c *state.Cipher) bool {
	return c != nil && c.Login != nil && c.Type == api.CipherTypeLogin && c.DeletedDate == nil && c.ArchivedDate == nil
}

func quickFieldValue(c *state.Cipher, field QuickField) (string, error) {
	if c == nil || c.Login == nil {
		return "", quickDenied("This item is no longer available.")
	}
	switch field {
	case QuickUsername:
		if strings.TrimSpace(c.Login.Username) == "" {
			return "", quickDenied("This item has no username.")
		}
		return c.Login.Username, nil
	case QuickPassword:
		if c.Login.Password == "" {
			return "", quickDenied("This item has no password.")
		}
		return c.Login.Password, nil
	case QuickTOTP:
		cfg, err := totp.ParseTOTP(c.Login.TOTP)
		if err != nil {
			return "", quickDenied("This verification code is invalid.")
		}
		code, _, _, err := totp.Generate(cfg, time.Now())
		if err != nil || code == "" {
			return "", quickDenied("Couldn't generate a verification code.")
		}
		return code, nil
	}
	return "", quickDenied("This field is empty.")
}

// quickFillArgs maps a field to the target's Fill arguments.
func quickFillArgs(c *state.Cipher, field QuickField) (string, string, bool, error) {
	if field == QuickLogin {
		user, err := quickFieldValue(c, QuickUsername)
		if err != nil {
			return "", "", false, err
		}
		password, err := quickFieldValue(c, QuickPassword)
		if err != nil {
			return "", "", false, err
		}
		return user, password, true, nil
	}
	value, err := quickFieldValue(c, field)
	if err != nil {
		return "", "", false, err
	}
	return value, "", false, nil
}

// QuickWebOrigin is the one HTTPS origin parser the UI and the platform's
// target adapter share. It accepts an absolute HTTPS URL and returns its
// canonical origin, or "" for anything else, so a browser target can fail
// closed. Path, query and fragment are ignored; default port 443 is
// dropped and other ports are kept. Credentials and invalid ports are
// rejected.
func QuickWebOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		if n == 443 {
			port = ""
		}
	} else if strings.HasPrefix(u.Host, "[") {
		if !strings.HasSuffix(u.Host, "]") {
			return ""
		}
	} else if strings.Contains(u.Host, ":") {
		return ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host
}

func quickMatchesOrigin(origin string, uris []string) bool {
	if origin == "" {
		return false
	}
	for _, raw := range uris {
		if got := QuickWebOrigin(raw); got != "" && got == origin {
			return true
		}
	}
	return false
}

func quickLoginURIs(c *state.Cipher) []string {
	if c == nil || c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		// Bitwarden URI match mode 5 is Never; it cannot authorize a fill.
		if u.Match == nil || *u.Match != 5 {
			out = append(out, u.URI)
		}
	}
	return out
}

// quickRankByOrigin keeps the search order within each group and puts
// items whose stored HTTPS origin is the target's first.
func quickRankByOrigin(list []state.CipherSummary, origin string) []state.CipherSummary {
	if origin == "" {
		return list
	}
	exact := make([]state.CipherSummary, 0, len(list))
	rest := make([]state.CipherSummary, 0, len(list))
	for _, s := range list {
		if quickMatchesOrigin(origin, s.URIs) {
			exact = append(exact, s)
		} else {
			rest = append(rest, s)
		}
	}
	return append(exact, rest...)
}

func quickMatchBadge(origin string, uris []string) core.Node {
	if origin == "" || !quickMatchesOrigin(origin, uris) {
		return core.View{}
	}
	return ui.Badge{Text: "This site", Variant: ui.BadgeSuccess}
}
