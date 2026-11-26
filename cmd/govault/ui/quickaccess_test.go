package ui

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type quickFillCall struct {
	user, password string
	tab            bool
}

func startQuickPanel(t *testing.T, svc *mockVaultService, target QuickTarget, dismiss func(), prepare func(*AppModel)) *nsgotest.App {
	t.Helper()
	return nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m := NewAppModel(cx, svc, PlatformHooks{
			CopySecret: func(string, time.Duration) (bool, error) { return true, nil },
			CopyPlain:  func(string) {},
		})
		if prepare != nil {
			prepare(m)
		}
		return QuickAccessView(cx, m, target, dismiss)
	}, nsgotest.Size(640, 520))
}

func takeQuickFill(t *testing.T, calls <-chan quickFillCall) quickFillCall {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("the target was not filled")
		return quickFillCall{}
	}
}

func TestQuickWebOriginStrictHTTPS(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"https://github.com", "https://github.com"},
		{"HTTPS://GitHub.com:443/login?x=1#top", "https://github.com"},
		{"https://github.com:8443/login", "https://github.com:8443"},
		{"https://[::1]:8443/login", "https://[::1]:8443"},
		{"http://github.com", ""},
		{"github.com", ""},
		{"https://user@github.com", ""},
		{"https://github.com:bad", ""},
		{"https://github.com:0", ""},
		{"https://", ""},
	}
	for _, c := range cases {
		if got := QuickWebOrigin(c.raw); got != c.want {
			t.Errorf("QuickWebOrigin(%q) = %q, want %q", c.raw, got, c.want)
		}
	}

	origin := QuickWebOrigin("https://github.com/login")
	if origin != "https://github.com" {
		t.Fatalf("origin = %q", origin)
	}
	if !quickMatchesOrigin(origin, []string{"https://GitHub.com:443", "https://github.com.evil"}) {
		t.Fatal("an exact stored HTTPS origin did not match")
	}
	if quickMatchesOrigin(origin, []string{"http://github.com", "https://github.com.evil"}) {
		t.Fatal("a non-HTTPS or lookalike stored URI matched")
	}
	never := 5
	record := &state.Cipher{Login: &state.Login{URIs: []state.LoginURI{{URI: origin, Match: &never}}}}
	if quickMatchesOrigin(origin, quickLoginURIs(record)) {
		t.Fatal("Never match URI matched")
	}

	list := []state.CipherSummary{
		{ID: "other", URIs: []string{"https://other.example"}},
		{ID: "exact", URIs: []string{"https://github.com"}},
	}
	if got := quickRankByOrigin(list, origin); got[0].ID != "exact" {
		t.Fatalf("ranked %q first, want the exact origin", got[0].ID)
	}
}

func TestQuickAccessEnterFillsLoginPair(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var dismissed atomic.Int32
	calls := make(chan quickFillCall, 1)
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(user, password string, tab bool) error {
			calls <- quickFillCall{user: user, password: password, tab: tab}
			return nil
		},
	}
	app := startQuickPanel(t, svc, target, func() { dismissed.Add(1) }, nil)
	app.WaitFor("id:quick-fill-password", 2*time.Second)
	app.Focus("id:quick-search")
	app.Key("enter")

	call := takeQuickFill(t, calls)
	if call.user != "alice@example.com" || call.password != "gh-secret-password" || !call.tab {
		t.Fatal("Enter did not fill the username/password pair with a Tab")
	}
	app.WaitUntil(2*time.Second, func() bool { return dismissed.Load() == 1 })
	select {
	case <-calls:
		t.Fatal("Enter filled the target twice")
	default:
	}
}

func TestQuickAccessShiftEnterFillsPassword(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	calls := make(chan quickFillCall, 1)
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(user, password string, tab bool) error {
			calls <- quickFillCall{user: user, password: password, tab: tab}
			return nil
		},
	}
	app := startQuickPanel(t, svc, target, func() {}, nil)
	app.WaitFor("id:quick-fill-password", 2*time.Second)
	app.Focus("id:quick-search")
	app.Key("shift+enter")

	call := takeQuickFill(t, calls)
	if call.user != "" || call.password != "gh-secret-password" || call.tab {
		t.Fatal("Shift+Enter did not fill only the password")
	}
}

func TestQuickAccessEnterPasswordOnlyWithoutUsername(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Login.Username = ""
	calls := make(chan quickFillCall, 1)
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(user, password string, tab bool) error {
			calls <- quickFillCall{user: user, password: password, tab: tab}
			return nil
		},
	}
	app := startQuickPanel(t, svc, target, func() {}, nil)
	app.WaitFor("id:quick-fill-password", 2*time.Second)
	app.Focus("id:quick-search")
	app.Key("enter")

	call := takeQuickFill(t, calls)
	if call.user != "gh-secret-password" || call.password != "" || call.tab {
		t.Fatal("Enter with no username did not fill only the password")
	}
}

func TestQuickAccessModifiersFillSingleFields(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		check func(quickFillCall) bool
	}{
		{"username", "mod+1", func(c quickFillCall) bool {
			return c.user == "alice@example.com" && c.password == "" && !c.tab
		}},
		{"password", "mod+2", func(c quickFillCall) bool {
			return c.user == "gh-secret-password" && c.password == "" && !c.tab
		}},
		{"totp", "mod+3", func(c quickFillCall) bool {
			digits := c.user != "" && strings.IndexFunc(c.user, func(r rune) bool { return r < '0' || r > '9' }) < 0
			return digits && c.password == "" && !c.tab
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockVaultService(state.StatusUnlocked)
			calls := make(chan quickFillCall, 1)
			target := QuickTarget{
				App: "Safari", Window: "GitHub", Origin: "https://github.com",
				Fill: func(user, password string, tab bool) error {
					calls <- quickFillCall{user: user, password: password, tab: tab}
					return nil
				},
			}
			app := startQuickPanel(t, svc, target, func() {}, nil)
			app.WaitFor("id:quick-fill-password", 2*time.Second)
			app.Focus("id:quick-search")
			app.Key(tc.key)

			if call := takeQuickFill(t, calls); !tc.check(call) {
				t.Fatalf("%s did not fill its single field", tc.name)
			}
		})
	}
}

func TestQuickAccessDeniedFillKeepsCopy(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var dismissed atomic.Int32
	var fills atomic.Int32
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(string, string, bool) error { fills.Add(1); return nil },
	}
	app := startQuickPanel(t, svc, target, func() { dismissed.Add(1) }, func(m *AppModel) {
		m.QuickAccessPermission = func() bool { return false }
	})
	app.WaitFor("id:quick-fill-password", 2*time.Second)
	if !app.Find("id:quick-fill-password").Props.Disabled {
		t.Fatal("fill password is enabled without the platform permission")
	}
	if app.Find("id:quick-copy-password").Props.Disabled {
		t.Fatal("copy password is disabled without the platform permission")
	}
	app.Find("id:quick-accessibility-settings")
	app.Press("id:quick-copy-password")
	app.WaitUntil(2*time.Second, func() bool { return dismissed.Load() == 1 })
	if fills.Load() != 0 {
		t.Fatal("a copy filled the destination")
	}
}

func TestQuickAccessHiddenPasswordOffersNoSecretActions(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].HidePassword = true
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(string, string, bool) error { return nil },
	}
	app := startQuickPanel(t, svc, target, func() {}, nil)
	app.WaitFor("id:quick-fill-password", 2*time.Second)
	if !app.Find("id:quick-fill-password").Props.Disabled {
		t.Fatal("fill password is enabled for a hidden password")
	}
	if !app.Find("id:quick-copy-password").Props.Disabled {
		t.Fatal("copy password is enabled for a hidden password")
	}
	if app.Find("id:quick-copy-username").Props.Disabled {
		t.Fatal("copy username is disabled when only the password is hidden")
	}
	app.Find("id:quick-action-note")
}

func TestQuickAccessShowsDestinationError(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var scope *core.Scope
	var notice *core.Signal[string]
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		scope = cx
		model = NewAppModel(cx, svc, PlatformHooks{})
		return core.Text{Content: "main"}
	}, nsgotest.Size(640, 520))

	app.Post(func() {
		notice = core.NewSignal(scope, "")
		qa := &quickAccess{
			m: model, permitted: true, notice: notice,
			target: QuickTarget{App: "Slack", Window: "#general", Fill: func(string, string, bool) error {
				return errors.New("quick access: target changed")
			}},
		}
		qa.fillValue("c-github", QuickPassword, model.LockGeneration(), true)
	})
	app.Settle()
	if got := notice.Get(); !strings.Contains(got, "target changed") {
		t.Fatalf("notice = %q, want the target's static error", got)
	}
}

func TestQuickAccessFillRechecksLockAndReportsDenial(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var scope *core.Scope
	fills := atomic.Int32{}
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		scope = cx
		model = NewAppModel(cx, svc, PlatformHooks{})
		return core.Text{Content: "main"}
	}, nsgotest.Size(640, 520))

	app.Post(func() {
		qa := &quickAccess{
			m: model, permitted: true,
			target: QuickTarget{App: "Slack", Window: "#general", Fill: func(string, string, bool) error {
				fills.Add(1)
				return nil
			}},
		}
		gen := model.LockGeneration()
		model.RevokePending()
		qa.fillValue("c-github", QuickPassword, gen, true)
	})
	app.Settle()
	if fills.Load() != 0 {
		t.Fatal("fill raced a revoked lock generation")
	}

	var notice *core.Signal[string]
	app.Post(func() {
		notice = core.NewSignal(scope, "")
		qa := &quickAccess{
			m: model, permitted: true, notice: notice,
			target: QuickTarget{App: "Slack", Window: "#general"},
		}
		qa.fillValue("c-github", QuickPassword, model.LockGeneration(), true)
	})
	app.Settle()
	if got := notice.Get(); !strings.Contains(got, "Fill is unavailable") {
		t.Fatalf("denial message = %q, want a user-facing fill denial", got)
	}
}
