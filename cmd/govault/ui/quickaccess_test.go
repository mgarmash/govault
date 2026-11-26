package ui

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

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
		t.Fatal("Never match URI authorized a fill")
	}

	list := []state.CipherSummary{
		{ID: "other", URIs: []string{"https://other.example"}},
		{ID: "exact", URIs: []string{"https://github.com"}},
	}
	if got := quickRankByOrigin(list, origin); got[0].ID != "exact" {
		t.Fatalf("ranked %q first, want the exact origin", got[0].ID)
	}
}

func TestQuickAccessWrongOriginKeepsCopyOnly(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var fills, dismissed atomic.Int32
	target := QuickTarget{
		App: "Safari", Window: "Evil", Origin: "https://evil.example",
		Fill: func(QuickField, string) error { fills.Add(1); return nil },
	}
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		hooks := PlatformHooks{
			CopySecret: func(string, time.Duration) (bool, error) { return true, nil },
			CopyPlain:  func(string) {},
		}
		return QuickAccessView(cx, NewAppModel(cx, svc, hooks), target, func() { dismissed.Add(1) })
	}, nsgotest.Size(640, 520))

	app.WaitFor("id:quick-fill-password", 2*time.Second)
	if !strings.Contains(app.Find("id:quick-target").Text, "https://evil.example") {
		t.Fatalf("target line %q does not show the origin", app.Find("id:quick-target").Text)
	}
	if !app.Find("id:quick-fill-password").Props.Disabled {
		t.Fatal("fill password is enabled for a non-matching origin")
	}
	if app.Find("id:quick-copy-password").Props.Disabled {
		t.Fatal("copy password is disabled for a non-matching origin")
	}
	app.Press("id:quick-copy-password")
	app.WaitUntil(2*time.Second, func() bool { return dismissed.Load() == 1 })
	if fills.Load() != 0 {
		t.Fatal("a copy filled the destination")
	}
}

func TestQuickAccessNativeFillConfirmsFirst(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var dismissed atomic.Int32
	filled := make(chan QuickField, 1)
	value := make(chan string, 1)
	target := QuickTarget{
		App: "Slack", Window: "#general",
		Fill: func(f QuickField, v string) error { filled <- f; value <- v; return nil },
	}
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		return QuickAccessView(cx, NewAppModel(cx, svc, PlatformHooks{}), target, func() { dismissed.Add(1) })
	}, nsgotest.Size(640, 520))

	app.Press("id:quick-fill-password")
	app.WaitFor("id:quick-fill-confirm", 2*time.Second)
	select {
	case <-filled:
		t.Fatal("native fill happened before confirmation")
	default:
	}
	app.Press("id:quick-fill-confirm-action")
	app.WaitUntil(2*time.Second, func() bool { return dismissed.Load() == 1 })
	if f := <-filled; f != QuickPassword {
		t.Fatalf("filled %v, want password", f)
	}
	if v := <-value; v != "gh-secret-password" {
		t.Fatalf("filled %q", v)
	}
}

func TestQuickAccessHiddenPasswordOffersNoSecretActions(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].HidePassword = true
	target := QuickTarget{
		App: "Safari", Window: "GitHub", Origin: "https://github.com",
		Fill: func(QuickField, string) error { return nil },
	}
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		return QuickAccessView(cx, NewAppModel(cx, svc, PlatformHooks{}), target, func() {})
	}, nsgotest.Size(640, 520))

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

func TestQuickAccessFieldHintAndMalformedOrigin(t *testing.T) {
	qa := &quickAccess{
		native: false, origin: "https://github.com", originOK: true,
		target: QuickTarget{
			App: "Safari", Window: "GitHub",
			Fill:    func(QuickField, string) error { return nil },
			CanFill: func(f QuickField) bool { return f == QuickUsername },
		},
	}
	f := quickFacts{Valid: true, HasUsername: true, HasPassword: true, HasTOTP: true, OriginOK: true}
	if qa.fillAllowed(f, QuickPassword) || qa.fillAllowed(f, QuickTOTP) {
		t.Fatal("a field the adapter refuses is offered")
	}
	if !qa.fillAllowed(f, QuickUsername) {
		t.Fatal("the adapter's allowed field is not offered")
	}
	qa.originOK = false // a malformed adapter origin
	if qa.fillAllowed(f, QuickUsername) {
		t.Fatal("fill is offered with a malformed origin")
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
			m: model, native: true, originOK: true,
			target: QuickTarget{App: "Slack", Window: "#general", Fill: func(QuickField, string) error { fills.Add(1); return nil }},
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
			m: model, native: true, originOK: true, notice: notice,
			target: QuickTarget{App: "Slack", Window: "#general"},
		}
		qa.fillValue("c-github", QuickPassword, model.LockGeneration(), true)
	})
	app.Settle()
	if got := notice.Get(); !strings.Contains(got, "Fill is unavailable") {
		t.Fatalf("denial message = %q, want a user-facing fill denial", got)
	}
}
