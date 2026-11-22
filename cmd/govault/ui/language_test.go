package ui

import (
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/i18n"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/locales"
	"github.com/txchen/govault/internal/vaultcore/state"
)

const languageTestPrefsKey = "govault.language-test"

func startInLocale(t *testing.T, systemLocale string, opts ...nsgotest.Option) (*nsgotest.App, *AppModel) {
	t.Helper()
	var m *AppModel
	opts = append(opts, nsgotest.Size(1100, 720), nsgotest.Environment(core.Environment{Idiom: core.IdiomDesktop, Locale: systemLocale}))
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, newMockVaultService(state.StatusUnlocked), PlatformHooks{PrefsKey: languageTestPrefsKey})
		m.MainWinVisible.Set(true)
		m.RefreshVaultData()
		return MainWindowView(cx, m)
	}, opts...)
	return app, m
}

// shows waits until the sidebar and toolbar say their words in msgs: one
// a text built once, the other one that follows its signals.
func shows(t *testing.T, app *nsgotest.App, msgs locales.Messages) {
	t.Helper()
	app.WaitUntil(2*time.Second, func() bool {
		title := app.Query("id:toolbar-title")
		return app.Exists("id:sidebar-favorites >> text:"+msgs.Favorites()) && len(title) == 1 && title[0].Text == msgs.AllItems()
	})
}

func TestLanguageFollowsTheSystemAndSwitchesLive(t *testing.T) {
	app, m := startInLocale(t, i18n.PseudoAccents)
	pseudo, english := locales.In(i18n.PseudoAccents), locales.In("en")
	shows(t, app, pseudo)

	app.Post(func() { m.SetLanguage("en") })
	shows(t, app, english)
	if got := m.Prefs.Get().Language; got != "en" {
		t.Fatalf("saved language = %q, want en", got)
	}

	app.Post(func() { m.Route.Set(RouteSettings) })
	app.WaitFor("id:settings-language", 2*time.Second)
	app.Post(func() { m.SetLanguage("") })
	app.WaitUntil(2*time.Second, func() bool {
		title := app.Query("id:toolbar-title")
		return len(title) == 1 && title[0].Text == pseudo.Settings() && app.Exists("id:settings-view >> text:"+pseudo.Language())
	})
	app.Post(func() { m.Route.Set(RouteVault) })
	shows(t, app, pseudo)
	if got := m.Prefs.Get().Language; got != "" {
		t.Fatalf("saved language = %q, want the system's", got)
	}
}

func TestUnsupportedSystemLanguageShowsEnglish(t *testing.T) {
	app, _ := startInLocale(t, "sw-KE")
	shows(t, app, locales.In("en"))
}

func TestChosenLanguageIsKeptForTheNextLaunch(t *testing.T) {
	app, m := startInLocale(t, "en-US")
	shows(t, app, locales.In("en"))
	app.Post(func() { m.SetLanguage(i18n.PseudoAccents) })
	shows(t, app, locales.In(i18n.PseudoAccents))
	saved, ok := app.Storage().GetItem(languageTestPrefsKey)
	if !ok {
		t.Fatal("the language choice was not saved")
	}

	next, _ := startInLocale(t, "en-US", nsgotest.Storage(map[string]string{languageTestPrefsKey: saved}))
	shows(t, next, locales.In(i18n.PseudoAccents))
}

func TestLanguagesAreNamedInThemselves(t *testing.T) {
	want := map[string]string{"en": "English", "zh-Hans": "简体中文", "zh-Hant": "繁體中文", "ja": "日本語", "ko": "한국어",
		"de": "Deutsch", "fr": "Français", "es": "Español", "pt-BR": "Português (Brasil)", "ru": "Русский"}
	if len(Languages) != len(want) {
		t.Fatalf("Languages = %v", Languages)
	}
	for _, l := range Languages {
		if want[l.Tag] != l.Name {
			t.Errorf("%s is named %q, want %q", l.Tag, l.Name, want[l.Tag])
		}
	}
}
