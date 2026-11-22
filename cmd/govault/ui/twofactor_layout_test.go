package ui

import (
	"fmt"
	"testing"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/i18n"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// TestTwoFactorMethodPickerFitsTheCard renders the two-step card in every
// catalog language, and the pseudo locale, with each set of methods a
// server can offer, and checks the method picker stays inside the card: a
// segmented control while it fits, else a full-width popup.
func TestTwoFactorMethodPickerFitsTheCard(t *testing.T) {
	sets := [][]api.TwoFactorProvider{
		{api.TwoFactorAuthenticator, api.TwoFactorEmail},
		{api.TwoFactorAuthenticator, api.TwoFactorYubiKey},
		{api.TwoFactorEmail, api.TwoFactorYubiKey},
		{api.TwoFactorAuthenticator, api.TwoFactorEmail, api.TwoFactorYubiKey},
	}
	tags := []string{i18n.PseudoAccents}
	for _, lang := range Languages {
		tags = append(tags, lang.Tag)
	}
	for _, tag := range tags {
		for _, set := range sets {
			t.Run(fmt.Sprintf("%s/%v", tag, set), func(t *testing.T) {
				var m *AppModel
				app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
					m = NewAppModel(cx, newMockVaultService(state.StatusLoggedOut), PlatformHooks{PrefsKey: "govault.twofactor-layout-test"})
					m.MainWinVisible.Set(true)
					m.SetLanguage(tag)
					m.TwoFactor.Set(&TwoFactorPrompt{Providers: set})
					return MainWindowView(cx, m)
				}, nsgotest.Size(980, 720), nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}))

				if w := app.Find("id:twofactor-code").Frame.Size.Width; w != authCardContentWidth {
					t.Fatalf("card content is %v wide, authCardContentWidth says %v", w, authCardContentWidth)
				}
				var labels []string
				for _, p := range set {
					labels = append(labels, twoFactorProviderName(m.Scope, p))
				}
				picker := "id:twofactor-method"
				if app.Exists("id:twofactor-providers") {
					picker = "id:twofactor-providers"
					// The estimate that chose the segmented control is what lays out.
					got := app.Find(picker).Frame.Size.Width
					if want := segmentedWidth(m.Scope, labels); got != want {
						t.Fatalf("segmented control is %v wide, segmentedWidth says %v", got, want)
					}
					for _, p := range set {
						meth, _ := twoFactorMethodOf(p)
						app.Find("id:twofactor-provider-" + meth.id)
					}
				} else {
					// The popup shows the chosen method in full.
					label := twoFactorProviderName(m.Scope, m.TwoFactorProvider.Get())
					text := app.Find("id:twofactor-method >> text:" + label)
					if need := m.Scope.MeasureText(label, core.Font{Size: 13}).Width; float32(text.Frame.Size.Width)+0.5 < need {
						t.Fatalf("popup cuts %q to %v of %v", label, text.Frame.Size.Width, need)
					}
				}
				if !app.Exists("id:twofactor-providers") && len(set) == 2 && segmentedWidth(m.Scope, labels) <= authCardContentWidth {
					t.Fatalf("a popup for %v, whose buttons fit", labels)
				}
				v := app.Find(picker)
				row := v.Parent
				if x, w := v.Frame.Origin.X, v.Frame.Size.Width; x < 0 || x+w > row.Frame.Size.Width || row.Frame.Size.Width > authCardContentWidth {
					t.Fatalf("%s spans %v..%v in a row %v wide (labels %q)", picker, x, x+w, row.Frame.Size.Width, labels)
				}
			})
		}
	}
}

// TestTwoFactorMethodPopupChoosesAMethod: in a language whose buttons do
// not fit, the popup lists the methods and switches between them.
func TestTwoFactorMethodPopupChoosesAMethod(t *testing.T) {
	var m *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, newMockVaultService(state.StatusLoggedOut), PlatformHooks{PrefsKey: "govault.twofactor-popup-test"})
		m.MainWinVisible.Set(true)
		m.SetLanguage("fr")
		m.TwoFactor.Set(&TwoFactorPrompt{Providers: []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail, api.TwoFactorYubiKey}})
		m.TwoFactorProvider.Set(api.TwoFactorYubiKey)
		return MainWindowView(cx, m)
	}, nsgotest.Size(980, 720), nsgotest.Environment(core.Environment{OS: core.OSMacOS, Idiom: core.IdiomDesktop, Locale: "en-US"}))

	if app.Exists("id:twofactor-providers") {
		t.Fatal("segmented control shown where it does not fit")
	}
	app.Press("id:twofactor-method")
	app.Press("id:twofactor-method-1")
	app.WaitUntil(2e9, func() bool { return m.TwoFactorProvider.Get() == api.TwoFactorEmail })
}
