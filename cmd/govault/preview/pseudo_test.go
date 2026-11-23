package preview

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/i18n"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	. "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// dataWords are the words the demo vault holds, which the app shows as
// they are in every language, with the names GoVault never translates.
func dataWords(svc *demo.Service) map[string]bool {
	var values []string
	var collect func(v any)
	collect = func(v any) {
		switch x := v.(type) {
		case string:
			values = append(values, x)
		case []any:
			for _, e := range x {
				collect(e)
			}
		case map[string]any:
			for _, e := range x {
				collect(e)
			}
		}
	}
	for _, part := range []any{svc.AllCiphers(), svc.Folders(), svc.Collections(), svc.Organizations()} {
		data, _ := json.Marshal(part)
		var decoded any
		_ = json.Unmarshal(data, &decoded)
		collect(decoded)
	}
	values = append(values, demo.Email, demo.ServerURL, "GoVault", "Touch ID", "Argon2id", "SSH_AUTH_SOCK", "a***@northwind.dev")
	words := map[string]bool{}
	for _, v := range values {
		for _, w := range wordsOf(v) {
			words[w] = true
		}
	}
	return words
}

func wordsOf(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// technical are texts the same in every language: character ranges,
// example addresses and key formats, and what the test types.
var technical = map[string]bool{
	"A–Z": true, "a–z": true, "https://example.com": true, "https://vault.example.com": true,
	"ssh-ed25519 AAAA…": true, "Ctrl+F": true, "Ctrl+N": true, "Ctrl+L": true, "⌘F": true, "⌘N": true, "⌘L": true, "SHA256:…": true, "-----BEGIN OPENSSH PRIVATE KEY-----": true, "zzzz": true,
}

// untranslated reports whether s, a text the app shows under the pseudo
// locale, is English that no catalog message says: not pseudo-localized,
// which brackets every message, and not the vault's own data.
func untranslated(s string, data map[string]bool) bool {
	s = strings.TrimSpace(s)
	// Monograms and avatars show an item's or account's initials.
	if len([]rune(s)) <= 2 || strings.HasPrefix(s, "[") || !strings.ContainsFunc(s, unicode.IsLetter) || technical[s] {
		return false
	}
	for _, w := range wordsOf(s) {
		if strings.ContainsFunc(w, unicode.IsLetter) && !data[w] {
			return true
		}
	}
	return false
}

// shownTexts are the texts, labels and placeholders under v.
func shownTexts(v *nsgotest.View) []string {
	if v == nil {
		return nil
	}
	out := []string{v.Text, v.Props.Label, v.Props.Hint, v.Input.Placeholder}
	for _, c := range v.Children {
		out = append(out, shownTexts(c)...)
	}
	return out
}

// TestPseudoLocaleShowsNoHardcodedText walks GoVault's screens in the
// en-XA pseudo locale, which shows every catalog message accented and
// bracketed, and fails on any English left outside the catalog. With
// GOVAULT_PSEUDO_DIR set it saves each screen, to check for cut text.
func TestPseudoLocaleShowsNoHardcodedText(t *testing.T) {
	dir := os.Getenv("GOVAULT_PSEUDO_DIR")
	svc := demo.NewService(state.StatusUnlocked)
	data := dataWords(svc)
	var m *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		m = NewAppModel(cx, svc, PlatformHooks{
			Secrets:              demo.NewSecretStore(),
			IsClipboardConcealed: func() bool { return true },
			PrefsKey:             "govault.pseudo.prefs",
		})
		m.UpdatePrefs(func(p UserPrefs) UserPrefs {
			p.AccountID, p.Email, p.ServerURL = demo.AccountID, demo.Email, demo.ServerURL
			kdf := demo.KDF
			p.KDF = &kdf
			p.BiometricEnabled = true
			return p
		})
		m.LastSync.Set(time.Now().Add(-2 * time.Minute))
		m.MainWinVisible.Set(true)
		m.BiometricKind.Set(core.BiometricFingerprint)
		m.RefreshVaultData()
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 720), nsgotest.Environment(core.Environment{Idiom: core.IdiomDesktop, Locale: i18n.PseudoAccents}))

	found := map[string][]string{}
	scene := func(name string, setup func()) {
		t.Helper()
		app.Post(setup)
		app.Settle()
		texts := app.Texts()
		for _, root := range app.Query("id:main-window-root") {
			texts = append(texts, shownTexts(root)...)
		}
		for _, a := range app.Alerts() {
			texts = append(texts, a.Title, a.Message)
			for _, action := range a.Actions {
				texts = append(texts, action.Label)
			}
		}
		for _, s := range texts {
			if s != m.GenResult.Get() && untranslated(s, data) && !slices.Contains(found[s], name) {
				found[s] = append(found[s], name)
			}
		}
		if dir != "" {
			time.Sleep(200 * time.Millisecond)
			app.Settle()
			if err := os.WriteFile(filepath.Join(dir, name+".png"), app.CapturePNG(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	show := func(id string) func() {
		return func() {
			m.LockState.Set(state.StatusUnlocked)
			m.Route.Set(RouteVault)
			m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll})
			m.SelectCipher(m.Scope, id)
		}
	}

	for _, c := range svc.AllCiphers() {
		if c.DeletedDate == nil {
			scene("item-"+c.ID, show(c.ID))
		}
	}
	scene("editor", func() { show("c-github")(); m.StartEditCipher(m.Scope) })
	scene("editor-new", func() { m.CancelEdit(m.Scope); m.StartCreateCipher(m.Scope) })
	for _, typ := range []api.CipherType{api.CipherTypeCard, api.CipherTypeIdentity, api.CipherTypeSSHKey, api.CipherTypeSecureNote} {
		scene("editor-type", func() { m.MutateDraft(func(d *EditDraft) { d.Type = typ }) })
	}
	scene("empty-search", func() {
		m.CancelEdit(m.Scope)
		m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, FolderID: "f-finance"})
		m.SetSearchQuery("zzzz")
	})
	scene("trash", func() {
		m.SetSearchQuery("")
		m.SetSidebarFilter(state.SearchFilter{Category: state.FilterTrash})
	})
	scene("archive", func() { m.SetSidebarFilter(state.SearchFilter{Category: state.FilterArchive}) })
	scene("generator", func() { m.Route.Set(RouteGenerator) })
	scene("copied", func() { m.CopySecretValue("[copied]", m.GenResult.Get()) })
	scene("generator-passphrase", func() {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.GeneratorMode = "passphrase"; return p })
	})
	scene("health", func() { m.Route.Set(RouteHealth) })
	scene("settings", func() { m.Route.Set(RouteSettings) })
	scene("import-empty", func() { m.Route.Set(RouteImport) })
	scene("folder-dialog", func() { m.Route.Set(RouteVault); m.OpenNewFolderModal() })
	scene("delete-folder", func() {
		m.FolderDialog.Set(FolderModal{})
		m.DeleteFolder(m.Scope, svc.Folders()[0])
	})
	scene("logout", func() { m.Logout(m.Scope) })
	scene("reprompt", func() { m.StartExport() })
	scene("backup-dialog", func() { m.CloseReprompt(); m.BackupDialog.Set(BackupExport) })
	scene("lock", func() { m.CloseBackupDialog(); m.Lock() })
	scene("login", func() { m.LockState.Set(state.StatusLoggedOut) })
	scene("twofactor", func() {
		m.TwoFactor.Set(&TwoFactorPrompt{
			Providers: []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail},
			EmailHint: "a***@northwind.dev",
		})
		m.SelectTwoFactorProvider(api.TwoFactorEmail)
	})
	scene("twofactor-yubikey", func() {
		m.TwoFactor.Set(&TwoFactorPrompt{
			Providers: []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail, api.TwoFactorYubiKey},
		})
		m.SelectTwoFactorProvider(api.TwoFactorYubiKey)
		m.VerifyTwoFactor()
	})
	scene("newdevice", func() {
		m.CancelTwoFactor()
		m.NewDevice.Set(&NewDevicePrompt{Email: "alex@northwind.dev"})
	})
	scene("newdevice-no-code", func() { m.VerifyNewDevice() })

	for s, scenes := range found {
		t.Errorf("not in the catalog: %q (on %s)", s, strings.Join(scenes, ", "))
	}
}
