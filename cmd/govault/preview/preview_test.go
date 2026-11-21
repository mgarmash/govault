package preview

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/nsgo-dev/nsgo"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/demo"
	. "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestMain(m *testing.M) { nsgotest.Main(m) }

func previewDir(t *testing.T) string {
	dir := os.Getenv("GOVAULT_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set GOVAULT_PREVIEW_DIR to capture UI previews")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func previewModel(cx *core.Scope) *AppModel {
	m := NewAppModel(cx, demo.NewService(state.StatusUnlocked), PlatformHooks{
		Secrets:              demo.NewSecretStore(),
		IsClipboardConcealed: func() bool { return true },
		PrefsKey:             "govault.preview.prefs",
	})
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.AccountID = demo.AccountID
		p.Email = demo.Email
		p.ServerURL = demo.ServerURL
		p.KDFSummary = demo.KDF
		p.BiometricEnabled = true
		p.AutoPromptBiometric = false
		p.QuickAccessHotKey = "mod+shift+space"
		return p
	})
	m.LastSync.Set(time.Now().Add(-2 * time.Minute))
	m.LoginServer.Set(demo.ServerURL)
	m.LoginEmail.Set(demo.Email)
	m.MainWinVisible.Set(true)
	m.RefreshVaultData()
	return m
}

func savePreview(t *testing.T, app *nsgotest.App, dir, name string) {
	app.Settle()
	time.Sleep(300 * time.Millisecond)
	app.Settle()
	if err := os.WriteFile(filepath.Join(dir, name+".png"), app.CapturePNG(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewMainWindow(t *testing.T) {
	dir := previewDir(t)
	var m *AppModel
	var root *core.Scope
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		root = cx
		m = previewModel(cx)
		m.BiometricKind.Set(core.BiometricFingerprint)
		return MainWindowView(cx, m)
	}, nsgotest.Size(1100, 720))

	scene := func(name string, appearance core.Appearance, setup func()) {
		app.Post(func() {
			root.SetAppearance(appearance)
			m.BiometricKind.Set(core.BiometricFingerprint)
			setup()
		})
		app.WaitUntil(3*time.Second, func() bool { return true })
		savePreview(t, app, dir, name)
	}
	selectItem := func(id string) func() {
		return func() {
			m.LockState.Set(state.StatusUnlocked)
			m.Route.Set(RouteVault)
			m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll})
			m.SelectCipher(m.Scope, id)
		}
	}

	scene("01-vault-login-light", core.AppearanceLight, selectItem("c-github"))
	app.WaitUntil(35*time.Second, func() bool { return m.TOTPRemaining.Get() >= 14 })
	savePreview(t, app, dir, "01-vault-login-light")
	scene("02-vault-login-dark", core.AppearanceDark, func() {
		selectItem("c-aws")()
		m.RevealPW.Set(true)
	})
	scene("03-vault-card-light", core.AppearanceLight, selectItem("c-visa"))
	scene("04-vault-identity-dark", core.AppearanceDark, selectItem("c-identity"))
	scene("05-editor-light", core.AppearanceLight, func() {
		selectItem("c-github")()
		m.StartEditCipher(m.Scope)
	})
	scene("06-generator-light", core.AppearanceLight, func() {
		m.CancelEdit(m.Scope)
		m.Route.Set(RouteGenerator)
	})
	scene("07-settings-dark", core.AppearanceDark, func() { m.Route.Set(RouteSettings) })
	scene("08-lock-light", core.AppearanceLight, func() {
		m.Route.Set(RouteVault)
		m.Lock()
	})
	scene("09-lock-dark", core.AppearanceDark, func() {})
	scene("10-login-light", core.AppearanceLight, func() { m.LockState.Set(state.StatusLoggedOut) })
}

func TestPreviewQuickPanel(t *testing.T) {
	dir := previewDir(t)
	var m *AppModel
	var root *core.Scope
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		root = cx
		m = previewModel(cx)
		m.MainWinVisible.Set(false)
		m.QuickPanelVisible.Set(true)
		m.RefreshQuickItems()
		return QuickPanelView(cx, m)
	}, nsgotest.Size(620, 440))

	app.WaitUntil(3*time.Second, func() bool { return m.TOTPCode.Get() != "" || true })
	savePreview(t, app, dir, "11-quick-panel-light")
	app.Post(func() {
		root.SetAppearance(core.AppearanceDark)
		m.QuickSelectedIdx.Set(1)
	})
	savePreview(t, app, dir, "12-quick-panel-dark")
}
