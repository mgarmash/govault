package main

import (
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/cmd/govault/demo"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func newDemoShell(app *core.Scope) *DesktopShell {
	shell := &DesktopShell{
		scope:     app,
		clipboard: NewClipboardAdapter(app),
	}
	hooks := shell.platformHooks(demo.NewSecretStore())
	hooks.PrefsKey = "govault.demo.prefs"
	hooks.VerifyMasterPassword = func(password []byte) error {
		if len(password) == 0 {
			return state.ErrLocked
		}
		return nil
	}

	shell.model = govaultui.NewAppModel(app, demo.NewService(state.StatusUnlocked), hooks)
	shell.model.UpdatePrefs(func(p govaultui.UserPrefs) govaultui.UserPrefs {
		p.AccountID = demo.AccountID
		p.Email = demo.Email
		p.ServerURL = demo.ServerURL
		p.KDFSummary = demo.KDF
		p.BiometricEnabled = true
		p.AutoPromptBiometric = false
		if p.QuickAccessHotKey == "" {
			p.QuickAccessHotKey = "mod+shift+space"
		}
		return p
	})
	shell.model.LastSync.Set(time.Now().Add(-2 * time.Minute))
	shell.model.LoginServer.Set(demo.ServerURL)
	shell.model.LoginEmail.Set(demo.Email)
	shell.model.RefreshVaultData()
	shell.model.SelectCipher(app, "c-github")
	shell.finishSetup()
	return shell
}
