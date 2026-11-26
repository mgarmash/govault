//go:build darwin && !ios

package main

import (
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func startQuickAccess(s *DesktopShell) func() {
	app := s.scope
	var panel *desktop.Window
	var closePanel func()
	open := func() {
		if closePanel != nil {
			closePanel()
			return
		}
		if s.model.LockState.Get() != state.StatusUnlocked {
			s.OpenMainWindow()
			return
		}
		if s.model.Reprompt.Get().Open || s.model.RepromptBusy.Get() {
			s.OpenMainWindow()
			return
		}
		target := captureQuickTarget()
		dismissed := false
		dismiss := func() {
			if dismissed {
				return
			}
			dismissed = true
			w := panel
			panel, closePanel = nil, nil
			w.Close()
		}
		closePanel = dismiss
		panel = desktop.OpenPanel(app, desktop.PanelOptions{Width: 640, Height: 460, HideOnBlur: true}, func(cx *core.Scope) core.Node {
			w := desktop.CurrentWindow(cx)
			cx.Effect(func() {
				if w.Visible() && s.model.LockState.Get() == state.StatusUnlocked {
					return
				}
				// A new surface starts hidden until Show; evaluate after the commit.
				app.Post(func() {
					if !w.Visible() || s.model.LockState.Get() != state.StatusUnlocked {
						dismiss()
					}
				})
			})
			return govaultui.QuickAccessView(cx, s.model, target, dismiss)
		})
		if panel == nil {
			closePanel = nil
			return
		}
		panel.Show()
	}
	m := s.model
	m.QuickAccessPermission = quickAutofillAvailable
	m.QuickAccessRegistration = core.NewSignal[*core.HotKey](app, nil)
	m.RecordQuickAccessHotKey = core.NewSignal(app, false)
	key := core.NewMemo(app, func() string { return m.Prefs.Get().QuickAccessHotKey })
	app.Effect(func() {
		shortcut := key.Get()
		var registration *core.HotKey
		if shortcut != "" && !m.RecordQuickAccessHotKey.Get() {
			registration = desktop.RegisterHotKey(app, shortcut, open)
		}
		m.QuickAccessRegistration.Set(registration)
	})
	return open
}
