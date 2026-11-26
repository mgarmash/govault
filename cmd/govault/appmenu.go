package main

import (
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/txchen/govault/cmd/govault/locales"
)

// installApplicationMenu sets the menu bar for goos, again in each
// language the app shows as it changes.
func installApplicationMenu(app *core.Scope, goos string, quickAccess func()) {
	app.Effect(func() {
		desktop.SetApplicationMenu(app, applicationMenu(locales.For(app), goos, quickAccess, func() {
			app.OpenPermissionSettings(core.PermissionAccessibility, nil)
		}))
	})
}

// applicationMenu is the menu bar for goos, in the language of msgs.
// On macOS it keeps the standard app, Edit and Window menus and their
// system shortcuts. The edit roles have no handlers of their own, so they go
// down the responder chain exactly as NSGo's default menu does. Elsewhere the
// window draws the menu bar itself; it stays hidden until Alt (see
// OpenMainWindow), so it only offers the app items.
func applicationMenu(msgs locales.Messages, goos string, quickAccess, accessSettings func()) []desktop.MenuItem {
	if goos != "darwin" {
		return []desktop.MenuItem{{Label: "GoVault", Items: []desktop.MenuItem{
			{Role: desktop.MenuQuit},
		}}}
	}
	appItems := []desktop.MenuItem{{Role: desktop.MenuAbout}}
	if quickAccess != nil {
		appItems = append(appItems, desktop.MenuItem{Label: "Quick Access", OnSelect: quickAccess})
		appItems = append(appItems, desktop.MenuItem{Label: "Autofill Accessibility Settings…", OnSelect: accessSettings})
	}
	appItems = append(appItems,
		desktop.MenuItem{Separator: true},
		desktop.MenuItem{Role: desktop.MenuHide},
		desktop.MenuItem{Role: desktop.MenuHideOthers},
		desktop.MenuItem{Role: desktop.MenuShowAll},
		desktop.MenuItem{Separator: true},
		desktop.MenuItem{Role: desktop.MenuQuit},
	)
	return []desktop.MenuItem{
		{Label: "GoVault", Items: appItems},
		{Label: msgs.EditMenu(), Items: []desktop.MenuItem{
			{Role: desktop.MenuUndo},
			{Role: desktop.MenuRedo},
			{Separator: true},
			{Role: desktop.MenuCut},
			{Role: desktop.MenuCopy},
			{Role: desktop.MenuPaste},
			{Role: desktop.MenuSelectAll},
		}},
		{Label: msgs.WindowMenu(), Role: desktop.MenuWindowMenu, Items: []desktop.MenuItem{
			{Role: desktop.MenuMinimize},
			{Role: desktop.MenuZoom},
			{Separator: true},
			{Role: desktop.MenuClose},
		}},
	}
}
