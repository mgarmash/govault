package ui

import (
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
)

const defaultQuickAccessHotKey = "ctrl+shift+space"

var quickAccessKeyLabel = strings.NewReplacer("ctrl+", "⌃", "alt+", "⌥", "shift+", "⇧", "meta+", "⌘", "space", "Space")

func quickAccessSettings(cx *core.Scope, m *AppModel) core.Node {
	recording := m.RecordQuickAccessHotKey
	var recorder core.Ref
	cx.Cleanup(func() { recording.Set(false) })

	set := func(key string) {
		m.UpdatePrefs(func(p UserPrefs) UserPrefs { p.QuickAccessHotKey = key; return p })
		recording.Set(false)
	}
	label := func() string {
		if recording.Get() {
			return "Press a shortcut…"
		}
		key := m.Prefs.Get().QuickAccessHotKey
		if key == "" {
			return "Set shortcut…"
		}
		return quickAccessKeyLabel.Replace(key)
	}
	status := func() string {
		if recording.Get() {
			return "Use modifiers and a key. Esc cancels."
		}
		if m.Prefs.Get().QuickAccessHotKey == "" {
			return "Off"
		}
		switch m.QuickAccessRegistration.Get().State() {
		case core.HotKeyRegistered:
			return "Active"
		case core.HotKeyTaken:
			return "In use — choose another shortcut"
		case core.HotKeyUnsupported:
			return "Unavailable — choose another shortcut"
		default:
			return "Registering…"
		}
	}
	return section("Quick Access", card(
		settingsRow("Hot Key", "Open Quick Access from any app.", core.View{
			Ref: &recorder, TestID: "settings-quick-hotkey", Role: core.RoleButton,
			Class:     "px-3 py-1.5 rounded-[6px] border border-gv-line bg-gv-card",
			LabelFunc: label,
			OnPress: func(core.PressEvent) {
				recording.Set(true)
				recorder.Focus()
			},
			OnBlur: func() { recording.Set(false) },
			OnKeyDown: func(e core.KeyEvent) bool {
				if !recording.Get() || e.Key == "tab" {
					return false
				}
				if e.Repeat {
					return true
				}
				if e.Key == "escape" {
					recording.Set(false)
					return true
				}
				key := e.Shortcut()
				if strings.Contains(key, "+") && (e.Modifiers.Control || e.Modifiers.Alt || e.Modifiers.Platform) {
					set(key)
				}
				return true
			},
			Children: []core.Node{core.Text{Class: "text-[12px] text-gv-fg", ContentFunc: label}},
		}),
		settingsMetaRow("Registration", status),
		core.View{Class: "flex-row justify-end gap-2 px-4 py-2", Children: []core.Node{
			ui.Button{TestID: "settings-quick-hotkey-off", Text: "Turn off", Variant: ui.ButtonGhost,
				Disabled: func() bool { return m.Prefs.Get().QuickAccessHotKey == "" }, OnPress: func() { set("") }},
			ui.Button{TestID: "settings-quick-hotkey-reset", Text: "Restore default", Variant: ui.ButtonSecondary,
				Disabled: func() bool { return m.Prefs.Get().QuickAccessHotKey == defaultQuickAccessHotKey },
				OnPress:  func() { set(defaultQuickAccessHotKey) }},
		}},
		quickAccessPermissionRow(cx, m),
	))
}

func quickAccessPermissionRow(cx *core.Scope, m *AppModel) core.Node {
	if m.QuickAccessPermission == nil {
		return nil
	}
	allowed := core.NewSignal(cx, m.QuickAccessPermission())
	cx.Effect(func() {
		_ = cx.Env().Lifecycle()
		allowed.Set(m.QuickAccessPermission())
	})
	return core.Dynamic(func(cx *core.Scope) core.Node {
		if allowed.Get() {
			return settingsMetaRow("Autofill · Accessibility", func() string { return "Allowed" })
		}
		return settingsRow("Autofill · Accessibility", "Allow GoVault in macOS to type into other apps. Copy works without it.", ui.Button{
			TestID: "quick-accessibility-settings", Text: "Open macOS Settings…", Variant: ui.ButtonSecondary,
			OnPress: func() {
				cx.OpenPermissionSettings(core.PermissionAccessibility, nil)
			},
		})
	})
}
