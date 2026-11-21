package main

import (
	"fmt"
	"time"

	"github.com/nsgo-dev/nsgo"
	"github.com/nsgo-dev/nsgo/base"
	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
)

const keychainSpikeAccount = "phase0-spike-probe"

type spikeApp struct {
	scope      *core.Scope
	clipboard  *ConcealedClipboard
	mainWin    *desktop.Window
	quickPanel *desktop.Window

	biometricKind   *core.Signal[string]
	biometricStatus *core.Signal[string]
	keychainStatus  *core.Signal[string]
	clipboardStatus *core.Signal[string]
	quickQuery      *core.Signal[string]
}

func main() {
	nsgo.Run(App, nsgo.WindowSize(640, 480))
}

func App(app *core.Scope) {
	desktop.SetShutdownMode(app, desktop.ShutdownOnExplicit)

	s := &spikeApp{
		scope:           app,
		clipboard:       NewConcealedClipboard(),
		biometricKind:   core.NewSignal(app, "Checking..."),
		biometricStatus: core.NewSignal(app, "Idle"),
		keychainStatus:  core.NewSignal(app, "Idle"),
		clipboardStatus: core.NewSignal(app, "Idle"),
		quickQuery:      core.NewSignal(app, ""),
	}

	app.Cleanup(func() {
		s.clipboard.Cancel()
	})

	s.quickPanel = desktop.OpenPanel(app, desktop.PanelOptions{
		Width:      460,
		Height:     140,
		HideOnBlur: true,
	}, func(cx *core.Scope) core.Node {
		return s.quickPanelView(cx)
	})

	desktop.NewTray(app, desktop.TrayOptions{
		Tooltip: "GoVault (Phase 0 Spike)",
		Width:   28,
		View:    trayIconView,
		Panel:   s.quickPanel,
		Menu: func() []desktop.MenuItem {
			return []desktop.MenuItem{
				{Label: "Open GoVault", OnSelect: s.openMainWindow},
				{Label: "Toggle Quick Access", OnSelect: func() { s.quickPanel.Toggle() }},
				{Separator: true},
				{Label: "Quit GoVault", OnSelect: app.Quit},
			}
		},
	})

	desktop.OnReopen(app, s.openMainWindow)
	s.refreshBiometricAvailability(app)

	if !desktop.LaunchedAtLogin(app) {
		s.openMainWindow()
	}
}

func (s *spikeApp) openMainWindow() {
	s.mainWin = desktop.OpenWindow(s.scope, desktop.WindowOptions{
		Title:  "GoVault — Phase 0 Spike",
		Key:    "main",
		Width:  640,
		Height: 480,
		Constraints: desktop.WindowConstraints{
			MinWidth:  480,
			MinHeight: 360,
		},
	}, func(cx *core.Scope) core.Node {
		return s.mainWindowView(cx)
	})
	desktop.SetMainWindow(s.scope, s.mainWin)
}

func (s *spikeApp) refreshBiometricAvailability(cx *core.Scope) {
	cx.BiometricAvailability(func(kind core.BiometricKind) {
		s.biometricKind.Set(formatBiometricKind(kind))
	})
}

func (s *spikeApp) testBiometricPrompt(cx *core.Scope) {
	s.biometricStatus.Set("Prompting...")
	cx.AuthenticateBiometric("Verify Touch ID for GoVault Phase 0 spike", func(res core.BiometricResult) {
		s.biometricStatus.Set(formatBiometricResult(res))
	})
}

func (s *spikeApp) testKeychainRoundTrip(cx *core.Scope) {
	s.keychainStatus.Set("Running...")
	secrets := cx.Secrets()
	probeValue := fmt.Sprintf("govault-probe-%d", time.Now().UnixNano())

	go func() {
		status := runKeychainProbe(secrets, probeValue)
		cx.Post(func() {
			s.keychainStatus.Set(status)
		})
	}()
}

func runKeychainProbe(secrets core.Secrets, probeValue string) string {
	if err := secrets.Set(keychainSpikeAccount, probeValue); err != nil {
		return "Set failed: " + err.Error()
	}
	got, ok, err := secrets.Get(keychainSpikeAccount)
	if err != nil {
		_ = secrets.Delete(keychainSpikeAccount)
		return "Get failed: " + err.Error()
	}
	if err := secrets.Delete(keychainSpikeAccount); err != nil {
		return "Delete failed: " + err.Error()
	}
	if !ok || got != probeValue {
		return "Mismatch on readback"
	}
	return "OK (Set/Get/Delete verified)"
}

func (s *spikeApp) copyConcealedSecret() {
	changeCount, err := s.clipboard.Copy("govault-phase0-spike-secret", 5*time.Second)
	if err != nil {
		s.clipboardStatus.Set("Error: " + err.Error())
		return
	}
	s.clipboardStatus.Set(fmt.Sprintf("Copied concealed (changeCount=%d, auto-clear 5s)", changeCount))
}

func (s *spikeApp) mainWindowView(cx *core.Scope) core.Node {
	win := desktop.CurrentWindow(cx)
	return core.View{
		Class: "flex-1 p-6 gap-4 bg-white dark:bg-neutral-900",
		Children: []core.Node{
			core.Text{
				Class:   "text-xl font-semibold text-neutral-900 dark:text-white",
				Content: "GoVault — Phase 0 macOS NSGo Spike",
			},
			statusRow("Biometric Availability", s.biometricKind),
			statusRow("Biometric Prompt", s.biometricStatus),
			statusRow("Keychain (core.Secrets)", s.keychainStatus),
			statusRow("Concealed Clipboard", s.clipboardStatus),
			core.View{
				Class: "flex-row flex-wrap gap-2 pt-2",
				Children: []core.Node{
					ui.Button{
						Text:    "Refresh Biometric",
						Variant: ui.ButtonSecondary,
						OnPress: func() { s.refreshBiometricAvailability(cx) },
					},
					ui.Button{
						Text:    "Test Touch ID",
						Variant: ui.ButtonPrimary,
						OnPress: func() { s.testBiometricPrompt(cx) },
					},
					ui.Button{
						Text:    "Test Keychain",
						Variant: ui.ButtonSecondary,
						OnPress: func() { s.testKeychainRoundTrip(cx) },
					},
					ui.Button{
						Text:    "Copy Concealed (5s)",
						Variant: ui.ButtonSecondary,
						OnPress: s.copyConcealedSecret,
					},
					ui.Button{
						Text:    "Toggle Quick Panel",
						Variant: ui.ButtonOutline,
						OnPress: func() { s.quickPanel.Toggle() },
					},
					ui.Button{
						Text:    "Hide to Tray",
						Variant: ui.ButtonGhost,
						OnPress: func() { win.Close() },
					},
				},
			},
		},
	}
}

func (s *spikeApp) quickPanelView(cx *core.Scope) core.Node {
	win := desktop.CurrentWindow(cx)
	return core.View{
		Class: "flex-1 p-4 gap-3 bg-white dark:bg-neutral-900",
		Children: []core.Node{
			core.Text{
				Class:   "text-xs font-semibold text-neutral-500 dark:text-neutral-400",
				Content: "GoVault Quick Access (Phase 0 Spike)",
			},
			base.Input{
				Class:       "px-3 py-2 rounded-md border border-neutral-300 dark:border-neutral-700 text-sm text-neutral-900 dark:text-white",
				AutoFocus:   true,
				Placeholder: "Type query and press Enter to copy concealed secret...",
				Value:       s.quickQuery.Get,
				OnChange:    s.quickQuery.Set,
				OnSubmit: func(string) {
					s.copyConcealedSecret()
					win.Hide()
				},
			},
			core.View{
				Class: "flex-row gap-2",
				Children: []core.Node{
					ui.Button{
						Text:    "Copy Concealed",
						Variant: ui.ButtonPrimary,
						OnPress: func() {
							s.copyConcealedSecret()
							win.Hide()
						},
					},
					ui.Button{
						Text:    "Open Main Window",
						Variant: ui.ButtonSecondary,
						OnPress: func() {
							win.Hide()
							s.openMainWindow()
						},
					},
				},
			},
		},
	}
}

func trayIconView(cx *core.Scope) core.Node {
	return core.View{
		Class: "flex-row items-center justify-center h-full",
		Children: []core.Node{
			core.Icon{
				SVG: lucide.Lock(),
				StyleFunc: func() core.Style {
					c := core.RGB(0x000000)
					if cx.Dark() {
						c = core.RGB(0xffffff)
					}
					return core.Style{Width: core.Pt(15), Height: core.Pt(15), Color: c}
				},
			},
		},
	}
}

func statusRow(label string, sig *core.Signal[string]) core.Node {
	return core.View{
		Class: "flex-row items-center justify-between py-1 border-b border-neutral-200 dark:border-neutral-800",
		Children: []core.Node{
			core.Text{
				Class:   "text-sm font-medium text-neutral-700 dark:text-neutral-300",
				Content: label,
			},
			core.Text{
				Class:       "text-sm text-neutral-900 dark:text-white",
				ContentFunc: sig.Get,
			},
		},
	}
}

func formatBiometricKind(kind core.BiometricKind) string {
	switch kind {
	case core.BiometricFingerprint:
		return "Touch ID (BiometricFingerprint)"
	case core.BiometricFace:
		return "Face ID (BiometricFace)"
	default:
		return "None (BiometricNone)"
	}
}

func formatBiometricResult(res core.BiometricResult) string {
	switch res {
	case core.BiometricSuccess:
		return "Success"
	case core.BiometricCancelled:
		return "Cancelled"
	case core.BiometricUnavailable:
		return "Unavailable"
	default:
		return "Failure"
	}
}
