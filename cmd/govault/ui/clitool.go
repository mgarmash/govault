package ui

import (
	"errors"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/cmd/govault/clitool"
	"github.com/txchen/govault/cmd/govault/locales"
)

// CommandLineTool installs the gv command that the app bundle carries.
type CommandLineTool interface {
	Inspect() clitool.Report
	Apply(action clitool.Action, prompt string) error
}

// RefreshCommandLineTool reads the gv command's state off the UI thread.
func (m *AppModel) RefreshCommandLineTool() {
	tool := m.Hooks.CommandLineTool
	if tool == nil {
		return
	}
	go func() {
		r := tool.Inspect()
		m.Scope.Post(func() { m.CommandLineTool.Set(r) })
	}()
}

// ApplyCommandLineTool runs action, which asks macOS for an administrator
// password, then shows the new state.
func (m *AppModel) ApplyCommandLineTool(action clitool.Action) {
	tool := m.Hooks.CommandLineTool
	if tool == nil || m.CommandLineToolBusy.Get() {
		return
	}
	m.CommandLineToolBusy.Set(true)
	prompt := locales.CommandLineToolPrompt(m.Scope)
	go func() {
		err := tool.Apply(action, prompt)
		r := tool.Inspect()
		m.Scope.Post(func() {
			m.CommandLineToolBusy.Set(false)
			m.CommandLineTool.Set(r)
			switch {
			case err == nil, errors.Is(err, clitool.ErrCancelled):
			case errors.Is(err, clitool.ErrChanged):
				m.ShowToast(ui.ToastError, locales.CommandLineToolFailed(m.Scope), locales.CommandLineToolChanged(m.Scope))
			default:
				m.ShowToast(ui.ToastError, locales.CommandLineToolFailed(m.Scope), m.errorText(err))
			}
		})
	}()
}

func commandLineToolStatus(cx *core.Scope, r clitool.Report) string {
	var s string
	switch r.State {
	case clitool.Unavailable:
		return locales.CommandLineToolUnavailable(cx)
	case clitool.NotInstalled:
		s = locales.CommandLineToolNotInstalled(cx)
	case clitool.Installed:
		s = locales.CommandLineToolInstalled(cx, r.Path)
	case clitool.Homebrew:
		s = locales.CommandLineToolHomebrew(cx, r.Path)
	case clitool.Broken:
		s = locales.CommandLineToolBroken(cx, r.Path)
	case clitool.OtherCopy:
		s = locales.CommandLineToolOtherCopy(cx, r.Path)
	case clitool.Foreign:
		return locales.CommandLineToolForeign(cx, r.Path)
	}
	if r.Untrusted != nil && r.State != clitool.Homebrew {
		s += "\n" + locales.CommandLineToolUntrusted(cx)
	}
	if r.Shadow != "" {
		s += "\n" + locales.CommandLineToolShadowed(cx, r.Shadow)
	} else if r.Later != "" {
		s += "\n" + locales.CommandLineToolOtherOnPath(cx, r.Later)
	}
	return s
}

func commandLineSection(m *AppModel) core.Node {
	m.RefreshCommandLineTool()
	return section(locales.CommandLine(m.Scope), core.Dynamic(func(cx *core.Scope) core.Node {
		r := m.CommandLineTool.Get()
		var buttons []core.Node
		for _, a := range r.Actions() {
			action := a
			b := ui.Button{
				Variant: ui.ButtonSecondary,
				Busy:    func() bool { return m.CommandLineToolBusy.Get() },
				OnPress: func() { m.ApplyCommandLineTool(action) },
			}
			switch action {
			case clitool.Install:
				b.TestID, b.Text = "settings-cli-install", locales.InstallCommandLineTool(cx)
			case clitool.Repair:
				b.TestID, b.Text = "settings-cli-repair", locales.RepairCommandLineTool(cx)
			case clitool.Uninstall:
				b.TestID, b.Text = "settings-cli-uninstall", locales.UninstallCommandLineTool(cx)
			}
			buttons = append(buttons, b)
		}
		return card(settingsRow(
			locales.CommandLineTool(cx),
			commandLineToolStatus(cx, r),
			core.View{Class: "flex-row items-center gap-2", Children: buttons},
		))
	}))
}
