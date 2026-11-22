package ui

import (
	"sync"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/cmd/govault/clitool"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type fakeCLITool struct {
	mu      sync.Mutex
	report  clitool.Report
	applied []clitool.Action
}

func (f *fakeCLITool) Inspect() clitool.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.report
}

func (f *fakeCLITool) Apply(a clitool.Action, prompt string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, a)
	if a == clitool.Install {
		f.report = clitool.Report{State: clitool.Installed, Path: clitool.LinkPath}
	}
	return nil
}

func (f *fakeCLITool) actions() []clitool.Action {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]clitool.Action(nil), f.applied...)
}

func TestSettingsInstallsTheCommandLineTool(t *testing.T) {
	tool := &fakeCLITool{report: clitool.Report{State: clitool.NotInstalled}}
	var model *AppModel
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, newMockVaultService(state.StatusUnlocked), PlatformHooks{CommandLineTool: tool})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 760))
	app.Post(func() { model.Route.Set(RouteSettings) })
	app.WaitFor("id:settings-cli-install", 2*time.Second)
	app.Press("id:settings-cli-install")
	app.WaitFor("id:settings-cli-uninstall", 2*time.Second)
	if got := tool.actions(); len(got) != 1 || got[0] != clitool.Install {
		t.Fatalf("applied %v, want one install", got)
	}
}
