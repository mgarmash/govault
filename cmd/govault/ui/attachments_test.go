package ui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestAttachmentsCardUploadDownloadDelete(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].Attachments = []state.Attachment{{ID: "att-1", FileName: "codes.txt", Size: 2048}}

	dir := t.TempDir()
	upload := filepath.Join(dir, "invoice.pdf")
	if err := os.WriteFile(upload, []byte("%PDF-1.7"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(dir, "saved.txt")

	var model *AppModel
	var root *core.Scope
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		root = cx
		model = NewAppModel(cx, svc, PlatformHooks{
			ChooseSavePath: func(_ string, done func(string, bool, error)) { done(saved, true, nil) },
		})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 900))
	app.PickFiles = func(core.FilesRequest) []core.File {
		return []core.File{{Name: "invoice.pdf", Size: 8, Path: upload}}
	}
	app.OnAlert = func(core.AlertConfig) int { return 1 }

	app.Post(func() { model.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-view >> text:codes.txt", 2*time.Second)
	app.Find("id:detail-view >> text:2.0 KB")

	app.Press("id:detail-attachment-download-0")
	app.WaitUntil(2*time.Second, func() bool {
		data, err := os.ReadFile(saved)
		fi, statErr := os.Stat(saved)
		return err == nil && string(data) == "contents of codes.txt" && statErr == nil && fi.Mode().Perm() == 0o600
	})

	app.Press("id:detail-attach-file")
	app.WaitFor("id:detail-view >> text:invoice.pdf", 2*time.Second)

	app.Press("id:detail-attachment-delete-0")
	app.WaitForGone("id:detail-view >> text:codes.txt", 2*time.Second)
	app.Find("id:detail-view >> text:invoice.pdf")
}
