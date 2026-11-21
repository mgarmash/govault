package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
)

const attachmentUploadBusy = "upload"

func (m *AppModel) CanModifyAttachments(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && !m.CipherReadOnly(c) && !m.PasswordHidden(c) && m.SyncState.Get() != SyncOffline
}

func (m *AppModel) applyCipherUpdate(c *state.Cipher) {
	m.RefreshVaultData()
	if c != nil && m.SelectedID.Get() == c.ID {
		m.ActiveCipher.Set(c)
	}
}

func (m *AppModel) CanDownloadAttachments(c *state.Cipher) bool {
	return c != nil && !m.PasswordHidden(c)
}

// DownloadAttachment decrypts the attachment and writes it where the user
// chooses. The destination is only replaced, atomically, once the plaintext
// sits in a private 0600 temporary file beside it and the vault is still
// unlocked; a failed or revoked save leaves an existing file untouched.
func (m *AppModel) DownloadAttachment(cx *core.Scope, c *state.Cipher, att state.Attachment) {
	if !m.CanDownloadAttachments(c) || m.AttachmentBusy.Get() != "" {
		return
	}
	m.GateReprompt(cx, c, "download attachment", func() {
		m.ResetIdleTimer()
		m.AttachmentBusy.Set(att.ID)
		gen := m.LockGeneration()
		cipherID := c.ID
		go func() {
			data, name, err := m.Core.DownloadAttachment(context.Background(), cipherID, att.ID)
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					return
				}
				m.AttachmentBusy.Set("")
				if err != nil {
					m.ShowToast(ui.ToastError, "Download failed", friendlyError(err))
					return
				}
				if name == "" {
					name = att.FileName
				}
				m.chooseSavePath(cx, name, func(path string, err error) {
					if err != nil || path == "" || !m.StillUnlocked(gen) {
						crypto.ZeroBytes(data)
						if err != nil {
							m.ShowToast(ui.ToastError, "Save failed", err.Error())
						}
						return
					}
					go func() {
						published, err := m.savePrivateFile(gen, path, data)
						m.Scope.Post(func() {
							switch {
							case err != nil:
								m.ShowToast(ui.ToastError, "Save failed", err.Error())
							case published:
								m.ShowToast(ui.ToastSuccess, "Attachment saved", filepath.Base(path))
							}
						})
					}()
				})
			})
		}()
	})
}

// chooseSavePath reports a destination on the engine goroutine, or "" when
// the user cancelled. Without a native path-only dialog it asks for a folder
// and picks a file name there that does not exist yet.
func (m *AppModel) chooseSavePath(cx *core.Scope, name string, done func(path string, err error)) {
	name = filepath.Base(filepath.Clean("/" + name))
	if name == "/" || name == "." {
		name = "attachment"
	}
	if choose := m.Hooks.ChooseSavePath; choose != nil {
		choose(name, func(path string, ok bool, err error) {
			m.Scope.Post(func() {
				if !ok {
					path = ""
				}
				done(path, err)
			})
		})
		return
	}
	cx.PickDirectories(core.PickDirectoriesOptions{Title: "Save Attachment", Button: "Save Here"}, func(dirs []core.Directory, err error) {
		if err != nil || len(dirs) == 0 || dirs[0].Path == "" {
			done("", err)
			return
		}
		done(unusedPath(dirs[0].Path, name), nil)
	})
}

func unusedPath(dir, name string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	path := filepath.Join(dir, name)
	for i := 2; ; i++ {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return path
		}
		path = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
	}
}

// savePrivateFile writes data to a 0600 temporary file beside path, syncs it,
// and renames it over path only if gen is still current. data is zeroed.
func (m *AppModel) savePrivateFile(gen uint64, path string, data []byte) (bool, error) {
	defer crypto.ZeroBytes(data)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	err = tmp.Chmod(0o600)
	if err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	published := false
	if err == nil {
		published, err = m.publishIfUnlocked(gen, func() error { return os.Rename(name, path) })
	}
	if !published {
		_ = os.Remove(name)
	}
	return published, err
}

func (m *AppModel) AttachFile(cx *core.Scope, c *state.Cipher) {
	if !m.CanModifyAttachments(c) || m.AttachmentBusy.Get() != "" {
		return
	}
	m.ResetIdleTimer()
	cipherID := c.ID
	cx.PickFiles(core.PickFilesOptions{Title: "Attach File", Button: "Attach"}, func(files []core.File, err error) {
		if err != nil {
			m.ShowToast(ui.ToastError, "Could not open file", err.Error())
			return
		}
		if len(files) == 0 {
			return
		}
		f := files[0]
		if f.Size > api.MaxAttachmentSize {
			m.ShowToast(ui.ToastError, "File too large", "Attachments are limited to 100 MiB.")
			return
		}
		m.AttachmentBusy.Set(attachmentUploadBusy)
		gen := m.LockGeneration()
		go func() {
			updated, err := uploadPickedFile(m.Core, cipherID, f)
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					return
				}
				m.AttachmentBusy.Set("")
				if err != nil {
					m.ShowToast(ui.ToastError, "Upload failed", friendlyError(err))
					return
				}
				m.applyCipherUpdate(updated)
				m.ShowToast(ui.ToastSuccess, "File attached", f.Name)
			})
		}()
	})
}

func uploadPickedFile(svc state.VaultService, cipherID string, f core.File) (*state.Cipher, error) {
	if f.Temporary && f.Path != "" {
		defer os.Remove(f.Path)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(rc, api.MaxAttachmentSize+1))
	_ = rc.Close()
	defer crypto.ZeroBytes(data)
	if err != nil {
		return nil, err
	}
	if len(data) > api.MaxAttachmentSize {
		return nil, api.ErrAttachmentTooLarge
	}
	return svc.UploadAttachment(context.Background(), cipherID, f.Name, data)
}

func (m *AppModel) DeleteAttachment(cx *core.Scope, c *state.Cipher, att state.Attachment) {
	if !m.CanModifyAttachments(c) || m.AttachmentBusy.Get() != "" {
		return
	}
	cipherID := c.ID
	cx.ShowAlert(core.AlertConfig{
		Title:   "Delete attachment?",
		Message: fmt.Sprintf("%q will be permanently deleted.", att.FileName),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.AttachmentBusy.Set(att.ID)
		gen := m.LockGeneration()
		go func() {
			updated, err := m.Core.DeleteAttachment(context.Background(), cipherID, att.ID)
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					return
				}
				m.AttachmentBusy.Set("")
				if err != nil {
					m.ShowToast(ui.ToastError, "Delete failed", friendlyError(err))
					return
				}
				m.applyCipherUpdate(updated)
				m.ShowToast(ui.ToastInfo, "Attachment deleted", "")
			})
		}()
	})
}

func attachmentSizeLabel(a state.Attachment) string {
	if a.SizeName != "" {
		return a.SizeName
	}
	return formatByteSize(a.Size)
}

func formatByteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func attachmentsSection(cx *core.Scope, m *AppModel, c *state.Cipher) core.Node {
	canModify := m.CanModifyAttachments(c)
	if len(c.Attachments) == 0 && !canModify {
		return nil
	}
	busy := func(id string) func() bool { return func() bool { return m.AttachmentBusy.Get() == id } }
	rows := make([]core.Node, 0, len(c.Attachments)+1)
	for i, a := range c.Attachments {
		att := a
		var actions []core.Node
		if m.CanDownloadAttachments(c) {
			actions = append(actions, ui.Button{
				TestID:   fmt.Sprintf("detail-attachment-download-%d", i),
				Icon:     lucide.Download,
				Label:    "Download " + att.FileName,
				Variant:  ui.ButtonGhost,
				Side:     28,
				IconSize: 14,
				Busy:     busy(att.ID),
				Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
				OnPress:  func() { m.DownloadAttachment(cx, c, att) },
			})
		}
		if canModify {
			actions = append(actions, ui.Button{
				TestID:   fmt.Sprintf("detail-attachment-delete-%d", i),
				Icon:     lucide.Trash,
				Label:    "Delete " + att.FileName,
				Variant:  ui.ButtonGhost,
				Side:     28,
				IconSize: 14,
				Tint:     func() core.Color { return themeColor(cx, "gv-fg2") },
				OnPress:  func() { m.DeleteAttachment(cx, c, att) },
			})
		}
		rows = append(rows, core.View{
			TestID: "detail-attachment",
			Class:  "flex-row items-center gap-3 pl-4 pr-2.5 py-2 min-h-[48px]",
			Children: []core.Node{
				icon(lucide.Paperclip(), 14, "text-gv-fg3"),
				core.View{
					Class: "flex-1 gap-[2px] overflow-hidden",
					Children: []core.Node{
						core.Text{MaxLines: 1, Class: "text-[13.5px] text-gv-fg", Content: att.FileName},
						core.Text{Class: "text-[11.5px] text-gv-fg3 tabular-nums", Content: attachmentSizeLabel(att)},
					},
				},
				core.View{Class: "flex-row items-center gap-0.5", Children: actions},
			},
		})
	}
	if canModify {
		rows = append(rows, core.View{
			Class: "flex-row items-center px-2.5 py-1.5",
			Children: []core.Node{
				ui.Button{
					TestID:  "detail-attach-file",
					Text:    "Attach File",
					Icon:    lucide.Plus,
					Variant: ui.ButtonGhost,
					Size:    ui.SizeSmall,
					Busy:    busy(attachmentUploadBusy),
					OnPress: func() { m.AttachFile(cx, c) },
				},
			},
		})
	}
	return section("Attachments", card(rows...))
}
