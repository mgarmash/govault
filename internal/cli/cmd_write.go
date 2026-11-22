package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/profile"
	"github.com/txchen/govault/internal/vaultcore/state"
)

var (
	createObjects = []string{"item", "attachment", "folder", "my-folder", "org-collection", "org-shared-folder"}
	createShown   = []string{"item", "attachment", "folder", "org-collection"}
	editObjects   = []string{"item", "item-collections", "item-shared-folders", "folder", "my-folder", "org-collection", "org-shared-folder"}
	editShown     = []string{"item", "item-collections", "folder", "org-collection"}
	deleteObjects = []string{"item", "attachment", "folder", "my-folder", "org-collection", "org-shared-folder"}
	deleteShown   = []string{"item", "attachment", "folder", "org-collection"}
)

const (
	noEditPermission   = "You do not have permission to edit this item"
	noDeletePermission = "You do not have permission to delete this item."
	premiumRequired    = "Premium status is required to use this feature."
	orgCollectionsNote = "gv does not manage organization collections yet."
)

// decodeBase64 decodes like Node's Buffer.from(s, "base64"), which skips
// characters outside the alphabet and takes the URL-safe one too.
func decodeBase64(s string) []byte {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			b.WriteRune(r)
		case r == '-':
			b.WriteByte('+')
		case r == '_':
			b.WriteByte('/')
		case r == '=':
			goto done
		}
	}
done:
	clean := b.String()
	// A lone trailing character carries no whole byte; Node drops it.
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out, _ := base64.RawStdEncoding.DecodeString(clean)
	return out
}

// request reads a write's encoded JSON from its argument or stdin into v.
func (a *app) request(arg string, v any) *response {
	if arg == "" && !a.env.StdinTTY && a.env.Stdin != nil {
		data, _ := io.ReadAll(a.env.Stdin)
		arg = string(data)
	}
	if arg == "" {
		r := failure("`requestJson` was not provided.")
		return &r
	}
	if err := json.Unmarshal(decodeBase64(arg), v); err != nil {
		r := failure("Error parsing the encoded request data.")
		return &r
	}
	return nil
}

// writing runs fn with the vault open for changes, unlocking first when
// interaction allows, as reads do.
func (a *app) writing(fn func(w *profile.Writer) response) response {
	prof, err := a.openProfile()
	if err != nil {
		return errResponse(err)
	}
	if fail := a.ensureUnlocked(prof); fail != nil {
		return *fail
	}
	var r response
	err = prof.Write(a.ctx, a.flags.session, a.apiKeyFromEnv(), func(w *profile.Writer) error {
		r = fn(w)
		return nil
	})
	if err != nil {
		return errResponse(err)
	}
	return r
}

// writeFailure maps a write error to bw's message for it.
func (a *app) writeFailure(err error, permission string) response {
	var apiErr *api.APIError
	var local *state.LocalCopyError
	switch {
	case errors.As(err, &local):
		a.warn("Warning: the server has the change, but gv could not record it in its local copy; run `gv sync`.")
		return success(nil)
	case errors.Is(err, state.ErrCipherNotFound), errors.Is(err, state.ErrFolderNotFound), errors.Is(err, state.ErrAttachmentNotFound):
		return notFound()
	case errors.Is(err, state.ErrReadOnlyCipher), errors.Is(err, state.ErrHiddenByOrganization):
		return failure(permission)
	case errors.Is(err, state.ErrPremiumRequired):
		return failure(premiumRequired)
	case errors.Is(err, api.ErrRevisionConflict):
		return failure("The client copy of this cipher is out of date. Resync the client and try again.")
	case errors.Is(err, state.ErrCipherChanged):
		return failure("The item changed on the server since the last sync. Run `gv sync` and try again.")
	case errors.As(err, &apiErr) && apiErr.Message != "":
		return failure(apiErr.Message)
	}
	return errResponse(err)
}

// written prints a changed item, or reports that the server has it but
// the local copy does not.
func (a *app) written(c *state.Cipher, err error, permission string) response {
	var local *state.LocalCopyError
	if errors.As(err, &local) && c != nil {
		a.warn("Warning: the server has the change, but gv could not record it in its local copy; run `gv sync`.")
		err = nil
	}
	if err != nil {
		return a.writeFailure(err, permission)
	}
	return success(itemJSON(c, nil))
}

func restrictedFor(w *profile.Writer, c *state.Cipher) bool {
	return restricted(c, restrictions(w.View))
}

func (a *app) create(p *parsed) response {
	object := p.arg(0)
	if !slices.Contains(createObjects, object) {
		return unknownObject(object, createShown)
	}
	if object == "org-collection" || object == "org-shared-folder" {
		return failure(orgCollectionsNote)
	}
	if object == "attachment" {
		return a.createAttachment(p)
	}
	var raw json.RawMessage
	if fail := a.request(p.arg(1), &raw); fail != nil {
		return *fail
	}
	if object == "item" {
		var it export.Item
		if err := json.Unmarshal(raw, &it); err != nil {
			return failure("Error parsing the encoded request data.")
		}
		return a.writing(func(w *profile.Writer) response {
			if !export.IsSavableType(it.Type) {
				return failure(fmt.Sprintf("Item type %d is not available.", it.Type))
			}
			c, err := export.NewCipher(it)
			if err != nil {
				return a.writeFailure(err, noEditPermission)
			}
			if restrictedFor(w, c) {
				return failure("Creating this item type is restricted by organizational policy.")
			}
			saved, err := w.SaveCipher(a.ctx, c)
			return a.written(saved, err, noEditPermission)
		})
	}
	var folder struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &folder); err != nil {
		return failure("Error parsing the encoded request data.")
	}
	return a.writing(func(w *profile.Writer) response {
		f, err := w.SaveFolder(a.ctx, &state.Folder{Name: folder.Name})
		if err != nil && f == nil {
			return a.writeFailure(err, noEditPermission)
		}
		return success(folderJSON(f.ID, f.Name))
	})
}

func (a *app) createAttachment(p *parsed) response {
	itemID := strings.ToLower(optValue(p, "itemid"))
	if itemID == "" {
		return failure("`itemid` option is required.")
	}
	file := optValue(p, "file")
	if file == "" {
		return failure("`file` option is required.")
	}
	abs, _ := filepath.Abs(file)
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return failure("Cannot find file at " + abs)
	}
	if err != nil {
		return errResponse(err)
	}
	name := filepath.Base(abs)
	if len(data) > api.MaxAttachmentSize {
		return failure("The file is larger than the 100 MiB attachment limit.")
	}
	return a.writing(func(w *profile.Writer) response {
		c, err := w.GetCipher(itemID)
		if err != nil {
			return notFound()
		}
		if !w.View.Profile.Premium && (c.OrganizationID == nil || *c.OrganizationID == "") {
			return failure(premiumRequired)
		}
		saved, err := w.UploadAttachment(a.ctx, c.ID, name, data)
		return a.written(saved, err, noEditPermission)
	})
}

func (a *app) edit(p *parsed) response {
	object := p.arg(0)
	if !slices.Contains(editObjects, object) {
		return unknownObject(object, editShown)
	}
	if object == "org-collection" || object == "org-shared-folder" {
		return failure(orgCollectionsNote)
	}
	id := strings.ToLower(p.arg(1))
	var raw json.RawMessage
	if fail := a.request(p.arg(2), &raw); fail != nil {
		return *fail
	}
	switch object {
	case "item":
		var it export.Item
		if err := json.Unmarshal(raw, &it); err != nil {
			return failure("Error parsing the encoded request data.")
		}
		return a.writing(func(w *profile.Writer) response { return a.editItem(w, id, it) })
	case "item-collections", "item-shared-folders":
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return failure("Error parsing the encoded request data.")
		}
		return a.writing(func(w *profile.Writer) response {
			c, err := w.SetCipherCollections(a.ctx, id, ids)
			switch {
			case errors.Is(err, state.ErrNotOrganizationItem):
				return failure("Item does not belong to an organization. Consider moving it first.")
			case err == nil && c == nil:
				return success(nil)
			}
			return a.written(c, err, noEditPermission)
		})
	}
	var folder struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &folder); err != nil {
		return failure("Error parsing the encoded request data.")
	}
	return a.writing(func(w *profile.Writer) response {
		if !slices.ContainsFunc(w.Folders(), func(f state.Folder) bool { return f.ID == id }) {
			return notFound()
		}
		f, err := w.SaveFolder(a.ctx, &state.Folder{ID: id, Name: folder.Name})
		if err != nil && f == nil {
			return a.writeFailure(err, noEditPermission)
		}
		return success(folderJSON(f.ID, f.Name))
	})
}

func (a *app) editItem(w *profile.Writer, id string, it export.Item) response {
	cur, err := w.GetCipher(id)
	if err != nil {
		return notFound()
	}
	if cur.ReadOnly {
		return failure(noEditPermission)
	}
	if cur.DeletedDate != nil {
		return failure("You may not edit a deleted item. Use the restore command first.")
	}
	if cur.ArchivedDate != nil && !w.View.Profile.Premium {
		return failure("Edit cancelled. Editing an archived item needs premium; restore it from the Archive first.")
	}
	if !export.IsSavableType(it.Type) {
		return failure(fmt.Sprintf("Item type %d is not available.", it.Type))
	}
	hiddenPassword, hiddenTOTP := "", ""
	hiddenFields := map[string][]string{}
	if cur.HidePassword {
		if cur.Login != nil {
			hiddenPassword, hiddenTOTP = cur.Login.Password, cur.Login.TOTP
		}
		for _, f := range cur.Fields {
			if f.Type == fieldTypeHidden {
				hiddenFields[f.Name] = append(hiddenFields[f.Name], f.Value)
			}
		}
	}
	if err := export.Edit(cur, it); err != nil {
		if errors.Is(err, export.ErrTypeChange) {
			return failure("gv cannot change an item's type.")
		}
		return a.writeFailure(err, noEditPermission)
	}
	// As bw does, values the user may not see, sent back blank, keep
	// what they were.
	if cur.HidePassword {
		if cur.Login != nil {
			if cur.Login.Password == "" {
				cur.Login.Password = hiddenPassword
			}
			if cur.Login.TOTP == "" {
				cur.Login.TOTP = hiddenTOTP
			}
		}
		for i, f := range cur.Fields {
			if vals := hiddenFields[f.Name]; f.Type == fieldTypeHidden && f.Value == "" && len(vals) > 0 {
				cur.Fields[i].Value, hiddenFields[f.Name] = vals[0], vals[1:]
			}
		}
	}
	if restrictedFor(w, cur) {
		return failure("Editing this item type is restricted by organizational policy.")
	}
	saved, err := w.SaveCipher(a.ctx, cur)
	return a.written(saved, err, noEditPermission)
}

func (a *app) delete(p *parsed) response {
	object := p.arg(0)
	if !slices.Contains(deleteObjects, object) {
		return unknownObject(object, deleteShown)
	}
	if object == "org-collection" || object == "org-shared-folder" {
		return failure(orgCollectionsNote)
	}
	id := strings.ToLower(p.arg(1))
	switch object {
	case "item":
		return a.writing(func(w *profile.Writer) response {
			c, err := w.GetCipher(id)
			if err != nil {
				return notFound()
			}
			if c.ReadOnly {
				return failure(noDeletePermission)
			}
			if restrictedFor(w, c) {
				return failure("Deleting this item type is restricted by organizational policy.")
			}
			if p.has("permanent") {
				err = w.DeleteCipherPermanently(a.ctx, id)
			} else {
				err = w.SoftDeleteCipher(a.ctx, id)
			}
			if err != nil {
				return a.writeFailure(err, noDeletePermission)
			}
			return success(nil)
		})
	case "attachment":
		itemID := strings.ToLower(optValue(p, "itemid"))
		if itemID == "" {
			return failure("`itemid` option is required.")
		}
		return a.writing(func(w *profile.Writer) response {
			c, err := w.GetCipher(itemID)
			if err != nil {
				return notFound()
			}
			if len(c.Attachments) == 0 {
				return failure("No attachments available for this item.")
			}
			i := slices.IndexFunc(c.Attachments, func(at state.Attachment) bool { return strings.ToLower(at.ID) == id })
			if i < 0 {
				return failure("Attachment `" + id + "` was not found.")
			}
			if !w.View.Profile.Premium && (c.OrganizationID == nil || *c.OrganizationID == "") {
				return failure(premiumRequired)
			}
			if _, err := w.DeleteAttachment(a.ctx, c.ID, c.Attachments[i].ID); err != nil {
				var local *state.LocalCopyError
				if !errors.As(err, &local) {
					return a.writeFailure(err, noDeletePermission)
				}
				a.warn("Warning: the server has the change, but gv could not record it in its local copy; run `gv sync`.")
			}
			return success(nil)
		})
	}
	return a.writing(func(w *profile.Writer) response {
		if !slices.ContainsFunc(w.Folders(), func(f state.Folder) bool { return f.ID == id }) {
			return notFound()
		}
		if err := w.DeleteFolder(a.ctx, id); err != nil {
			var local *state.LocalCopyError
			if !errors.As(err, &local) {
				return a.writeFailure(err, noDeletePermission)
			}
		}
		return success(nil)
	})
}

func (a *app) restore(p *parsed) response {
	if p.arg(0) != "item" {
		return unknownObject(p.arg(0), []string{"item"})
	}
	id := strings.ToLower(p.arg(1))
	return a.writing(func(w *profile.Writer) response {
		c, err := w.GetCipher(id)
		if err != nil {
			return notFound()
		}
		switch {
		case c.ArchivedDate != nil && c.DeletedDate == nil:
			err = w.UnarchiveCipher(a.ctx, id)
		case c.DeletedDate == nil:
			return failure("Cipher is not in trash.")
		case c.ReadOnly:
			return failure("You do not have permission to restore this item")
		default:
			err = w.RestoreCipher(a.ctx, id)
		}
		if err != nil {
			return a.writeFailure(err, "You do not have permission to restore this item")
		}
		return success(nil)
	})
}

func (a *app) archive(p *parsed) response {
	if p.arg(0) != "item" {
		return unknownObject(p.arg(0), []string{"item"})
	}
	id := strings.ToLower(p.arg(1))
	return a.writing(func(w *profile.Writer) response {
		c, err := w.GetCipher(id)
		if err != nil {
			return notFound()
		}
		switch {
		case !w.View.Profile.Premium:
			return failure(premiumRequired)
		case c.ArchivedDate != nil:
			return failure("Item is already archived.")
		case c.DeletedDate != nil:
			return failure("Item is in the trash, the item must be restored before archiving.")
		}
		if err := w.ArchiveCipher(a.ctx, id); err != nil {
			return a.writeFailure(err, noEditPermission)
		}
		return success(nil)
	})
}
