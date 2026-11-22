package cli

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/export"
	"github.com/txchen/govault/internal/vaultcore/profile"
	"github.com/txchen/govault/internal/vaultcore/state"
)

const policyDisablePersonalVaultExport = 10

// maxExportSize is the largest file import reads.
var maxExportSize = export.MaxFileSize

var exportFormats = []string{"csv", "json", "encrypted_json", "zip"}

// exportFileName is bw's ExportHelper.getFileName.
func exportFileName(format string, now time.Time) string {
	prefix, ext := "", format
	if format == "encrypted_json" {
		prefix, ext = "_encrypted", "json"
	}
	return "bitwarden" + prefix + "_export_" + now.Format("20060102150405") + "." + ext
}

func (a *app) export(p *parsed) response {
	if optValue(p, "organizationid", "vaultid") != "" {
		return failure("gv cannot export organization vaults yet.")
	}
	password, hasPassword := p.opt("password")
	format := optValue(p, "format")
	switch {
	case format == "" && hasPassword, format == "json" && hasPassword:
		// A password always means a password-protected file.
		format = "encrypted_json"
	case format == "":
		format = "csv"
	}
	if !slices.Contains(exportFormats, format) {
		return failure(fmt.Sprintf("'%s' is not a supported export format. Supported formats: %s.", format, strings.Join(exportFormats, ", ")))
	}
	if hasPassword && format != "encrypted_json" {
		return failure(fmt.Sprintf("A %s export cannot be password protected: use --format encrypted_json with --password.", format))
	}
	return a.unlocked(func(v *profile.Vault) response {
		for _, pol := range v.Policies {
			if pol.Type == policyDisablePersonalVaultExport && policyApplies(pol, v.Organizations) {
				return failure("One or more organization policies prevents you from exporting your personal vault.")
			}
		}
		if format == "encrypted_json" && hasPassword && password == "" {
			if !a.canPrompt() {
				return failure("An export file password is required.")
			}
			pw, err := a.env.Terminal.ReadSecret("Export file password:")
			if err != nil || pw == "" {
				return failure("An export file password is required.")
			}
			password = pw
		}
		if err := exportComplete(v); err != nil {
			return failure(err.Error())
		}
		var data []byte
		var err error
		switch format {
		case "csv":
			data = exportCSV(v)
		case "json":
			data = a.prettyJSON(exportPlain(v))
		case "encrypted_json":
			if hasPassword {
				data, err = export.Protect(a.prettyJSON(exportPlain(v)), []byte(password), v.KDF)
			} else {
				data, err = a.exportAccount(v)
			}
		case "zip":
			data, err = a.exportZip(v)
		}
		if err != nil {
			return errResponse(err)
		}
		if format != "zip" && len(data) > maxExportSize {
			return failure(fmt.Sprintf("The export is larger than %d MiB, which no GoVault or gv import reads.", maxExportSize>>20))
		}
		return a.saveResult(data, optValue(p, "output"), exportFileName(format, a.env.Now()))
	})
}

// prettyJSON is JSON.stringify(v, null, "  ").
func (a *app) prettyJSON(v any) []byte {
	raw, err := marshal(v)
	if err != nil {
		return nil
	}
	var b bytes.Buffer
	if err := json.Indent(&b, raw, "", "  "); err != nil {
		return raw
	}
	return b.Bytes()
}

// exportComplete refuses an export that would leave out an item GoVault
// cannot read, or a passkey part of which does not decrypt, as the
// desktop's backup refuses it.
func exportComplete(v *profile.Vault) error {
	if n := len(v.Unreadable); n > 0 {
		return fmt.Errorf("The export would be incomplete: %d item(s) GoVault cannot read (%s). Export them with another Bitwarden client.", n, strings.Join(v.Unreadable, ", "))
	}
	for _, c := range exported(v) {
		if c.Login == nil {
			continue
		}
		for _, f := range c.Login.Fido2Credentials {
			if len(f.Unreadable) > 0 {
				return fmt.Errorf("The export would be incomplete: a passkey of %s does not fully decrypt (%s).", c.ID, strings.Join(f.Unreadable, ", "))
			}
		}
	}
	return nil
}

// exported are the items bw exports: personal, outside Trash, of a type
// no policy restricts, in its sort order.
func exported(v *profile.Vault) []*state.Cipher {
	limits := restrictions(v.VaultView)
	var out []*state.Cipher
	for _, c := range sortedItems(v) {
		if c.DeletedDate == nil && (c.OrganizationID == nil || *c.OrganizationID == "") && !restricted(c, limits) {
			out = append(out, c)
		}
	}
	return out
}

func exportPlain(v *profile.Vault) obj {
	fs := []any{}
	for _, f := range folders(v) {
		if f.ID != "" {
			fs = append(fs, obj{}.set("name", f.Name).set("id", f.ID))
		}
	}
	items := []any{}
	for _, c := range exported(v) {
		items = append(items, exportItemJSON(c, v.TypeData(c.ID)))
	}
	return obj{}.set("encrypted", false).set("folders", fs).set("items", items)
}

// exportItemJSON is bw's CipherWithIdExport of an item: its CLI form
// without object, attachments or hidden-password blanks, collectionIds
// null and no password revision date.
func exportItemJSON(c *state.Cipher, typeData map[string]any) obj {
	cp := *c
	cp.HidePassword = false
	src := itemJSON(&cp, typeData)
	out := obj{}
	for _, e := range src {
		switch e.k {
		case "object", "attachments":
		case "collectionIds":
			out = out.set("collectionIds", nil)
		case "passwordHistory":
			history := []any{}
			for _, h := range c.PasswordHistory {
				history = append(history, obj{}.set("password", h.Password).set("lastUsedDate", jsTime(h.LastUsedDate)))
			}
			out = out.set("passwordHistory", history)
		case "login":
			l := obj{}
			for _, le := range e.v.(obj) {
				if le.k != "passwordRevisionDate" {
					l = append(l, le)
				}
			}
			out = out.set("login", l)
		default:
			out = append(out, e)
		}
	}
	return out
}

// csvNeedsQuotes is Papa Parse's quoting rule.
func csvNeedsQuotes(s string) bool {
	return strings.ContainsAny(s, ",\"\r\n") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ")
}

func csvLine(fields []string) string {
	for i, f := range fields {
		if csvNeedsQuotes(f) {
			fields[i] = `"` + strings.ReplaceAll(f, `"`, `""`) + `"`
		}
	}
	return strings.Join(fields, ",")
}

// exportCSV is bw's CSV export: personal logins and secure notes.
func exportCSV(v *profile.Vault) []byte {
	names := map[string]string{}
	for _, f := range v.Folders {
		names[f.ID] = f.Name
	}
	lines := []string{"folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp"}
	for _, c := range exported(v) {
		if c.Type != api.CipherTypeLogin && c.Type != api.CipherTypeSecureNote {
			continue
		}
		row := make([]string, 12)
		if c.FolderID != nil {
			row[0] = names[*c.FolderID]
		}
		if c.Favorite {
			row[1] = "1"
		}
		row[3], row[4], row[6] = c.Name, c.Notes, strconv.Itoa(c.Reprompt)
		var fields []string
		for _, f := range c.Fields {
			fields = append(fields, f.Name+": "+f.Value)
		}
		row[5] = strings.Join(fields, "\n")
		if c.ArchivedDate != nil {
			row[7] = jsTime(*c.ArchivedDate)
		}
		if c.Type == api.CipherTypeLogin {
			row[2] = "login"
			if l := c.Login; l != nil {
				var uris []string
				for _, u := range l.URIs {
					uris = append(uris, u.URI)
				}
				row[8], row[9], row[10], row[11] = strings.Join(uris, ","), l.Username, l.Password, l.TOTP
			}
		} else {
			row[2] = "note"
		}
		lines = append(lines, csvLine(row))
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// accountItemOrder is the key order of bw's account-key export items.
var accountItemOrder = []string{"name", "notes", "key", "fields", "login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport", "passwordHistory", "creationDate", "revisionDate", "deletedDate", "archivedDate"}

// exportAccount writes the encrypted items and folders as the server keeps
// them, readable only with this account's key.
func (a *app) exportAccount(v *profile.Vault) ([]byte, error) {
	validation, err := v.ExportValidation()
	if err != nil {
		return nil, err
	}
	ciphers, encFolders := v.PersonalEncrypted()
	folders := []any{}
	for _, f := range encFolders {
		folders = append(folders, obj{}.set("name", f.Name).set("id", f.ID))
	}
	limits := restrictions(v.VaultView)
	items := []any{}
	for _, c := range ciphers {
		if restricted(&state.Cipher{Type: c.Type}, limits) {
			continue
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		o := obj{}.set("type", int(c.Type)).set("favorite", c.Favorite).set("reprompt", c.Reprompt).set("id", c.ID).
			set("collectionIds", nil).set("organizationId", nil).set("folderId", nullable(c.FolderID))
		for _, k := range accountItemOrder {
			if val, ok := m[k]; ok && string(val) != "null" {
				o = o.set(k, val)
			}
		}
		items = append(items, o)
	}
	return a.prettyJSON(obj{}.set("encrypted", true).set("encKeyValidation_DO_NOT_EDIT", validation).
		set("folders", folders).set("items", items)), nil
}

var (
	zipUnsafe     = regexp.MustCompile(`[/\\><:"|?*]`)
	zipUnsafeName = regexp.MustCompile(`[/\\><:"|?*.]`)
)

// exportZip is bw's zip export: data.json and the attachments of the
// items data.json holds, named as bw names them, made unique against the
// archive's paths. An attachment that does not download fails the export.
func (a *app) exportZip(v *profile.Vault) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("data.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(a.prettyJSON(exportPlain(v))); err != nil {
		return nil, err
	}
	collapse := regexp.MustCompile(`__+`)
	used := map[string]bool{}
	unique := func(stem, suffix string, n *int) string {
		for {
			name := stem + suffix
			if *n > 0 {
				name = fmt.Sprintf("%s_%d%s", stem, *n, suffix)
			}
			*n++
			if !used[strings.ToLower(name)] {
				used[strings.ToLower(name)] = true
				return name
			}
		}
	}
	dirCount := map[string]int{}
	for _, c := range exported(v) {
		if len(c.Attachments) == 0 {
			continue
		}
		stem := collapse.ReplaceAllString(zipUnsafe.ReplaceAllString(c.Name, "_"), "_")
		n := dirCount[stem]
		dir := unique("attachments/"+stem, "", &n)
		dirCount[stem] = n
		fileCount := map[string]int{}
		for _, at := range c.Attachments {
			data, err := v.Attachment(a.ctx, c, at.ID)
			if err != nil {
				return nil, fmt.Errorf("The export would be incomplete: attachment %s of %s did not download: %s", at.ID, c.ID, userMessage(err))
			}
			base, suffix := at.FileName, ""
			if parts := strings.Split(at.FileName, "."); len(parts) > 1 {
				base, suffix = strings.Join(parts[:len(parts)-1], ""), "."+parts[len(parts)-1]
			}
			base = collapse.ReplaceAllString(zipUnsafeName.ReplaceAllString(base, "_"), "_")
			k := fileCount[base+suffix]
			name := unique(dir+"/"+base, suffix, &k)
			fileCount[base+suffix] = k
			f, err := zw.Create(name)
			if err != nil {
				return nil, err
			}
			if _, err := f.Write(data); err != nil {
				return nil, err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var importFormats = []string{"bitwardencsv", "bitwardenjson", "bitwardenpasswordprotected"}

func (a *app) importCmd(p *parsed) response {
	if optValue(p, "organizationid", "vaultid") != "" {
		return failure("gv cannot import into organizations yet.")
	}
	if p.has("formats") {
		list := strings.Join(importFormats, "\n")
		return success(message{title: "Supported input formats:", text: &list, raw: &list})
	}
	format, path := p.arg(0), p.arg(1)
	if format == "" {
		return failure("`format` was not provided.")
	}
	if !slices.Contains(importFormats, format) {
		return failure(fmt.Sprintf("gv cannot import %s files; it reads %s.", format, strings.Join(importFormats, ", ")))
	}
	if path == "" {
		return failure("`filepath` was not provided.")
	}
	data, err := readLimited(path, export.MaxFileSize)
	if errors.Is(err, errTooLarge) {
		return failure(fmt.Sprintf("The import file is larger than %d MiB.", export.MaxFileSize>>20))
	}
	if errors.Is(err, os.ErrNotExist) {
		shown := path
		if !strings.ContainsAny(path, "/\\") {
			cwd, _ := os.Getwd()
			shown = filepath.Join(cwd, path)
		}
		return failure(fmt.Sprintf("ENOENT: no such file or directory, open '%s'", shown))
	}
	if err != nil {
		return failure(err.Error())
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return failure("Import file was empty.")
	}
	var plain *export.Vault
	if format == "bitwardencsv" {
		if plain, err = readBitwardenCSV(data); err != nil {
			return failure(err.Error())
		}
	} else if !export.IsAccountExport(data) {
		var password []byte
		if needs, _ := export.NeedsPassword(data); needs {
			pw, fail := a.importPassword(p)
			if fail != nil {
				return *fail
			}
			password = []byte(pw)
		}
		if plain, err = export.Read(data, password); err != nil {
			if errors.Is(err, export.ErrWrongPassword) {
				return failure("The import file password is incorrect.")
			}
			return failure(userMessage(err))
		}
	}
	return a.writing(func(w *profile.Writer) response {
		v := plain
		if v == nil {
			var err error
			if v, err = openAccountExport(w, data); err != nil {
				return errResponse(err)
			}
		}
		return a.importVault(w, v, path)
	})
}

func (a *app) importPassword(p *parsed) (string, *response) {
	if file := optValue(p, "passwordfile"); file != "" {
		line, err := readFirstLine(file)
		if err != nil {
			r := failure("Cannot read the password file: " + err.Error())
			return "", &r
		}
		return line, nil
	}
	if name := optValue(p, "passwordenv"); name != "" && a.getenv(name) != "" {
		return a.getenv(name), nil
	}
	if a.canPrompt() {
		if pw, err := a.env.Terminal.ReadSecret("Import file password:"); err == nil && pw != "" {
			return pw, nil
		}
	}
	r := failure("The import file is password protected: provide its password with --passwordenv or --passwordfile.")
	return "", &r
}

func openAccountExport(w *profile.Writer, data []byte) (*export.Vault, error) {
	var f export.AccountExport
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, export.ErrNotBitwardenExport
	}
	items := make([]api.EncryptedCipher, 0, len(f.Items))
	for _, raw := range f.Items {
		var c api.EncryptedCipher
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, export.ErrNotBitwardenExport
		}
		items = append(items, c)
	}
	folders := make([]api.EncryptedFolder, 0, len(f.Folders))
	for _, raw := range f.Folders {
		var fo api.EncryptedFolder
		if err := json.Unmarshal(raw, &fo); err != nil {
			return nil, export.ErrNotBitwardenExport
		}
		folders = append(folders, fo)
	}
	ciphers, decFolders, err := w.View.OpenAccountExport(f.EncKeyValidation, items, folders)
	if err != nil {
		return nil, err
	}
	v := &export.Vault{}
	for _, fo := range decFolders {
		v.Folders = append(v.Folders, export.Folder{ID: fo.ID, Name: fo.Name})
	}
	for _, c := range ciphers {
		v.Items = append(v.Items, export.FromCipher(c))
	}
	return v, nil
}

// importVault creates every item of v as a new personal item, as bw does.
// A file folder the vault has, by ID, is reused; any other is created, as
// Vaultwarden's import does.
func (a *app) importVault(w *profile.Writer, v *export.Vault, path string) response {
	// Organization policy decides what may be created before anything is.
	limits := restrictions(w.View)
	for _, it := range v.Items {
		if restricted(&state.Cipher{Type: it.Type}, limits) {
			return failure(fmt.Sprintf("Import cancelled: %s is of a type an organization policy restricts; nothing was imported.", idOrUnknown(it.ID)))
		}
	}
	have := map[string]bool{}
	for _, f := range w.Folders() {
		have[f.ID] = true
	}
	fileFolder := map[string]string{}
	for _, f := range v.Folders {
		if have[f.ID] {
			fileFolder[f.ID] = f.ID
			continue
		}
		created, err := w.SaveFolder(a.ctx, &state.Folder{Name: f.Name})
		if err != nil && created == nil {
			return a.writeFailure(err, noEditPermission)
		}
		fileFolder[f.ID] = created.ID
	}
	var skipped, unarchived []string
	for _, it := range v.Items {
		it.OrganizationID, it.CollectionIDs = nil, nil
		if it.FolderID != nil {
			if id, ok := fileFolder[*it.FolderID]; ok {
				it.FolderID = &id
			} else {
				it.FolderID = nil
			}
		}
		c, err := export.NewCipher(it)
		if errors.Is(err, export.ErrUnsupportedType) {
			skipped = append(skipped, fmt.Sprintf("  - %s: unsupported item type", idOrUnknown(it.ID)))
			continue
		}
		var saved *state.Cipher
		if err == nil {
			saved, err = w.SaveCipher(a.ctx, c)
		}
		// An archived item is archived again where the account may archive.
		if err == nil && it.ArchivedDate != nil && saved != nil {
			if w.View.Profile.Premium {
				err = w.ArchiveCipher(a.ctx, saved.ID)
			} else {
				unarchived = append(unarchived, "  - "+idOrUnknown(it.ID))
			}
		}
		var local *state.LocalCopyError
		if err != nil && !errors.As(err, &local) {
			r := a.writeFailure(err, noEditPermission)
			r.message = fmt.Sprintf("Import stopped at %s: %s", idOrUnknown(it.ID), r.message)
			return r
		}
	}
	var notes []string
	if len(skipped) > 0 {
		notes = append(notes, fmt.Sprintf("%d item(s) could not be imported and were skipped:\n%s", len(skipped), strings.Join(skipped, "\n")))
	}
	if len(unarchived) > 0 {
		notes = append(notes, fmt.Sprintf("%d archived item(s) were imported outside the Archive, which needs premium:\n%s", len(unarchived), strings.Join(unarchived, "\n")))
	}
	if len(notes) > 0 {
		text := strings.Join(notes, "\n")
		return success(message{title: "Imported " + path, text: &text, raw: &text})
	}
	return msg("Imported " + path)
}

func idOrUnknown(id string) string {
	if strings.TrimSpace(id) == "" {
		return "(unidentified item)"
	}
	return id
}

// readBitwardenCSV reads bw's CSV export.
func readBitwardenCSV(data []byte) (*export.Vault, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, errors.New("The file is not a Bitwarden CSV export.")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	if _, ok := col["name"]; !ok {
		return nil, errors.New("The file is not a Bitwarden CSV export.")
	}
	v := &export.Vault{}
	folderIDs := map[string]string{}
	str := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	for n, row := range rows[1:] {
		it := export.Item{ID: fmt.Sprintf("row %d", n+2), Name: get(row, "name"), Notes: str(get(row, "notes")), Favorite: get(row, "favorite") == "1"}
		it.Reprompt, _ = strconv.Atoi(get(row, "reprompt"))
		if t, err := time.Parse(time.RFC3339Nano, get(row, "archivedDate")); err == nil {
			it.ArchivedDate = &t
		}
		if folder := get(row, "folder"); folder != "" {
			id, ok := folderIDs[folder]
			if !ok {
				id = fmt.Sprintf("csv-folder-%d", len(folderIDs))
				folderIDs[folder] = id
				v.Folders = append(v.Folders, export.Folder{ID: id, Name: folder})
			}
			it.FolderID = &id
		}
		if fields := get(row, "fields"); fields != "" {
			for _, line := range strings.Split(fields, "\n") {
				name, value, _ := strings.Cut(line, ": ")
				it.Fields = append(it.Fields, export.Field{Name: str(name), Value: str(value)})
			}
		}
		switch get(row, "type") {
		case "note":
			it.Type, it.SecureNote = api.CipherTypeSecureNote, &export.SecureNote{}
		default:
			it.Type = api.CipherTypeLogin
			l := &export.Login{Username: str(get(row, "login_username")), Password: str(get(row, "login_password")), TOTP: str(get(row, "login_totp"))}
			for _, u := range strings.Split(get(row, "login_uri"), ",") {
				if u = strings.TrimSpace(u); u != "" {
					l.URIs = append(l.URIs, export.URI{URI: str(u)})
				}
			}
			it.Login = l
		}
		v.Items = append(v.Items, it)
	}
	return v, nil
}
