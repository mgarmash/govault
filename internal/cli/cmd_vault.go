package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"github.com/txchen/govault/internal/vaultcore/privatefile"
	"github.com/txchen/govault/internal/vaultcore/profile"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

var (
	listObjects = []string{"items", "folders", "my-folders", "collections", "shared-folders", "org-collections", "org-shared-folders", "org-members", "organizations"}
	listShown   = []string{"items", "folders", "collections", "org-collections", "org-members", "organizations"}
	getObjects  = []string{"item", "username", "password", "uri", "totp", "notes", "exposed", "attachment", "folder", "my-folder",
		"collection", "shared-folder", "org-collection", "org-shared-folder", "organization", "template", "fingerprint", "send"}
	getShown = []string{"item", "username", "password", "uri", "totp", "notes", "exposed", "attachment", "folder", "collection",
		"org-collection", "organization", "template", "fingerprint", "send"}
)

func unknownObject(object string, shown []string) response {
	return failure(`Unknown object "` + object + `". Allowed objects are: ` + strings.Join(shown, ", ") + ".")
}

// optValue is an option's value, "" when absent or empty, as bw's
// `passedOptions?.x || ...` reads them.
func optValue(p *parsed, names ...string) string {
	for _, n := range names {
		if v, ok := p.opt(n); ok && v != "" {
			return v
		}
	}
	return ""
}

func (a *app) list(p *parsed) response {
	object := p.arg(0)
	if !slices.Contains(listObjects, object) {
		return unknownObject(object, listShown)
	}
	if object == "org-members" {
		return failure("gv does not list organization members yet.")
	}
	return a.unlocked(func(v *profile.Vault) response {
		switch object {
		case "items":
			return listItems(v, p)
		case "folders", "my-folders":
			return listFolders(v, optValue(p, "search"))
		case "collections", "shared-folders":
			return listCollections(v, p)
		case "org-collections", "org-shared-folders":
			return a.listOrgCollections(v, p)
		}
		return listOrganizations(v, optValue(p, "search"))
	})
}

func sortedItems(v *profile.Vault) []*state.Cipher {
	items := slices.Clone(v.Ciphers)
	sortItems(items)
	return items
}

func listItems(v *profile.Vault, p *parsed) response {
	trash := p.has("trash")
	archived := p.has("archived") && v.Profile.Premium
	matchesState := func(c *state.Cipher) bool {
		return (c.DeletedDate != nil) == trash && (c.ArchivedDate != nil) == archived
	}
	limits := restrictions(v.VaultView)
	items := sortedItems(v)
	if u := optValue(p, "url"); strings.TrimSpace(u) != "" {
		def := defaultURIMatch(v.VaultView)
		items = slices.DeleteFunc(items, func(c *state.Cipher) bool {
			return c.DeletedDate != nil || c.ArchivedDate != nil || restricted(c, limits) || !matchesAnyURL(c, u, def)
		})
	}
	folderID, collectionID, orgID := optValue(p, "folderid"), optValue(p, "collectionid", "sharedfolderid"), optValue(p, "organizationid")
	search := optValue(p, "search")
	switch {
	case folderID != "" || collectionID != "" || orgID != "":
		items = slices.DeleteFunc(items, func(c *state.Cipher) bool {
			return !matchesState(c) || !matchesFilters(c, folderID, collectionID, orgID)
		})
	case strings.TrimSpace(search) == "":
		items = slices.DeleteFunc(items, func(c *state.Cipher) bool { return !matchesState(c) })
	}
	if strings.TrimSpace(search) != "" {
		items = slices.DeleteFunc(items, func(c *state.Cipher) bool { return !matchesState(c) })
		items = searchBasic(items, search)
	}
	out := listData{}
	for _, c := range items {
		if !restricted(c, limits) {
			out = append(out, itemJSON(c, v.TypeData(c.ID)))
		}
	}
	return success(out)
}

// matchesFilters is true when any of the given ID filters matches; "null"
// and "notnull" test for absence and presence.
func matchesFilters(c *state.Cipher, folderID, collectionID, orgID string) bool {
	has := func(p *string) bool { return p != nil && *p != "" }
	if folderID != "" {
		switch {
		case folderID == "notnull" && has(c.FolderID),
			folderID == "null" && !has(c.FolderID),
			has(c.FolderID) && *c.FolderID == folderID:
			return true
		}
	}
	if orgID != "" {
		switch {
		case orgID == "notnull" && has(c.OrganizationID),
			orgID == "null" && !has(c.OrganizationID),
			has(c.OrganizationID) && *c.OrganizationID == orgID:
			return true
		}
	}
	if collectionID != "" {
		switch {
		case collectionID == "notnull" && len(c.CollectionIDs) > 0,
			collectionID == "null" && len(c.CollectionIDs) == 0,
			collectionID != "null" && slices.Contains(c.CollectionIDs, collectionID):
			return true
		}
	}
	return false
}

const noFolderName = "No Folder"

// folders returns the folders sorted by name, then bw's "No Folder".
func folders(v *profile.Vault) []state.Folder {
	out := slices.Clone(v.Folders)
	slices.SortStableFunc(out, func(a, b state.Folder) int { return compareNames(a.Name, b.Name) })
	return append(out, state.Folder{Name: noFolderName})
}

func nameContains(name, search string) bool {
	return strings.Contains(lowerJS(name), lowerJS(search))
}

func listFolders(v *profile.Vault, search string) response {
	out := listData{}
	for _, f := range folders(v) {
		if strings.TrimSpace(search) == "" || nameContains(f.Name, search) {
			out = append(out, folderJSON(f.ID, f.Name))
		}
	}
	return success(out)
}

func sortedCollections(cols []state.ViewCollection) []state.ViewCollection {
	out := slices.Clone(cols)
	slices.SortStableFunc(out, func(a, b state.ViewCollection) int { return compareNames(a.Name, b.Name) })
	return out
}

func listCollections(v *profile.Vault, p *parsed) response {
	orgID, search := optValue(p, "organizationid"), optValue(p, "search")
	out := listData{}
	for _, c := range sortedCollections(v.Collections) {
		if (orgID == "" || c.OrganizationID == orgID) && (strings.TrimSpace(search) == "" || nameContains(c.Name, search)) {
			out = append(out, collectionJSON(c, false))
		}
	}
	return success(out)
}

func (a *app) listOrgCollections(v *profile.Vault, p *parsed) response {
	orgID := optValue(p, "organizationid")
	if orgID == "" {
		return failure("`organizationid` option is required.")
	}
	if !isGUID(orgID) {
		return failure("`" + orgID + "` is not a GUID.")
	}
	i := slices.IndexFunc(v.Organizations, func(o state.ViewOrganization) bool { return o.ID == orgID })
	if i < 0 {
		return failure("Organization not found.")
	}
	cols, err := v.OrganizationCollections(a.ctx, v.Organizations[i])
	if err != nil {
		return errResponse(err)
	}
	search := optValue(p, "search")
	out := listData{}
	for _, c := range sortedCollections(cols) {
		if strings.TrimSpace(search) == "" || nameContains(c.Name, search) {
			out = append(out, collectionJSON(c, true))
		}
	}
	return success(out)
}

func listOrganizations(v *profile.Vault, search string) response {
	out := listData{}
	for _, o := range v.Organizations {
		if strings.TrimSpace(search) == "" || nameContains(o.Name, search) {
			out = append(out, organizationJSON(o))
		}
	}
	return success(out)
}

func (a *app) get(p *parsed) response {
	object := p.arg(0)
	if !slices.Contains(getObjects, object) {
		return unknownObject(object, getShown)
	}
	switch object {
	case "exposed":
		return failure("gv does not check passwords against breach services.")
	case "org-collection", "org-shared-folder":
		return failure("gv does not read organization collection details yet; use `gv list org-collections`.")
	case "send":
		return failure("gv does not support Bitwarden Send.")
	}
	id := strings.ToLower(p.arg(1))
	return a.unlocked(func(v *profile.Vault) response {
		switch object {
		case "item":
			return getItem(v, id, nil)
		case "username", "password", "uri", "totp", "notes":
			return getScalar(v, object, id)
		case "attachment":
			return a.getAttachment(v, id, p)
		case "folder", "my-folder":
			return getFolder(v, id)
		case "collection", "shared-folder":
			return getCollection(v, id)
		case "organization":
			return getOrganization(v, id)
		case "template":
			t, ok := templates[templateAliases(id)]
			if !ok {
				return failure("Unknown template object.")
			}
			return success(templateData{template: t})
		}
		return a.getFingerprint(v, id)
	})
}

// lookup finds an item by ID, or else by a search of active items, which
// may return several.
func lookup(v *profile.Vault, id string) []*state.Cipher {
	if isGUID(id) {
		for _, c := range v.Ciphers {
			if c.ID == id {
				return []*state.Cipher{c}
			}
		}
		return nil
	}
	if strings.TrimSpace(id) == "" {
		return nil
	}
	active := slices.DeleteFunc(sortedItems(v), func(c *state.Cipher) bool { return c.DeletedDate != nil || c.ArchivedDate != nil })
	return searchBasic(active, id)
}

const restrictedMessage = "Access to this item type is restricted by organizational policy."

// findItem is bw's getCipher: one item for id that passes filter.
func findItem(v *profile.Vault, id string, filter func(*state.Cipher) bool) (*state.Cipher, *response) {
	fail := func(r response) (*state.Cipher, *response) { return nil, &r }
	limits := restrictions(v.VaultView)
	found := lookup(v, id)
	if len(found) == 0 {
		return fail(notFound())
	}
	if !isGUID(id) {
		found = slices.DeleteFunc(found, func(c *state.Cipher) bool { return restricted(c, limits) })
		if len(found) == 0 {
			return fail(failure(restrictedMessage))
		}
		if filter != nil {
			found = slices.DeleteFunc(found, func(c *state.Cipher) bool { return !filter(c) })
		}
		switch len(found) {
		case 0:
			return fail(notFound())
		case 1:
			return found[0], nil
		}
		ids := make([]string, len(found))
		for i, c := range found {
			ids[i] = c.ID
		}
		return fail(multipleResults(ids))
	}
	c := found[0]
	if restricted(c, limits) {
		return fail(failure(restrictedMessage))
	}
	if filter != nil && !filter(c) {
		return fail(notFound())
	}
	return c, nil
}

func getItem(v *profile.Vault, id string, filter func(*state.Cipher) bool) response {
	c, fail := findItem(v, id, filter)
	if fail != nil {
		return *fail
	}
	return success(itemJSON(c, v.TypeData(c.ID)))
}

func isLogin(c *state.Cipher) bool { return c.Type == api.CipherTypeLogin && c.Login != nil }

func getScalar(v *profile.Vault, object, id string) response {
	var filter func(*state.Cipher) bool
	switch object {
	case "username":
		filter = func(c *state.Cipher) bool { return isLogin(c) && !isBlank(c.Login.Username) }
	case "password":
		filter = func(c *state.Cipher) bool { return isLogin(c) && !isBlank(c.Login.Password) }
	case "uri":
		filter = func(c *state.Cipher) bool { return isLogin(c) && len(c.Login.URIs) > 0 && c.Login.URIs[0].URI != "" }
	case "totp":
		filter = func(c *state.Cipher) bool { return isLogin(c) && !isBlank(c.Login.TOTP) }
	case "notes":
		filter = func(c *state.Cipher) bool { return !isBlank(c.Notes) }
	}
	c, fail := findItem(v, id, filter)
	if fail != nil {
		return *fail
	}
	if object == "notes" {
		return str(c.Notes)
	}
	if !isLogin(c) {
		return failure("Not a login.")
	}
	l := c.Login
	switch object {
	case "username":
		return str(l.Username)
	case "uri":
		return str(l.URIs[0].URI)
	case "password":
		if c.HidePassword || isBlank(l.Password) {
			return failure("No password available for this login.")
		}
		return str(l.Password)
	}
	if c.HidePassword || isBlank(l.TOTP) {
		return failure("No TOTP available for this login.")
	}
	cfg, err := totp.ParseTOTP(l.TOTP)
	if err != nil {
		return failure("Couldn't generate TOTP code.")
	}
	code, _, _, err := totp.Generate(cfg, time.Now())
	if err != nil || code == "" {
		return failure("Couldn't generate TOTP code.")
	}
	if !v.Profile.Premium && !orgUsesTOTP(v, c) {
		return failure("Premium status is required to use this feature.")
	}
	return str(code)
}

func orgUsesTOTP(v *profile.Vault, c *state.Cipher) bool {
	if c.OrganizationID == nil || *c.OrganizationID == "" {
		return false
	}
	var on bool
	if raw, ok := c.Extra["organizationUseTotp"]; ok && string(raw) == "true" {
		on = true
	}
	return on
}

func (a *app) getAttachment(v *profile.Vault, id string, p *parsed) response {
	itemID := strings.ToLower(optValue(p, "itemid"))
	if itemID == "" {
		return failure("--itemid <itemid> required.")
	}
	c, fail := findItem(v, itemID, nil)
	if fail != nil {
		return *fail
	}
	if len(c.Attachments) == 0 {
		return failure("No attachments available for this item.")
	}
	var matches []state.Attachment
	for _, at := range c.Attachments {
		if strings.ToLower(at.ID) == id || strings.Contains(strings.ToLower(at.FileName), id) {
			matches = append(matches, at)
		}
	}
	if len(matches) == 0 {
		return failure("Attachment `" + id + "` was not found.")
	}
	var exact []state.Attachment
	for _, at := range matches {
		if strings.ToLower(at.FileName) == id {
			exact = append(exact, at)
		}
	}
	if len(exact) == 1 {
		matches = exact
	}
	if len(matches) > 1 {
		ids := make([]string, len(matches))
		for i, at := range matches {
			ids[i] = at.ID
		}
		return multipleResults(ids)
	}
	if !v.Profile.Premium && (c.OrganizationID == nil || *c.OrganizationID == "") {
		return failure("Premium status is required to use this feature.")
	}
	data, err := v.Attachment(a.ctx, c, matches[0].ID)
	switch {
	case errors.Is(err, state.ErrHiddenByOrganization):
		return failure("Your organization hides this item's passwords, so its attachments cannot be downloaded.")
	case err != nil:
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			return failure(fmt.Sprintf("A %d error occurred while downloading the attachment.", apiErr.StatusCode))
		}
		return errResponse(err)
	}
	return a.saveResult(data, optValue(p, "output"), safeFileName(matches[0].FileName))
}

// safeFileName reduces a server-chosen file name to a plain base name.
func safeFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(filepath.FromSlash(name))
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return fmt.Sprintf("BitwardenAttachment-%d", time.Now().UnixMilli())
	}
	return base
}

// saveResult writes data to stdout under --raw without an output path, or
// else to a private file, as bw's saveResultToFile does. It refuses to
// write through a symbolic link.
func (a *app) saveResult(data []byte, output, defaultName string) response {
	if output == "" && a.flags.raw {
		_, _ = a.env.Stdout.Write(data)
		return success(fileWritten{})
	}
	cwd, err := os.Getwd()
	if err != nil {
		return errResponse(err)
	}
	target := filepath.Join(cwd, defaultName)
	mkdir := false
	if output != "" {
		out := filepath.Clean(output)
		switch {
		case !strings.ContainsAny(output, `/\`):
			target = filepath.Join(cwd, out)
		case strings.HasSuffix(output, "/") || strings.HasSuffix(output, string(filepath.Separator)):
			mkdir, target = true, filepath.Join(out, defaultName)
		default:
			mkdir, target = true, out
		}
	}
	if target, err = filepath.Abs(target); err != nil {
		return errResponse(err)
	}
	if mkdir {
		if dir := filepath.Dir(target); dir != "" {
			if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
				if err := privatefile.MkdirAll(dir); err != nil {
					return failure("Cannot save file to " + target)
				}
			}
		}
	}
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return failure("Cannot save file to " + target + ": it is a symbolic link")
	}
	if err := privatefile.WriteFile(target, data); err != nil {
		return failure("Cannot save file to " + target)
	}
	return success(message{title: "Saved " + target, raw: &target})
}

func getFolder(v *profile.Vault, id string) response {
	if isGUID(id) {
		for _, f := range v.Folders {
			if f.ID == id {
				return success(folderJSON(f.ID, f.Name))
			}
		}
		return notFound()
	}
	if strings.TrimSpace(id) == "" {
		return notFound()
	}
	var found []state.Folder
	for _, f := range folders(v) {
		if nameContains(f.Name, id) {
			found = append(found, f)
		}
	}
	switch len(found) {
	case 0:
		return notFound()
	case 1:
		return success(folderJSON(found[0].ID, found[0].Name))
	}
	ids := make([]string, len(found))
	for i, f := range found {
		ids[i] = f.ID
	}
	return multipleResults(ids)
}

func getCollection(v *profile.Vault, id string) response {
	if isGUID(id) {
		for _, c := range v.Collections {
			if c.ID == id {
				return success(collectionJSON(c, true))
			}
		}
		return notFound()
	}
	if strings.TrimSpace(id) == "" {
		return notFound()
	}
	var found []state.ViewCollection
	for _, c := range sortedCollections(v.Collections) {
		if nameContains(c.Name, id) {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 0:
		return notFound()
	case 1:
		return success(collectionJSON(found[0], false))
	}
	ids := make([]string, len(found))
	for i, c := range found {
		ids[i] = c.ID
	}
	return multipleResults(ids)
}

func getOrganization(v *profile.Vault, id string) response {
	var found []state.ViewOrganization
	for _, o := range v.Organizations {
		if (isGUID(id) && o.ID == id) || (!isGUID(id) && strings.TrimSpace(id) != "" && nameContains(o.Name, id)) {
			found = append(found, o)
		}
	}
	switch len(found) {
	case 0:
		return notFound()
	case 1:
		return success(organizationJSON(found[0]))
	}
	ids := make([]string, len(found))
	for i, o := range found {
		ids[i] = o.ID
	}
	return multipleResults(ids)
}

func (a *app) getFingerprint(v *profile.Vault, id string) response {
	var phrase []string
	switch {
	case id == "me":
		if len(v.Profile.PublicKey) == 0 {
			return failure("No public key available for the active user.")
		}
		phrase, _ = gen.FingerprintPhrase(v.AccountID, v.Profile.PublicKey)
	case isGUID(id):
		if key, err := v.UserPublicKey(a.ctx, id); err == nil {
			phrase, _ = gen.FingerprintPhrase(id, key)
		}
	}
	if phrase == nil {
		return notFound()
	}
	return str(strings.Join(phrase, "-"))
}
