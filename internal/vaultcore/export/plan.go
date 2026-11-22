package export

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/state"
)

type Class int

const (
	ClassNew Class = iota
	ClassConflict
	ClassIdentical
)

type Action int

const (
	ActionSkip Action = iota
	ActionCreate
	ActionUpdate
)

// Entry is one backup item compared with the vault. Nothing is written until
// Apply runs, and only as Action says.
type Entry struct {
	Item       Item
	FolderName string
	Class      Class
	// Match is the vault item the backup item corresponds to, for conflicts
	// and identical items.
	Match *state.Cipher
	// Diff names the fields that differ, never their values.
	Diff      []string
	CanUpdate bool
	// UpdateBlocked says why Update is not offered for a backup item that
	// cannot safely update its match, if that is the reason.
	UpdateBlocked string
	Action        Action
}

// Allowed lists the actions the entry may take.
func (e *Entry) Allowed() []Action {
	switch {
	case e.Class == ClassNew:
		return []Action{ActionCreate, ActionSkip}
	case e.CanUpdate:
		return []Action{ActionSkip, ActionCreate, ActionUpdate}
	default:
		return []Action{ActionSkip, ActionCreate}
	}
}

// SetAction applies a if the entry allows it.
func (e *Entry) SetAction(a Action) bool {
	if !slices.Contains(e.Allowed(), a) {
		return false
	}
	e.Action = a
	return true
}

type Plan struct {
	Entries []Entry
}

type Counts struct {
	New, Conflicts, Identical int
	Create, Update, Skip      int
}

func (p *Plan) Counts() Counts {
	var c Counts
	for _, e := range p.Entries {
		switch e.Class {
		case ClassNew:
			c.New++
		case ClassConflict:
			c.Conflicts++
		case ClassIdentical:
			c.Identical++
		}
		switch e.Action {
		case ActionCreate:
			c.Create++
		case ActionUpdate:
			c.Update++
		default:
			c.Skip++
		}
	}
	return c
}

func itemKey(t int, name, username string) string {
	return fmt.Sprintf("%d\x00%s\x00%s", t, strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(username))
}

func cipherUsername(c *state.Cipher) string {
	if c.Login != nil {
		return c.Login.Username
	}
	return ""
}

// BuildPlan compares the backup with the active vault items. A backup item
// matches a vault item with the same ID, or else the same type, name and
// username. New items default to Create; conflicts and identical items
// default to Skip, so nothing in the vault changes unless the user asks.
func BuildPlan(backup *Vault, current []*state.Cipher, folders []state.Folder) *Plan {
	backupFolders := map[string]string{}
	for _, f := range backup.Folders {
		backupFolders[f.ID] = f.Name
	}
	currentFolders := map[string]string{}
	for _, f := range folders {
		currentFolders[f.ID] = f.Name
	}
	byID := map[string]*state.Cipher{}
	byKey := map[string][]*state.Cipher{}
	for _, c := range current {
		if c == nil || c.DeletedDate != nil {
			continue
		}
		byID[c.ID] = c
		k := itemKey(int(c.Type), c.Name, cipherUsername(c))
		byKey[k] = append(byKey[k], c)
	}
	used := map[string]bool{}

	p := &Plan{}
	for _, it := range backup.Items {
		if it.DeletedDate != nil {
			continue
		}
		e := Entry{Item: it, FolderName: backupFolders[val(it.FolderID)]}
		match := byID[it.ID]
		if match == nil || used[match.ID] || match.Type != it.Type {
			match = nil
			username := ""
			if it.Login != nil {
				username = val(it.Login.Username)
			}
			for _, c := range byKey[itemKey(int(it.Type), it.Name, username)] {
				if !used[c.ID] {
					match = c
					break
				}
			}
		}
		if match == nil {
			e.Class, e.Action = ClassNew, ActionCreate
		} else {
			used[match.ID] = true
			e.Match = match
			e.Diff = diff(it, e.FolderName, match, currentFolders[val(match.FolderID)])
			e.CanUpdate = !match.ReadOnly && !match.HidePassword
			switch probe := *match; {
			case !e.CanUpdate:
			case !it.complete():
				e.CanUpdate, e.UpdateBlocked = false, "the backup item is incomplete"
			case mergeContent(&probe, it) != nil:
				e.CanUpdate, e.UpdateBlocked = false, "its fields or websites cannot be matched safely"
			}
			e.Class, e.Action = ClassIdentical, ActionSkip
			if len(e.Diff) > 0 {
				e.Class = ClassConflict
			}
		}
		p.Entries = append(p.Entries, e)
	}
	return p
}

func diff(it Item, folderName string, c *state.Cipher, currentFolder string) []string {
	want := it.content()
	var out []string
	add := func(label string, differ bool) {
		if differ {
			out = append(out, label)
		}
	}
	add("Name", want.Name != c.Name)
	add("Notes", want.Notes != c.Notes)
	add("Folder", !strings.EqualFold(folderName, currentFolder))
	add("Favorite", want.Favorite != c.Favorite)
	add("Reprompt", want.Reprompt != c.Reprompt)
	if want.Login != nil || c.Login != nil {
		a, b := want.Login, c.Login
		if a == nil {
			a = &state.Login{}
		}
		if b == nil {
			b = &state.Login{}
		}
		add("Username", a.Username != b.Username)
		add("Password", a.Password != b.Password)
		add("Verification Code", a.TOTP != b.TOTP)
		add("Websites", !slices.Equal(uriList(a), uriList(b)))
	}
	if want.Login != nil && c.Login != nil && len(want.Login.Fido2Credentials) > 0 {
		add("Passkey", !samePasskeys(want.Login.Fido2Credentials, c.Login.Fido2Credentials))
	}
	add("Card", ptrDiff(cardContentOf(want.Card), cardContentOf(c.Card)))
	add("Identity", ptrDiff(identityContentOf(want.Identity), identityContentOf(c.Identity)))
	add("SSH Key", ptrDiff(sshKeyContentOf(want.SSHKey), sshKeyContentOf(c.SSHKey)))
	add("Custom Fields", !slices.EqualFunc(want.Fields, c.Fields, func(x, y state.CustomField) bool {
		return x.Name == y.Name && x.Value == y.Value && x.Type == y.Type
	}))
	return out
}

// samePasskeys compares passkeys by credential and relying party, never by
// their secret material.
func samePasskeys(a, b []state.Fido2Credential) bool {
	return slices.EqualFunc(a, b, func(x, y state.Fido2Credential) bool {
		return x.CredentialID == y.CredentialID && x.RpID == y.RpID
	})
}

// The content types reduce nested items to what the user sees, so the diff
// ignores the unknown fields the server stores with them.
type cardContent struct {
	CardholderName, Brand, Number, ExpMonth, ExpYear, Code string
}

type identityContent struct {
	Title, FirstName, MiddleName, LastName, Address1, Address2, Address3, City, State,
	PostalCode, Country, Company, Email, Phone, SSN, Username, PassportNumber, LicenseNumber string
}

type sshKeyContent struct {
	PrivateKey, PublicKey, KeyFingerprint string
}

func cardContentOf(t *state.Card) *cardContent {
	if t == nil {
		return nil
	}
	return &cardContent{t.CardholderName, t.Brand, t.Number, t.ExpMonth, t.ExpYear, t.Code}
}

func identityContentOf(t *state.Identity) *identityContent {
	if t == nil {
		return nil
	}
	return &identityContent{t.Title, t.FirstName, t.MiddleName, t.LastName, t.Address1, t.Address2, t.Address3,
		t.City, t.State, t.PostalCode, t.Country, t.Company, t.Email, t.Phone, t.SSN, t.Username, t.PassportNumber, t.LicenseNumber}
}

func sshKeyContentOf(t *state.SSHKey) *sshKeyContent {
	if t == nil {
		return nil
	}
	return &sshKeyContent{t.PrivateKey, t.PublicKey, t.KeyFingerprint}
}

func uriList(l *state.Login) []string {
	out := make([]string, len(l.URIs))
	for i, u := range l.URIs {
		out[i] = u.URI
	}
	return out
}

func ptrDiff[T comparable](a, b *T) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil || b == nil:
		var zero T
		if a == nil {
			return *b != zero
		}
		return *a != zero
	}
	return *a != *b
}

// Writer is what Apply needs from the vault.
type Writer interface {
	GetCipher(id string) (*state.Cipher, error)
	SaveCipher(ctx context.Context, c *state.Cipher) (*state.Cipher, error)
	Folders() []state.Folder
	SaveFolder(ctx context.Context, f *state.Folder) (*state.Folder, error)
}

type Result struct {
	Created, Updated, Skipped, Failed int
	Err                               error
	// LocalCopyErr reports changes the server accepted (and that are
	// counted as created or updated) but GoVault could not write to its
	// encrypted local copy. They must not be retried; a sync refreshes
	// the local copy.
	LocalCopyErr error
}

// Apply carries out exactly the actions chosen in p. Folders the approved
// items need are reused by name or created. Updates keep the vault item's
// identity, organization and attachments and replace its content.
func Apply(ctx context.Context, w Writer, p *Plan) Result {
	var res Result
	var errs, local []error
	// done splits err into a committed change, whose local copy may have
	// failed, and a real failure.
	done := func(name string, err error) bool {
		var lc *state.LocalCopyError
		if errors.As(err, &lc) {
			local = append(local, fmt.Errorf("%s: %w", name, err))
			return true
		}
		return err == nil
	}
	folderIDs := map[string]string{}
	for _, f := range w.Folders() {
		key := strings.ToLower(f.Name)
		if _, ok := folderIDs[key]; !ok {
			folderIDs[key] = f.ID
		}
	}
	folderFor := func(name string) (*string, error) {
		if strings.TrimSpace(name) == "" {
			return nil, nil
		}
		key := strings.ToLower(name)
		if id, ok := folderIDs[key]; ok {
			return &id, nil
		}
		f, err := w.SaveFolder(ctx, &state.Folder{Name: name})
		if !done("folder "+name, err) {
			return nil, err
		}
		folderIDs[key] = f.ID
		return &f.ID, nil
	}

	for i := range p.Entries {
		e := &p.Entries[i]
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			res.Failed++
			continue
		}
		var err error
		switch e.Action {
		case ActionCreate:
			if err = createItem(ctx, w, e, folderFor); done(e.Item.Name, err) {
				res.Created++
				continue
			}
		case ActionUpdate:
			if err = updateItem(ctx, w, e, folderFor); done(e.Item.Name, err) {
				res.Updated++
				continue
			}
		default:
			res.Skipped++
			continue
		}
		res.Failed++
		errs = append(errs, fmt.Errorf("%s: %w", e.Item.Name, err))
	}
	res.Err = errors.Join(errs...)
	res.LocalCopyErr = errors.Join(local...)
	return res
}

func createItem(ctx context.Context, w Writer, e *Entry, folderFor func(string) (*string, error)) error {
	c := e.Item.content()
	if e.Class != ClassNew && c.Login != nil {
		// Create Copy: a passkey belongs to one item and is never copied.
		c.Login.Fido2Credentials = nil
	}
	folder, err := folderFor(e.FolderName)
	if err != nil {
		return err
	}
	c.FolderID = folder
	_, err = w.SaveCipher(ctx, c)
	return err
}

func updateItem(ctx context.Context, w Writer, e *Entry, folderFor func(string) (*string, error)) error {
	if e.Match == nil || !e.CanUpdate {
		return state.ErrReadOnlyCipher
	}
	cur, err := w.GetCipher(e.Match.ID)
	if err != nil {
		return err
	}
	if cur.ReadOnly || cur.HidePassword || cur.DeletedDate != nil || cur.Type != e.Item.Type || !e.Item.complete() {
		return state.ErrReadOnlyCipher
	}
	folder, err := folderFor(e.FolderName)
	if err != nil {
		return err
	}
	cur.Name = e.Item.Name
	cur.Notes = val(e.Item.Notes)
	cur.Favorite = e.Item.Favorite
	cur.Reprompt = e.Item.Reprompt
	cur.FolderID = folder
	if err := mergeContent(cur, e.Item); err != nil {
		return err
	}
	_, err = w.SaveCipher(ctx, cur)
	return err
}
