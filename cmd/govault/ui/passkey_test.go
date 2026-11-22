package ui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// passkeyLogin is c-github as a server stores it with a passkey and the
// fields GoVault does not show.
func passkeyLogin(svc *mockVaultService) *state.Cipher {
	match := 3
	cs := "2.checksum|of|uri"
	c := svc.ciphers["c-github"]
	c.SealedKeyID = "key-1"
	c.Extra = map[string]json.RawMessage{"futureCipherField": json.RawMessage(`"plain"`)}
	c.Login.Extra = map[string]json.RawMessage{"autofillOnPageLoad": json.RawMessage(`true`)}
	c.Login.URIs[0].Match = &match
	c.Login.URIs[0].Checksum, c.Login.URIs[0].ChecksumOf = &cs, c.Login.URIs[0].URI
	c.Login.URIs[0].Extra = map[string]json.RawMessage{"futureUriField": json.RawMessage(`7`)}
	c.Login.Fido2Credentials = []state.Fido2Credential{{RpID: "github.com", CreationDate: "2026-03-14T10:22:00Z", Sealed: json.RawMessage(`{"credentialId":"2.sealed"}`)}}
	linked := 2
	c.Fields = []state.CustomField{{Name: "PIN", Value: "1", Type: 1, LinkedID: &linked, Extra: map[string]json.RawMessage{"futureFieldField": json.RawMessage(`"keep"`)}}}
	return c
}

func TestEditorKeepsWhatItDoesNotShow(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	c := passkeyLogin(svc)
	d := draftFromCipher(c)
	d.Name, d.Password = "GitHub (work)", "changed"
	d.URIs = append(d.URIs, EditURIDraft{URI: "https://gist.github.com"})
	out := cipherFromDraft(d)

	if out.Name != "GitHub (work)" || out.Login.Password != "changed" || out.SealedKeyID != "key-1" {
		t.Fatalf("edit not applied: %+v", out)
	}
	if string(out.Extra["futureCipherField"]) != `"plain"` || string(out.Login.Extra["autofillOnPageLoad"]) != `true` {
		t.Fatal("unknown fields lost")
	}
	if len(out.Login.Fido2Credentials) != 1 || string(out.Login.Fido2Credentials[0].Sealed) != `{"credentialId":"2.sealed"}` {
		t.Fatalf("passkey lost: %+v", out.Login.Fido2Credentials)
	}
	u := out.Login.URIs[0]
	if u.Match == nil || *u.Match != 3 || u.Checksum == nil || u.ChecksumOf != u.URI || string(u.Extra["futureUriField"]) != `7` {
		t.Fatalf("URI lost its match, checksum or fields: %+v", u)
	}
	if added := out.Login.URIs[1]; added.URI != "https://gist.github.com" || added.Checksum != nil {
		t.Fatalf("added URI = %+v", added)
	}
	f := out.Fields[0]
	if f.LinkedID == nil || *f.LinkedID != 2 || string(f.Extra["futureFieldField"]) != `"keep"` {
		t.Fatalf("field lost its linked id or fields: %+v", f)
	}

	id := &state.Cipher{ID: "c-id", Type: api.CipherTypeIdentity, Name: "Me", Identity: &state.Identity{FirstName: "Alice", Address2: "Apt 4", Address3: "Floor 2", Extra: map[string]json.RawMessage{"x": json.RawMessage(`1`)}}}
	idd := draftFromCipher(id)
	idd.FirstName = "Alicia"
	if got := cipherFromDraft(idd).Identity; got.FirstName != "Alicia" || got.Address2 != "Apt 4" || got.Address3 != "Floor 2" || string(got.Extra["x"]) != `1` {
		t.Fatalf("identity edit lost hidden fields: %+v", got)
	}
}

func TestPasskeyShownAndRemovedOnlyOnSave(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	answers := []int{0, 1}
	app.OnAlert = func(core.AlertConfig) int { a := answers[0]; answers = answers[1:]; return a }

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-passkey", 2*time.Second)
	if !app.Exists("id:detail-view >> text:github.com · Created Mar 14, 2026") {
		t.Fatal("passkey row does not show the site and creation date")
	}

	app.Press("id:detail-edit")
	app.WaitFor("id:editor-passkey-remove", 2*time.Second)
	app.Press("id:editor-passkey-remove")
	app.Settle()
	if m.EditDraft.Get().RemovePasskey || !app.Exists("id:editor-passkey") {
		t.Fatal("cancelling the dialog removed the passkey")
	}
	app.Press("id:editor-passkey-remove")
	app.WaitFor("id:editor-passkey-removed", 2*time.Second)
	if c, _ := svc.GetCipher("c-github"); len(c.Login.Fido2Credentials) != 1 {
		t.Fatal("passkey removed before saving")
	}
	app.Press("id:editor-save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })

	c, _ := svc.GetCipher("c-github")
	if len(c.Login.Fido2Credentials) != 0 {
		t.Fatal("saving did not remove the passkey")
	}
	if string(c.Login.Extra["autofillOnPageLoad"]) != `true` || c.Login.URIs[0].Checksum == nil || string(c.Fields[0].Extra["futureFieldField"]) != `"keep"` || string(c.Extra["futureCipherField"]) != `"plain"` {
		t.Fatalf("removing the passkey changed other fields: %+v", c.Login)
	}
}

func TestLeavingEditorKeepsPasskey(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.OnAlert = func(cfg core.AlertConfig) int { return 1 }

	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-edit", 2*time.Second)
	app.Press("id:detail-edit")
	app.WaitFor("id:editor-passkey-remove", 2*time.Second)
	app.Press("id:editor-passkey-remove")
	app.WaitFor("id:editor-passkey-removed", 2*time.Second)
	app.Press("id:editor-cancel")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })
	if c, _ := svc.GetCipher("c-github"); len(c.Login.Fido2Credentials) != 1 {
		t.Fatal("leaving the editor without saving removed the passkey")
	}
}

func TestCloneDoesNotCopyPasskey(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	passkeyLogin(svc)
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SelectCipher(root, "c-github") })
	app.WaitFor("id:detail-clone", 2*time.Second)
	app.Press("id:detail-clone")
	app.WaitUntil(2*time.Second, func() bool { return m.EditMode.Get() })
	if m.EditDraft.Get().DraftPasskey() != nil || app.Exists("id:editor-passkey") {
		t.Fatal("clone editor offers the passkey")
	}
	app.Press("id:editor-save")
	app.WaitUntil(2*time.Second, func() bool { return !m.EditMode.Get() })
	cp, err := svc.GetCipher("c-new")
	if err != nil || len(cp.Login.Fido2Credentials) != 0 || !strings.HasSuffix(cp.Name, "(Copy)") {
		t.Fatalf("clone = %+v, %v", cp, err)
	}
	if orig, _ := svc.GetCipher("c-github"); len(orig.Login.Fido2Credentials) != 1 {
		t.Fatal("clone changed the original passkey")
	}
}
