package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

func itemOf(t *testing.T, out string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return m
}

func loginOf(t *testing.T, out string) map[string]any {
	t.Helper()
	l, _ := itemOf(t, out)["login"].(map[string]any)
	return l
}

// A collection that hides passwords hides them from reads and write
// responses alike, though the item's own flags allow them, and an edit
// that sends the hidden values back blank keeps them.
func TestCollectionHidesPasswordsForReadsAndWrites(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) { c.EngHidesPasswords = true })
	g.login()
	item := g.mustRun("get", "item", fakeserver.ItemOrgShared)
	if l := loginOf(t, item); l["password"] != nil || l["totp"] != nil {
		t.Fatalf("read shows a hidden password: %v", l)
	}
	if r := g.run("get", "password", fakeserver.ItemOrgShared); r.code != 1 {
		t.Fatalf("get password = %+v", r)
	}
	edited := strings.Replace(item, `"name":"Shared DB"`, `"name":"Shared DB 2"`, 1)
	out := g.mustRun("edit", "item", fakeserver.ItemOrgShared, b64(edited))
	if l := loginOf(t, out); l["password"] != nil {
		t.Fatalf("the write response shows a hidden password: %v", l)
	}
	g.srv.Configure(func(c *fakeserver.Config) { c.EngHidesPasswords = false })
	g.mustRun("sync", "-f")
	if got := g.mustRun("get", "password", fakeserver.ItemOrgShared); got != "db-secret" {
		t.Fatalf("the edit lost the hidden password: %q", got)
	}
}

// An organization item whose permissions the server omits is hidden for
// writes as for reads.
func TestOmittedViewPasswordHidesForWrites(t *testing.T) {
	g := newGV(t)
	g.srv.Mutate(fakeserver.ItemOrgShared, func(it map[string]any, _, _ func(string) any) { delete(it, "viewPassword") })
	g.login()
	item := g.mustRun("get", "item", fakeserver.ItemOrgShared)
	if loginOf(t, item)["password"] != nil {
		t.Fatal("read shows the password")
	}
	out := g.mustRun("edit", "item", fakeserver.ItemOrgShared, b64(item))
	if loginOf(t, out)["password"] != nil {
		t.Fatal("the write response shows the password")
	}
	g.srv.Mutate(fakeserver.ItemOrgShared, func(it map[string]any, _, _ func(string) any) { it["viewPassword"] = true })
	g.mustRun("sync", "-f")
	if got := g.mustRun("get", "password", fakeserver.ItemOrgShared); got != "db-secret" {
		t.Fatalf("password after the edit = %q", got)
	}
}

// The item's own flags hide it in a collection that does not.
func TestItemFlagHidesInAVisibleCollection(t *testing.T) {
	g := newGV(t)
	g.srv.Mutate(fakeserver.ItemOrgHidden, func(it map[string]any, _, _ func(string) any) {
		it["collectionIds"] = []string{fakeserver.CollectionEng}
	})
	g.login()
	if loginOf(t, g.mustRun("get", "item", fakeserver.ItemOrgHidden))["password"] != nil {
		t.Fatal("the item flag did not hide the password")
	}
}

// Hidden items do not print private key material, and an edit keeps it.
func TestHiddenItemsRedactPrivateKeys(t *testing.T) {
	g := newGV(t)
	const private = "-----BEGIN OPENSSH PRIVATE KEY-----\nORG\n-----END OPENSSH PRIVATE KEY-----\n"
	g.srv.Mutate(fakeserver.ItemOrgHidden, func(it map[string]any, org, _ func(string) any) {
		it["edit"] = true
		it["collectionIds"] = []string{fakeserver.CollectionEng}
		it["login"].(map[string]any)["fido2Credentials"] = []map[string]any{{
			"credentialId": org("cred-1"), "keyType": org("public-key"), "keyAlgorithm": org("ECDSA"), "keyCurve": org("P-256"),
			"keyValue": org("passkey-private"), "rpId": org("example.com"), "userHandle": org("uh"), "userName": org("root"),
			"counter": org("0"), "rpName": org("Example"), "userDisplayName": org("Root"), "discoverable": org("true"),
			"creationDate": "2026-01-02T03:04:05.000Z",
		}}
	})
	g.srv.Mutate(fakeserver.ItemOrgShared, func(it map[string]any, org, _ func(string) any) {
		it["type"], it["login"], it["viewPassword"] = 5, nil, false
		it["sshKey"] = map[string]any{"privateKey": org(private), "publicKey": org("ssh-ed25519 AAAA org"), "keyFingerprint": org("SHA256:org")}
	})
	g.login()
	for _, out := range []string{g.mustRun("get", "item", fakeserver.ItemOrgShared), g.mustRun("list", "items", "--search", "Shared")} {
		if strings.Contains(out, "PRIVATE KEY") {
			t.Fatalf("a hidden SSH private key was printed: %s", out)
		}
	}
	ssh := g.mustRun("get", "item", fakeserver.ItemOrgShared)
	if strings.Contains(g.mustRun("edit", "item", fakeserver.ItemOrgShared, b64(ssh)), "PRIVATE KEY") {
		t.Fatal("the write response printed the private key")
	}
	passkey := g.mustRun("get", "item", fakeserver.ItemOrgHidden)
	if strings.Contains(passkey, "passkey-private") || !strings.Contains(passkey, `"keyValue":null`) {
		t.Fatalf("a hidden passkey key was printed: %s", passkey)
	}
	g.mustRun("edit", "item", fakeserver.ItemOrgHidden, b64(passkey))

	for _, id := range []string{fakeserver.ItemOrgShared, fakeserver.ItemOrgHidden} {
		g.srv.Mutate(id, func(it map[string]any, _, _ func(string) any) { it["viewPassword"] = true })
	}
	g.mustRun("sync", "-f")
	if !strings.Contains(g.mustRun("get", "item", fakeserver.ItemOrgShared), "ORG") {
		t.Fatal("the edit lost the SSH private key")
	}
	if !strings.Contains(g.mustRun("get", "item", fakeserver.ItemOrgHidden), `"keyValue":"passkey-private"`) {
		t.Fatal("the edit lost the passkey key")
	}
}

// An edit made from a read that predates a change synced since is
// refused, as is one naming another item.
func TestEditRefusesAStaleReadAfterASync(t *testing.T) {
	g := newGV(t)
	g.login()
	read := g.mustRun("get", "item", fakeserver.ItemGitHubEnt)
	g.srv.Mutate(fakeserver.ItemGitHubEnt, func(it map[string]any, _, personal func(string) any) {
		it["notes"] = personal("changed elsewhere")
	})
	g.mustRun("sync", "-f")
	stale := strings.Replace(read, `"favorite":false`, `"favorite":true`, 1)
	r := g.run("edit", "item", fakeserver.ItemGitHubEnt, b64(stale))
	if r.code != 1 || !strings.Contains(r.err, "changed after the input was read") {
		t.Fatalf("stale edit = %+v", r)
	}
	if got := g.mustRun("get", "notes", fakeserver.ItemGitHubEnt); got != "changed elsewhere" {
		t.Fatalf("notes = %q", got)
	}
	fresh := g.mustRun("get", "item", fakeserver.ItemGitHubEnt)
	if r := g.run("edit", "item", fakeserver.ItemGitHub, b64(fresh)); r.code != 1 || !strings.Contains(r.err, "The item in the input is") {
		t.Fatalf("edit naming another item = %+v", r)
	}
	g.mustRun("edit", "item", fakeserver.ItemGitHubEnt, b64(strings.Replace(fresh, `"favorite":false`, `"favorite":true`, 1)))
}
