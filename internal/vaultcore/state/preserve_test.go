package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// sealedFixture is what a newer Bitwarden server or client stores on a
// login and GoVault does not model: values that must come back byte for
// byte on every save under the same key.
type sealedFixture struct {
	passkey       json.RawMessage
	uriChecksum   string
	sealedLogin   string
	sealedTop     string
	sealedHistory string
}

func mustEncString(t *testing.T, plain string, key *crypto.SymmetricKey) string {
	t.Helper()
	enc, err := crypto.EncryptString(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func checksumPlain(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// seedSealedLogin replaces c-1 (encrypted with its own cipher key) with a
// login carrying a passkey, autofillOnPageLoad, a URI checksum and unknown
// fields at every nested level.
func seedSealedLogin(t *testing.T, env *vaultTestEnv) sealedFixture {
	t.Helper()
	k := env.cipherKey
	e := func(s string) string { return mustEncString(t, s, k) }
	fx := sealedFixture{
		uriChecksum:   e(checksumPlain("https://github.com")),
		sealedLogin:   e("future login secret"),
		sealedTop:     e("future cipher secret"),
		sealedHistory: e("future history secret"),
	}
	fx.passkey = json.RawMessage(fmt.Sprintf(
		`{"credentialId":%q,"keyType":%q,"keyAlgorithm":%q,"keyCurve":%q,"keyValue":%q,"rpId":%q,"userHandle":%q,"userName":%q,"counter":%q,"rpName":%q,"userDisplayName":%q,"discoverable":%q,"creationDate":"2026-03-14T10:22:00.000Z","futurePasskeyField":1}`,
		e("cred-id-1"), e("public-key"), e("ECDSA"), e("P-256"), e("private-key-material"), e("github.com"),
		e("user-handle"), e("alice"), e("0"), e("GitHub"), e("Alice"), e("true")))

	env.mu.Lock()
	defer env.mu.Unlock()
	c := env.ciphers["c-1"]
	var login api.EncryptedLogin
	loginJSON := fmt.Sprintf(`{"username":%q,"password":%q,"totp":null,"uris":[{"uri":%q,"match":null,"uriChecksum":%q,"futureUriField":7}],"fido2Credentials":[%s],"autofillOnPageLoad":true,"futureLoginField":{"nested":"plain"},"sealedLoginField":%q}`,
		*c.Login.Username, *c.Login.Password, *c.Login.URIs[0].URI, fx.uriChecksum, fx.passkey, fx.sealedLogin)
	if err := json.Unmarshal([]byte(loginJSON), &login); err != nil {
		t.Fatal(err)
	}
	c.Login = &login
	var field api.EncryptedField
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"name":%q,"value":%q,"type":0,"linkedId":null,"futureFieldField":"keep"}`, e("PIN"), e("1234"))), &field)
	c.Fields = []api.EncryptedField{field}
	var hist api.EncryptedPasswordHistory
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"password":%q,"lastUsedDate":"2025-01-02T03:04:05Z","futureHistoryField":%q}`, e("older-password"), fx.sealedHistory)), &hist)
	c.PasswordHistory = []api.EncryptedPasswordHistory{hist}
	c.Extra = map[string]json.RawMessage{
		"futureCipherField": json.RawMessage(`"plain"`),
		"sealedCipherField": json.RawMessage(fmt.Sprintf("%q", fx.sealedTop)),
	}
	env.ciphers["c-1"] = c
	return fx
}

type jsonObj = map[string]json.RawMessage

func obj(t *testing.T, raw json.RawMessage) jsonObj {
	t.Helper()
	var m jsonObj
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not an object: %s", raw)
	}
	return m
}

func arr(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("not an array: %s", raw)
	}
	return a
}

func sameJSON(t *testing.T, what string, got json.RawMessage, want string) {
	t.Helper()
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s = %s, want %s", what, got, want)
	}
}

func (env *vaultTestEnv) body(t *testing.T) jsonObj {
	t.Helper()
	env.mu.Lock()
	defer env.mu.Unlock()
	return obj(t, env.lastBody)
}

// assertSealedKept checks a save under the original key sent every sealed
// and unknown value back unchanged.
func assertSealedKept(t *testing.T, step string, body jsonObj, fx sealedFixture) {
	t.Helper()
	sameJSON(t, step+": futureCipherField", body["futureCipherField"], `"plain"`)
	sameJSON(t, step+": sealedCipherField", body["sealedCipherField"], fmt.Sprintf("%q", fx.sealedTop))
	login := obj(t, body["login"])
	sameJSON(t, step+": fido2Credentials", login["fido2Credentials"], "["+string(fx.passkey)+"]")
	sameJSON(t, step+": autofillOnPageLoad", login["autofillOnPageLoad"], `true`)
	sameJSON(t, step+": futureLoginField", login["futureLoginField"], `{"nested":"plain"}`)
	sameJSON(t, step+": sealedLoginField", login["sealedLoginField"], fmt.Sprintf("%q", fx.sealedLogin))
	uri := obj(t, arr(t, login["uris"])[0])
	sameJSON(t, step+": uriChecksum", uri["uriChecksum"], fmt.Sprintf("%q", fx.uriChecksum))
	sameJSON(t, step+": futureUriField", uri["futureUriField"], `7`)
	field := obj(t, arr(t, body["fields"])[0])
	sameJSON(t, step+": futureFieldField", field["futureFieldField"], `"keep"`)
	found := false
	for _, h := range arr(t, body["passwordHistory"]) {
		if v, ok := obj(t, h)["futureHistoryField"]; ok {
			sameJSON(t, step+": futureHistoryField", v, fmt.Sprintf("%q", fx.sealedHistory))
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: password history lost its unknown field", step)
	}
}

func TestService_SavesKeepPasskeysAndUnknownNestedFields(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	c, err := svc.GetCipher("c-1")
	if err != nil || c.Login == nil || len(c.Login.Fido2Credentials) != 1 {
		t.Fatalf("GetCipher = %+v, %v", c, err)
	}
	if p := c.Login.Fido2Credentials[0]; p.RpID != "github.com" || p.RpName != "GitHub" || p.CreationDate != "2026-03-14T10:22:00.000Z" || p.KeyValue != "private-key-material" {
		t.Fatalf("decrypted passkey = %+v", p)
	}

	steps := []struct {
		name   string
		mutate func(c *Cipher)
	}{
		{"edit another field", func(c *Cipher) { c.Name = "GitHub (work)" }},
		{"toggle favorite", func(c *Cipher) { c.Favorite = !c.Favorite }},
		{"change password", func(c *Cipher) { c.Login.Password = "a-new-password" }},
	}
	for _, step := range steps {
		c, err := svc.GetCipher("c-1")
		if err != nil {
			t.Fatal(err)
		}
		step.mutate(c)
		if _, err := svc.SaveCipher(ctx, c); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		assertSealedKept(t, step.name, env.body(t), fx)
	}

	c, _ = svc.GetCipher("c-1")
	if len(c.PasswordHistory) != 2 || c.PasswordHistory[0].Password != "gh-secret" || c.PasswordHistory[1].Password != "older-password" {
		t.Fatalf("history after password change = %+v", c.PasswordHistory)
	}
}

func TestService_URIChecksumKeptOrRecomputed(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)

	c, _ := svc.GetCipher("c-1")
	c.Login.URIs[0].URI = "https://github.com/login"
	c.Login.URIs = append(c.Login.URIs, LoginURI{URI: "https://gist.github.com"})
	if _, err := svc.SaveCipher(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	uris := arr(t, obj(t, env.body(t)["login"])["uris"])
	for i, want := range []string{"https://github.com/login", "https://gist.github.com"} {
		u := obj(t, uris[i])
		var cs string
		_ = json.Unmarshal(u["uriChecksum"], &cs)
		if cs == fx.uriChecksum {
			t.Fatalf("uri %d kept the checksum of the old text", i)
		}
		plain, err := crypto.DecryptString(cs, env.cipherKey)
		if err != nil || plain != checksumPlain(want) {
			t.Fatalf("uri %d checksum = (%q, %v), want base64 SHA-256 of %q", i, plain, err, want)
		}
	}
	sameJSON(t, "edited uri futureUriField", obj(t, uris[0])["futureUriField"], `7`)
}

func TestURIChecksumMatchesBitwarden(t *testing.T) {
	key, _ := crypto.GenerateSymmetricKey()
	cs, err := uriChecksum("https://test.com", key)
	if err != nil {
		t.Fatal(err)
	}
	// Vector from bitwarden/sdk-internal, LoginUriView::generate_checksum.
	if plain, err := crypto.DecryptString(*cs, key); err != nil || plain != "OWk2vQvwYD1nhLZdA+ltrpBWbDa2JmHyjUEWxRZSS8w=" {
		t.Fatalf("checksum = (%q, %v)", plain, err)
	}
}

func TestService_KeyChangeDropsSealedValuesOnly(t *testing.T) {
	env := newVaultTestEnv(t)
	fx := seedSealedLogin(t, env)
	svc := loggedInTestService(t, env)

	// A copy under another key: c-1 has its own cipher key; the copy is a
	// new personal item encrypted with the user key.
	c, _ := svc.GetCipher("c-1")
	c.ID, c.Key, c.Name = "", nil, "GitHub (Copy)"
	if _, err := svc.SaveCipher(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	body := env.body(t)
	login := obj(t, body["login"])
	if _, ok := login["fido2Credentials"]; ok {
		t.Fatal("a passkey sealed with the old key was sent with a copy")
	}
	for _, k := range []string{"sealedLoginField"} {
		if _, ok := login[k]; ok {
			t.Fatalf("login %s sealed with the old key was sent", k)
		}
	}
	if _, ok := body["sealedCipherField"]; ok {
		t.Fatal("cipher field sealed with the old key was sent")
	}
	sameJSON(t, "plaintext autofillOnPageLoad", login["autofillOnPageLoad"], `true`)
	sameJSON(t, "plaintext futureLoginField", login["futureLoginField"], `{"nested":"plain"}`)
	sameJSON(t, "plaintext futureCipherField", body["futureCipherField"], `"plain"`)
	uri := obj(t, arr(t, login["uris"])[0])
	sameJSON(t, "plaintext futureUriField", uri["futureUriField"], `7`)
	var cs string
	_ = json.Unmarshal(uri["uriChecksum"], &cs)
	if cs == fx.uriChecksum {
		t.Fatal("old-key URI checksum sent with a copy")
	}
	if plain, err := crypto.DecryptString(cs, env.userKey); err != nil || plain != checksumPlain("https://github.com") {
		t.Fatalf("copy checksum under the new key = (%q, %v)", plain, err)
	}
	for _, h := range arr(t, body["passwordHistory"]) {
		if _, ok := obj(t, h)["futureHistoryField"]; ok {
			t.Fatal("password history field sealed with the old key was sent")
		}
	}
}

func TestService_OtherTypesKeepUnknownFields(t *testing.T) {
	env := newVaultTestEnv(t)
	k := env.userKey
	e := func(s string) string { return mustEncString(t, s, k) }
	sealed := e("future secret")
	rev := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	nested := func(known string) string {
		return fmt.Sprintf(`{%s"futurePlain":"keep","futureSealed":%q}`, known, sealed)
	}
	items := map[string]struct {
		t    api.CipherType
		json string
		key  string
	}{
		"c-card":     {api.CipherTypeCard, nested(fmt.Sprintf(`"cardholderName":%q,"brand":null,"number":%q,"expMonth":null,"expYear":null,"code":null,`, e("Alice"), e("4111"))), "card"},
		"c-identity": {api.CipherTypeIdentity, nested(fmt.Sprintf(`"firstName":%q,"address2":%q,`, e("Alice"), e("Apt 4"))), "identity"},
		"c-note":     {api.CipherTypeSecureNote, nested(`"type":0,`), "secureNote"},
		"c-ssh":      {api.CipherTypeSSHKey, nested(fmt.Sprintf(`"privateKey":%q,"publicKey":%q,"keyFingerprint":%q,`, e("priv"), e("pub"), e("SHA256:x"))), "sshKey"},
	}
	env.mu.Lock()
	for id, it := range items {
		raw := fmt.Sprintf(`{"id":%q,"type":%d,"name":%q,"revisionDate":%q,%q:%s}`, id, it.t, e("Item "+id), rev.Format(time.RFC3339), it.key, it.json)
		var c api.EncryptedCipher
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		env.ciphers[id] = c
	}
	env.mu.Unlock()
	svc := loggedInTestService(t, env)

	for id, it := range items {
		c, err := svc.GetCipher(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		c.Name = "Renamed " + id
		if _, err := svc.SaveCipher(context.Background(), c); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		part := obj(t, env.body(t)[it.key])
		sameJSON(t, id+" futurePlain", part["futurePlain"], `"keep"`)
		sameJSON(t, id+" futureSealed", part["futureSealed"], fmt.Sprintf("%q", sealed))
	}
	if c, _ := svc.GetCipher("c-identity"); c.Identity.Address2 != "Apt 4" {
		t.Fatalf("identity address2 = %q", c.Identity.Address2)
	}
}

func TestService_ImportedPasskeyIsSealedWithTheNewItemKey(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	_, err := svc.SaveCipher(context.Background(), &Cipher{Type: api.CipherTypeLogin, Name: "Imported", Login: &Login{
		Username:         "alice",
		Fido2Credentials: []Fido2Credential{{CredentialID: "cred-1", KeyValue: "private-key", RpID: "example.com", CreationDate: "2026-03-14T10:22:00Z"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	pk := obj(t, arr(t, obj(t, env.body(t)["login"])["fido2Credentials"])[0])
	sameJSON(t, "creationDate stays plaintext", pk["creationDate"], `"2026-03-14T10:22:00Z"`)
	for field, want := range map[string]string{"credentialId": "cred-1", "keyValue": "private-key", "rpId": "example.com"} {
		var enc string
		_ = json.Unmarshal(pk[field], &enc)
		if got, err := crypto.DecryptString(enc, env.userKey); err != nil || got != want {
			t.Fatalf("%s = (%q, %v), want %q sealed with the item key", field, got, err, want)
		}
	}
}
