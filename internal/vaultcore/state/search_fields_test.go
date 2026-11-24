package state

import (
	"testing"

	"github.com/txchen/govault/internal/vaultcore/api"
)

func fieldVault() map[string]*Cipher {
	org := "org-1"
	return map[string]*Cipher{
		"login": {ID: "login", Type: api.CipherTypeLogin, Name: "Router", Login: &Login{Password: "router-password", TOTP: "JBSWY3DPEHPK3PXP"},
			Fields: []CustomField{
				{Name: "region", Value: "eu-west-zone", Type: fieldText},
				{Name: "managed", Value: "true", Type: fieldBoolean},
				{Name: "api token", Value: "tok-hidden-value", Type: 1},
			}},
		"shared": {ID: "shared", Type: api.CipherTypeLogin, Name: "Shared DB", OrganizationID: &org, HidePassword: true,
			Fields: []CustomField{{Name: "dbhost", Value: "secret-host-name", Type: fieldText}}},
		"card": {ID: "card", Type: api.CipherTypeCard, Name: "Travel card",
			Card: &Card{Brand: "Amex", Number: "378282246310005", Code: "1234", CardholderName: "Jo"}},
		"hidden-card": {ID: "hidden-card", Type: api.CipherTypeCard, Name: "Team card", OrganizationID: &org, HidePassword: true,
			Card: &Card{Brand: "Visa", Number: "4111111111119876"}},
		"ssh": {ID: "ssh", Type: api.CipherTypeSSHKey, Name: "Deploy",
			SSHKey: &SSHKey{PrivateKey: "-----BEGIN PRIVATE KEY-----privkeymaterial", PublicKey: "ssh-ed25519 AAAA", KeyFingerprint: "SHA256:fpsearchable"}},
		"id": {ID: "id", Type: api.CipherTypeIdentity, Name: "Me",
			Identity: &Identity{FirstName: "Ada", MiddleName: "King", LastName: "Lovelace", Company: "Analytical Engines", Email: "ada@engines.example",
				Username: "countess", SSN: "123-45-6789", PassportNumber: "P9876543", LicenseNumber: "L5551234"}},
	}
}

func found(query string) []string {
	var ids []string
	for _, s := range searchCiphers(fieldVault(), query, SearchFilter{}, func(c *Cipher) bool { return c.HidePassword }) {
		ids = append(ids, s.ID)
	}
	return ids
}

// What an item shows is found; what it hides, and its secrets, are not,
// so search cannot be used to test a guess at a hidden value.
func TestSearchFindsShownFieldsAndNoSecrets(t *testing.T) {
	for q, want := range map[string]string{
		"eu-west-zone":      "login",
		"region":            "login",
		"managed":           "login",
		"amex":              "card",
		"0005":              "card",
		"fpsearchable":      "ssh",
		"analytical":        "id",
		"countess":          "id",
		"ada@engines":       "id",
		"ada king lovelace": "id",
	} {
		if got := found(q); len(got) != 1 || got[0] != want {
			t.Errorf("search %q = %v, want [%s]", q, got, want)
		}
	}
	for _, q := range []string{
		"tok-hidden-value", "api token", // a hidden field, name and value
		"router-password", "jbswy3dp", // a password and a TOTP secret
		"secret-host-name", "dbhost", // a field of an item that hides passwords
		"3782822", "1234", // a card's other digits and its code
		"9876",                                // the last four of a card that hides passwords
		"privkeymaterial",                     // an SSH private key
		"123-45-6789", "p9876543", "l5551234", // identity numbers
	} {
		if got := found(q); len(got) != 0 {
			t.Errorf("search %q found %v", q, got)
		}
	}
}
