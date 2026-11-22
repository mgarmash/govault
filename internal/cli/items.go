package cli

import (
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// The projections below reproduce bw 2026.11's response classes field for
// field, in its key order: CipherResponse over CipherWithIdExport and
// LoginResponse, FolderResponse, CollectionResponse and
// OrganizationResponse. Fields bw leaves undefined are omitted; the item
// key is never printed.

const fieldTypeHidden = 1

// itemJSON projects a decrypted item. Hidden passwords blank the password,
// TOTP secret and hidden field values and drop the password history.
func itemJSON(c *state.Cipher, typeData map[string]any) obj {
	hide := c.HidePassword
	o := obj{}.
		set("type", int(c.Type)).
		set("favorite", c.Favorite).
		set("reprompt", c.Reprompt).
		set("id", c.ID).
		set("collectionIds", stringList(c.CollectionIDs)).
		set("object", "item")
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		o = o.set("organizationId", *c.OrganizationID)
	}
	if c.FolderID != nil && *c.FolderID != "" {
		o = o.set("folderId", *c.FolderID)
	}
	o = o.set("name", c.Name).opt("notes", c.Notes)

	fields := make([]any, 0, len(c.Fields))
	for _, f := range c.Fields {
		fo := obj{}.set("type", f.Type).opt("name", f.Name)
		switch {
		case hide && f.Type == fieldTypeHidden:
			fo = fo.set("value", nil)
		default:
			fo = fo.opt("value", f.Value)
		}
		if f.LinkedID != nil {
			fo = fo.set("linkedId", *f.LinkedID)
		}
		fields = append(fields, fo)
	}
	o = o.set("fields", fields)

	switch c.Type {
	case api.CipherTypeLogin:
		if c.Login != nil {
			o = o.set("login", loginJSON(c.Login, hide))
		}
	case api.CipherTypeSecureNote:
		if c.SecureNote != nil {
			o = o.set("secureNote", obj{}.set("type", c.SecureNote.Type))
		}
	case api.CipherTypeCard:
		if k := c.Card; k != nil {
			o = o.set("card", obj{}.opt("cardholderName", k.CardholderName).opt("brand", k.Brand).opt("number", k.Number).
				opt("expMonth", k.ExpMonth).opt("expYear", k.ExpYear).opt("code", k.Code))
		}
	case api.CipherTypeIdentity:
		if id := c.Identity; id != nil {
			o = o.set("identity", obj{}.opt("title", id.Title).opt("firstName", id.FirstName).opt("middleName", id.MiddleName).
				opt("lastName", id.LastName).opt("address1", id.Address1).opt("address2", id.Address2).opt("address3", id.Address3).
				opt("city", id.City).opt("state", id.State).opt("postalCode", id.PostalCode).opt("country", id.Country).
				opt("company", id.Company).opt("email", id.Email).opt("phone", id.Phone).opt("ssn", id.SSN).
				opt("username", id.Username).opt("passportNumber", id.PassportNumber).opt("licenseNumber", id.LicenseNumber))
		}
	case api.CipherTypeSSHKey:
		if k := c.SSHKey; k != nil {
			// A hidden item's private key stays hidden, as the desktop
			// hides it.
			var private any = k.PrivateKey
			if hide {
				private = nil
			}
			o = o.set("sshKey", obj{}.set("privateKey", private).set("publicKey", k.PublicKey).set("keyFingerprint", k.KeyFingerprint))
		}
	case api.CipherTypeBankAccount:
		o = o.set("bankAccount", typeData)
	case api.CipherTypeDriversLicense:
		o = o.set("driversLicense", typeData)
	case api.CipherTypePassport:
		o = o.set("passport", typeData)
	}

	if !hide {
		history := make([]any, 0, len(c.PasswordHistory))
		for _, h := range c.PasswordHistory {
			history = append(history, obj{}.set("lastUsedDate", jsTime(h.LastUsedDate)).set("password", h.Password))
		}
		o = o.set("passwordHistory", history)
	}
	if c.CreationDate != nil {
		o = o.set("creationDate", jsTime(*c.CreationDate))
	}
	o = o.set("revisionDate", jsTimePtr(c.RevisionDate))
	if c.DeletedDate != nil {
		o = o.set("deletedDate", jsTime(*c.DeletedDate))
	}
	if c.ArchivedDate != nil {
		o = o.set("archivedDate", jsTime(*c.ArchivedDate))
	}
	atts := make([]any, 0, len(c.Attachments))
	for _, at := range c.Attachments {
		atts = append(atts, obj{}.set("id", at.ID).set("fileName", at.FileName).set("size", formatSize(at.Size)).
			set("sizeName", at.SizeName).set("url", at.URL))
	}
	return o.set("attachments", atts)
}

func loginJSON(l *state.Login, hide bool) obj {
	uris := make([]any, 0, len(l.URIs))
	for _, u := range l.URIs {
		uo := obj{}.set("uri", u.URI)
		if u.Match != nil {
			uo = uo.set("match", *u.Match)
		}
		uris = append(uris, uo)
	}
	passkeys := make([]any, 0, len(l.Fido2Credentials))
	for _, f := range l.Fido2Credentials {
		discoverable := f.Discoverable
		if discoverable == "" {
			discoverable = "false"
		}
		var key any = f.KeyValue
		if hide {
			key = nil
		}
		passkeys = append(passkeys, obj{}.set("credentialId", f.CredentialID).set("keyType", f.KeyType).
			set("keyAlgorithm", f.KeyAlgorithm).set("keyCurve", f.KeyCurve).set("keyValue", key).set("rpId", f.RpID).
			opt("userHandle", f.UserHandle).opt("userName", f.UserName).set("counter", f.Counter).opt("rpName", f.RpName).
			opt("userDisplayName", f.UserDisplayName).set("discoverable", discoverable).set("creationDate", f.CreationDate))
	}
	o := obj{}.set("uris", uris).set("fido2Credentials", passkeys).opt("username", l.Username)
	if hide {
		o = o.set("password", nil).set("totp", nil)
	} else {
		o = o.opt("password", l.Password).opt("totp", l.TOTP)
	}
	return o.set("passwordRevisionDate", jsTimePtr(l.PasswordRevisionDate))
}

func formatSize(n int64) string { return itoa(n) }

func stringList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func folderJSON(id, name string) obj {
	return obj{}.set("name", name).set("object", "folder").set("id", id)
}

// collectionJSON prints externalId only when withExternalID: bw shows it
// for collections read by ID and from the server, not for listed ones.
func collectionJSON(c state.ViewCollection, withExternalID bool) obj {
	o := obj{}.set("object", "collection").set("id", c.ID).set("organizationId", c.OrganizationID).set("name", c.Name)
	if withExternalID || c.ExternalID != nil {
		o = o.set("externalId", nullable(c.ExternalID))
	}
	return o
}

func organizationJSON(o state.ViewOrganization) obj {
	return obj{}.set("object", "organization").set("id", o.ID).set("name", o.Name).set("status", o.Status).
		set("type", o.Type).set("enabled", o.Enabled)
}
