package cli

// templates are bw's `get template` objects, in its key order.
var templates = map[string]any{
	"item": obj{}.set("type", 1).set("favorite", false).set("reprompt", 0).set("name", "Item name").
		set("notes", "Some notes about this item.").set("fields", []any{}).set("passwordHistory", []any{}),
	"item.field":     obj{}.set("type", 0).set("name", "Field name").set("value", "Some value"),
	"item.login":     obj{}.set("uris", []any{}).set("username", "jdoe").set("password", "myp@ssword123").set("totp", "JBSWY3DPEHPK3PXP").set("fido2Credentials", []any{}),
	"item.login.uri": obj{}.set("uri", "https://google.com"),
	"item.card": obj{}.set("cardholderName", "John Doe").set("brand", "visa").set("number", "4242424242424242").
		set("expMonth", "04").set("expYear", "2023").set("code", "123"),
	"item.identity": obj{}.set("title", "Mr").set("firstName", "John").set("middleName", "William").set("lastName", "Doe").
		set("address1", "123 Any St").set("address2", "Apt #123").set("city", "New York").set("state", "NY").
		set("postalCode", "10001").set("country", "US").set("company", "Acme Inc.").set("email", "john@company.com").
		set("phone", "5555551234").set("ssn", "000-123-4567").set("username", "jdoe").
		set("passportNumber", "US-123456789").set("licenseNumber", "D123-12-123-12333"),
	"item.securenote":  obj{}.set("type", 0),
	"folder":           obj{}.set("name", "Folder name"),
	"collection":       collectionTemplate(),
	"item-collections": []any{"collection-id1", "collection-id2"},
	"org-collection": collectionTemplate().set("groups", []any{selection(), selection()}).
		set("users", []any{selection(), selection()}),
}

const emptyGUID = "00000000-0000-0000-0000-000000000000"

func collectionTemplate() obj {
	return obj{}.set("organizationId", emptyGUID).set("name", "Collection name").set("externalId", nil)
}

func selection() obj {
	return obj{}.set("id", emptyGUID).set("readOnly", false).set("hidePasswords", false).set("manage", false)
}

func templateAliases(id string) string {
	switch id {
	case "my-folder":
		return "folder"
	case "shared-folder":
		return "collection"
	case "item-shared-folders":
		return "item-collections"
	case "org-shared-folder":
		return "org-collection"
	}
	return id
}
