package cli

import (
	"encoding/base64"

	"github.com/txchen/govault/internal/fakeserver"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func init() { contractCases = append(contractCases, writeCases...) }

const (
	// IDs the fake server gives new objects, in order.
	newID1 = "b0000001-0000-4000-8000-000000000001"
	newID2 = "b0000002-0000-4000-8000-000000000002"
)

var (
	newLoginJSON = `{"type":1,"name":"New login","notes":"made by a contract test","favorite":true,"folderId":"` + fakeserver.FolderWork + `",` +
		`"fields":[{"name":"plain","value":"text","type":0},{"name":"secret","value":"s3","type":1}],` +
		`"login":{"uris":[{"uri":"https://new.example.com","match":null},{"uri":"https://alt.example.com","match":3}],"username":"newuser","password":"newpass","totp":"JBSWY3DPEHPK3PXP"},"reprompt":0}`
	newNoteJSON = `{"type":2,"name":"New note","notes":"body","secureNote":{"type":0}}`
	newCardJSON = `{"type":3,"name":"New card","card":{"cardholderName":"A B","brand":"Visa","number":"4242424242424242","expMonth":"1","expYear":"2031","code":"999"}}`
	editGHEJSON = `{"type":1,"favorite":false,"reprompt":0,"id":"` + fakeserver.ItemGitHubEnt + `","collectionIds":[],"object":"item",` +
		`"folderId":"` + fakeserver.FolderHome + `","name":"GHE renamed","notes":"now with notes","fields":[{"type":0,"name":"team","value":"core"}],` +
		`"login":{"uris":[{"uri":"https://github.example.com"},{"uri":"https://ghe2.example.com","match":1}],"fido2Credentials":[],"username":"alice-corp","password":"ghe-new","passwordRevisionDate":null},` +
		`"passwordHistory":[],"creationDate":"2026-01-02T03:04:05.678Z","revisionDate":"2026-02-03T04:05:06.789Z","attachments":[]}`
	editNameOnlyJSON = `{"type":1,"name":"Only a name"}`
)

var writeCases = []contractCase{
	{Name: "write-templates", State: "unlocked", Steps: []contractStep{
		s("get", "template", "item"), s("get", "template", "item.field"), s("get", "template", "item.login"),
		s("get", "template", "item.login.uri"), s("get", "template", "item.card"), s("get", "template", "item.identity"),
		s("get", "template", "item.securenote"), s("get", "template", "folder"), s("get", "template", "collection"),
		s("get", "template", "item-collections"), s("get", "template", "org-collection"),
		s("get", "template", "foo"), s("get", "template", "item", "--pretty"),
	}},
	{Name: "write-folders", State: "unlocked", Steps: []contractStep{
		s("create", "folder", b64(`{"name":"Created"}`)),
		{Args: []string{"create", "folder"}, Stdin: b64(`{"name":"From stdin"}`), Session: true},
		{Args: []string{"create", "folder"}, Session: true},
		s("create", "folder", "%%%"),
		s("edit", "folder", fakeserver.FolderWork, b64(`{"name":"Work renamed"}`)),
		s("edit", "folder", "00000000-0000-4000-8000-000000000000", b64(`{"name":"x"}`)),
		s("delete", "folder", fakeserver.FolderHome),
		s("delete", "folder", fakeserver.FolderHome),
		s("list", "folders"),
		s("get", "item", fakeserver.ItemNote),
		s("create", "foo", "x"), s("edit", "foo", "x"), s("delete", "foo", "x"),
	}},
	{Name: "write-items", State: "unlocked", Steps: []contractStep{
		s("create", "item", b64(newLoginJSON)),
		s("get", "item", newID1),
		s("create", "item", b64(newNoteJSON), "--pretty"),
		s("create", "item", b64(newCardJSON), "--response"),
		s("create", "item", "not base64 json"),
		s("edit", "item", fakeserver.ItemGitHubEnt, b64(editGHEJSON)),
		s("get", "password", fakeserver.ItemGitHubEnt),
		s("edit", "item", fakeserver.ItemEmpty, b64(editNameOnlyJSON)),
		s("edit", "item", fakeserver.ItemOrgHidden, b64(editNameOnlyJSON)),
		s("edit", "item", fakeserver.ItemTrashed, b64(editNameOnlyJSON)),
		s("edit", "item", "00000000-0000-4000-8000-000000000000", b64(editNameOnlyJSON)),
		{Args: []string{"edit", "item", fakeserver.ItemCard}, Stdin: b64(`{"type":3,"name":"Visa via stdin","card":{"brand":"Visa","number":"4111111111111111"}}`), Session: true},
	}},
	{Name: "write-delete-restore", State: "unlocked", Steps: []contractStep{
		s("delete", "item", fakeserver.ItemNote),
		s("list", "items", "--trash"),
		s("restore", "item", fakeserver.ItemNote),
		s("restore", "item", fakeserver.ItemNote),
		s("delete", "item", fakeserver.ItemTrashed, "--permanent"),
		s("delete", "item", fakeserver.ItemCard, "-p"),
		s("get", "item", fakeserver.ItemCard),
		s("delete", "item", "00000000-0000-4000-8000-000000000000"),
		s("restore", "item", "00000000-0000-4000-8000-000000000000"),
		s("list", "items", "--trash"),
		s("restore", "foo", "x"),
	}},
	{Name: "write-archive", State: "unlocked", Steps: []contractStep{
		s("archive", "item", fakeserver.ItemIdentity),
		s("archive", "item", fakeserver.ItemIdentity),
		s("archive", "item", fakeserver.ItemTrashed),
		s("list", "items", "--archived"),
		s("restore", "item", fakeserver.ItemIdentity),
		s("restore", "item", fakeserver.ItemArchived),
		s("list", "items", "--archived"),
		s("archive", "foo", "x"),
	}},
	{Name: "write-collections", State: "unlocked", Steps: []contractStep{
		s("edit", "item-collections", fakeserver.ItemOrgShared, b64(`["`+fakeserver.CollectionEng+`","`+fakeserver.CollectionSec+`"]`)),
		s("edit", "item-collections", fakeserver.ItemGitHubEnt, b64(`[]`)),
		s("edit", "item-collections", fakeserver.ItemOrgHidden, b64(`[]`)),
		s("list", "items", "--collectionid", fakeserver.CollectionSec),
	}},
	{Name: "write-attachments", State: "unlocked", Steps: []contractStep{
		{Args: []string{"create", "attachment", "--file", "{{TMP}}/report.txt", "--itemid", fakeserver.ItemGitHubEnt}, Session: true,
			Files: map[string]string{"report.txt": "quarterly numbers\n"}},
		s("get", "attachment", "report.txt", "--itemid", fakeserver.ItemGitHubEnt, "--raw"),
		s("create", "attachment", "--file", "{{TMP}}/report.txt"),
		s("create", "attachment", "--itemid", fakeserver.ItemGitHubEnt),
		s("create", "attachment", "--file", "{{TMP}}/missing.txt", "--itemid", fakeserver.ItemGitHubEnt),
		s("delete", "attachment", fakeserver.AttachmentID, "--itemid", fakeserver.ItemGitHub),
		s("delete", "attachment", "nope", "--itemid", fakeserver.ItemGitHubEnt),
		s("delete", "attachment", "nope", "--itemid", fakeserver.ItemNote),
		s("delete", "attachment", "nope"),
		s("get", "item", fakeserver.ItemGitHub),
	}},
}
