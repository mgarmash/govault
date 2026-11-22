package cli

import "github.com/txchen/govault/internal/fakeserver"

// contractStep is one invocation of the client under test.
type contractStep struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env,omitempty"`
	// Session passes the session key of the profile's last unlock.
	Session bool   `json:"session,omitempty"`
	Stdin   string `json:"stdin,omitempty"`
}

// contractCase runs its steps in order, against a fresh profile that the
// state says how to prepare: "loggedout", "configured" (server set) or
// "unlocked" (signed in with a password, session key known).
type contractCase struct {
	Name  string         `json:"name"`
	State string         `json:"state"`
	Steps []contractStep `json:"steps"`
}

func s(args ...string) contractStep { return contractStep{Args: args, Session: true} }

func locked(args ...string) contractStep { return contractStep{Args: args} }

var contractCases = []contractCase{
	{Name: "status-loggedout", State: "loggedout", Steps: []contractStep{locked("status"), locked("status", "--response"), locked("status", "--pretty")}},
	{Name: "config-server", State: "loggedout", Steps: []contractStep{locked("config", "server"), locked("config", "server", "--raw"), locked("config", "server", "--response")}},
	{Name: "loggedout-errors", State: "loggedout", Steps: []contractStep{
		locked("list", "items"), locked("list", "items", "--response"), locked("get", "item", "x"),
		locked("lock"), locked("logout"), locked("sync"), locked("unlock", "--check"), locked("login", "--check"),
		locked("list", "items", "--cleanexit"), locked("list", "items", "--quiet"), locked("sync", "--last"),
	}},
	{Name: "encode", State: "loggedout", Steps: []contractStep{
		{Args: []string{"encode"}, Stdin: "{\"name\":\"My Folder\"}\n"},
		{Args: []string{"encode", "--response"}, Stdin: "héllo"},
		{Args: []string{"encode"}, Stdin: ""},
	}},
	{Name: "parse-errors", State: "loggedout", Steps: []contractStep{
		locked("foo"), locked("get", "item"), locked("list", "foo"), locked("get", "foo", "x"),
		locked("list", "foo", "--response"), locked("list", "foo", "--cleanexit"),
	}},
	{Name: "status-unlocked", State: "unlocked", Steps: []contractStep{s("status"), locked("status"), s("status", "--response", "--pretty")}},
	{Name: "list-items", State: "unlocked", Steps: []contractStep{
		s("list", "items"),
		s("list", "items", "--search", "github"),
		s("list", "items", "--search", "GITHUB ent"),
		s("list", "items", "--search", "a0000003"),
		s("list", "items", "--search", "example.com"),
		s("list", "items", "--search", "code-2"),
		s("list", "items", "--search", "nomatch", "--response"),
		s("list", "items", "--trash"),
		s("list", "items", "--archived"),
		s("list", "items", "--trash", "--search", "github"),
		s("list", "items", "--folderid", fakeserver.FolderWork),
		s("list", "items", "--folderid", "null"),
		s("list", "items", "--folderid", "notnull"),
		s("list", "items", "--organizationid", fakeserver.OrgID),
		s("list", "items", "--organizationid", "notnull"),
		s("list", "items", "--collectionid", fakeserver.CollectionEng),
		s("list", "items", "--collectionid", "null", "--search", "git"),
		s("list", "items", "--collectionid", "notnull"),
		s("list", "items", "--folderid", fakeserver.FolderHome, "--organizationid", fakeserver.OrgID),
		s("list", "items", "--folderid", fakeserver.FolderWork, "--trash"),
	}},
	{Name: "list-url", State: "unlocked", Steps: []contractStep{
		s("list", "items", "--url", "https://www.github.com/x"),
		s("list", "items", "--url", "https://gist.github.com/abc"),
		s("list", "items", "--url", "https://exact.example.org/path?q=1"),
		s("list", "items", "--url", "https://exact.example.org/path"),
		s("list", "items", "--url", "https://starts.example.org/app/more"),
		s("list", "items", "--url", "https://re.example.org/123"),
		s("list", "items", "--url", "https://never.example.org"),
		s("list", "items", "--url", "https://host.example.org:8443/x"),
		s("list", "items", "--url", "https://host.example.org/x"),
		s("list", "items", "--url", "db.example.com:5432"),
		s("list", "items", "--url", "https://prod.example.com", "--search", "root"),
	}},
	{Name: "list-other", State: "unlocked", Steps: []contractStep{
		s("list", "folders"), s("list", "folders", "--search", "wo"), s("list", "folders", "--search", "zz"),
		s("list", "collections"), s("list", "collections", "--organizationid", fakeserver.OrgID), s("list", "collections", "--search", "sec"),
		s("list", "organizations"), s("list", "organizations", "--search", "ac"),
		s("list", "org-collections", "--organizationid", fakeserver.OrgID),
		s("list", "org-collections", "--organizationid", fakeserver.OrgID, "--search", "eng"),
		s("list", "org-collections"),
		s("list", "org-collections", "--organizationid", "nope"),
		s("list", "org-collections", "--organizationid", "00000000-0000-4000-8000-000000000000"),
	}},
	{Name: "get-item", State: "unlocked", Steps: []contractStep{
		s("get", "item", fakeserver.ItemGitHub),
		s("get", "item", fakeserver.ItemGitHub, "--pretty"),
		s("get", "item", "github"),
		s("get", "item", "github", "--response"),
		s("get", "item", "github enterprise"),
		s("get", "item", fakeserver.ItemOrgHidden),
		s("get", "item", fakeserver.ItemCard),
		s("get", "item", fakeserver.ItemIdentity),
		s("get", "item", fakeserver.ItemSSH),
		s("get", "item", fakeserver.ItemNote),
		s("get", "item", fakeserver.ItemTrashed),
		s("get", "item", "old github"),
		s("get", "item", "nothing"),
		s("get", "item", "nothing", "--response"),
		s("get", "item", "00000000-0000-4000-8000-000000000000"),
		s("get", "item", "A0000004-0000-4000-8000-000000000004"),
	}},
	{Name: "get-scalars", State: "unlocked", Steps: []contractStep{
		s("get", "username", fakeserver.ItemGitHub),
		s("get", "password", fakeserver.ItemGitHub),
		s("get", "password", fakeserver.ItemGitHub, "--response"),
		s("get", "password", "github"),
		s("get", "password", fakeserver.ItemOrgHidden),
		s("get", "username", fakeserver.ItemOrgHidden),
		s("get", "totp", fakeserver.ItemOrgHidden),
		s("get", "uri", fakeserver.ItemGitHub),
		s("get", "notes", fakeserver.ItemGitHub),
		s("get", "notes", fakeserver.ItemGitHubEnt),
		s("get", "password", fakeserver.ItemNote),
		s("get", "username", fakeserver.ItemEmpty),
		s("get", "uri", fakeserver.ItemEmpty),
		s("get", "password", "recovery"),
		s("get", "notes", "recovery"),
		s("get", "password", "nothing"),
		s("get", "password", "modes"),
		s("get", "password", "modes", "--raw"),
		s("get", "password", "modes", "--quiet"),
		s("get", "password", "modes", "--response", "--quiet"),
	}},
	{Name: "get-other", State: "unlocked", Steps: []contractStep{
		s("get", "folder", "work"), s("get", "folder", fakeserver.FolderHome), s("get", "folder", "o"), s("get", "folder", "zz"),
		s("get", "collection", "eng"), s("get", "collection", fakeserver.CollectionSec),
		s("get", "organization", "acme"), s("get", "organization", fakeserver.OrgID),
		s("get", "fingerprint", "me"), s("get", "fingerprint", fakeserver.PeerUserID),
		s("get", "fingerprint", "00000000-0000-4000-8000-000000000000"), s("get", "fingerprint", "bob"),
	}},
	{Name: "get-attachment", State: "unlocked", Steps: []contractStep{
		s("get", "attachment", fakeserver.AttachmentName, "--itemid", fakeserver.ItemGitHub, "--raw"),
		s("get", "attachment", "readme", "--itemid", fakeserver.ItemGitHub, "--output", "{{TMP}}/"),
		s("get", "attachment", fakeserver.AttachmentID, "--itemid", fakeserver.ItemGitHub, "--output", "{{TMP}}/named.bin", "--response"),
		s("get", "attachment", "nope", "--itemid", fakeserver.ItemGitHub),
		s("get", "attachment", "readme"),
		s("get", "attachment", "x", "--itemid", fakeserver.ItemNote),
	}},
	{Name: "locked-reads", State: "unlocked", Steps: []contractStep{
		locked("list", "items", "--nointeraction"),
		locked("get", "item", "github", "--nointeraction", "--response"),
		locked("unlock", "--check"),
		s("unlock", "--check"),
		{Args: []string{"list", "items", "--session", "AAAA"}, Env: map[string]string{"BW_NOINTERACTION": "true"}},
		s("sync", "--last"),
	}},
	{Name: "unlock-flow", State: "unlocked", Steps: []contractStep{
		{Args: []string{"unlock", "--passwordenv", "PW", "--raw"}, Env: map[string]string{"PW": fakeserver.Password}},
		{Args: []string{"unlock", "--passwordenv", "PW"}, Env: map[string]string{"PW": "wrong"}},
		{Args: []string{"unlock", "--passwordenv", "PW", "--nointeraction"}, Env: map[string]string{}},
		{Args: []string{"unlock", fakeserver.Password}},
		s("unlock", "--check"),
		s("lock"),
		s("unlock", "--check"),
		s("list", "items", "--nointeraction"),
		locked("lock"),
	}},
	{Name: "sync-logout", State: "unlocked", Steps: []contractStep{
		s("sync"), s("sync", "-f"), s("sync", "--last", "--raw"), locked("sync"),
		locked("login", "--check"), locked("login", fakeserver.Email, "x"),
		locked("config", "server", "https://example.com"),
		locked("logout"), locked("status"), locked("logout"),
	}},
	{Name: "login-errors", State: "configured", Steps: []contractStep{
		locked("login", "--nointeraction"),
		locked("login", "bob", "pw"),
		locked("login", fakeserver.Email, "--nointeraction"),
		locked("login", fakeserver.Email, "wrong"),
		locked("login", fakeserver.Email, "pw", "--method", "9"),
		{Args: []string{"login", "--apikey", "--nointeraction"}, Env: map[string]string{}},
		{Args: []string{"login", "--apikey"}, Env: map[string]string{"BW_CLIENTID": "organization.x", "BW_CLIENTSECRET": "y"}},
		{Args: []string{"login", "--apikey"}, Env: map[string]string{"BW_CLIENTID": fakeserver.ClientID, "BW_CLIENTSECRET": "wrong"}},
	}},
	{Name: "login-apikey", State: "configured", Steps: []contractStep{
		{Args: []string{"login", "--apikey", "--nointeraction"}, Env: map[string]string{"BW_CLIENTID": fakeserver.ClientID, "BW_CLIENTSECRET": fakeserver.ClientSecret}},
		locked("status"),
		locked("login", "--check"),
		locked("sync"),
		{Args: []string{"unlock", "--passwordenv", "PW", "--raw"}, Env: map[string]string{"PW": fakeserver.Password}},
		s("get", "password", fakeserver.ItemGitHub),
	}},
	{Name: "login-password", State: "configured", Steps: []contractStep{
		{Args: []string{"login", fakeserver.Email, "--passwordenv", "PW"}, Env: map[string]string{"PW": fakeserver.Password}},
		s("get", "username", fakeserver.ItemGitHub),
		locked("login", fakeserver.Email, fakeserver.Password),
	}},
}
