package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/txchen/govault/internal/vaultcore/profile"
)

const (
	readOnlyNote = "gv is read-only: use the GoVault app, the web vault or bw to change your vault."
	moveNote     = "gv cannot move items to an organization yet: it needs re-encrypting the item with the organization key."
	orgAdminNote = "gv does not administer organizations."
)

func unsupported(name, why string) *command {
	return &command{name: name, unsupported: why, args: []argument{{"args", false}, {"more", false}, {"rest", false}}}
}

var commands = []*command{
	{name: "login", args: []argument{{"email", false}, {"password", false}}, summary: "Log into a user account.",
		opts: []option{{long: "method", value: "method"}, {long: "code", value: "code"}, {long: "sso", value: "identifier", optionalValue: true},
			{long: "apikey"}, {long: "passwordenv", value: "passwordenv"}, {long: "passwordfile", value: "passwordfile"}, {long: "check"}},
		run: (*app).login},
	{name: "logout", summary: "Log out of the current user account.", run: (*app).logout},
	{name: "lock", summary: "Lock the vault and destroy active session keys.", run: (*app).lock},
	{name: "unlock", args: []argument{{"password", false}}, summary: "Unlock the vault and return a new session key.",
		opts: []option{{long: "check"}, {long: "passwordenv", value: "passwordenv"}, {long: "passwordfile", value: "passwordfile"}},
		run:  (*app).unlock},
	{name: "sync", summary: "Pull the latest vault data from server.", opts: []option{{long: "force", short: 'f'}, {long: "last"}}, run: (*app).sync},
	{name: "generate", summary: "Generate a password/passphrase.",
		opts: []option{{long: "uppercase", short: 'u'}, {long: "lowercase", short: 'l'}, {long: "number", short: 'n'}, {long: "special", short: 's'},
			{long: "passphrase", short: 'p'}, {long: "length", value: "length"}, {long: "words", value: "words"},
			{long: "minNumber", value: "count"}, {long: "minSpecial", value: "count"}, {long: "separator", value: "separator"},
			{long: "capitalize", short: 'c'}, {long: "includeNumber"}, {long: "ambiguous"}},
		run: (*app).generate},
	{name: "encode", summary: "Base 64 encode stdin.", run: (*app).encode},
	{name: "config", args: []argument{{"setting", true}, {"value", false}}, summary: "Configure CLI settings.",
		opts: []option{{long: "web-vault", value: "url"}, {long: "api", value: "url"}, {long: "identity", value: "url"}, {long: "icons", value: "url"},
			{long: "notifications", value: "url"}, {long: "events", value: "url"}, {long: "key-connector", value: "url"}},
		run: (*app).config},
	{name: "status", summary: "Show server, last sync, user information, and vault status.", run: (*app).status},
	{name: "list", args: []argument{{"object", true}}, summary: "List an array of objects from the vault.",
		opts: []option{{long: "search", value: "search"}, {long: "url", value: "url"}, {long: "folderid", value: "folderid"},
			{long: "collectionid", value: "collectionid"}, {long: "sharedfolderid", value: "sharedfolderid"},
			{long: "organizationid", value: "organizationid"}, {long: "trash"}, {long: "archived"}},
		run: (*app).list},
	{name: "get", args: []argument{{"object", true}, {"id", true}}, summary: "Get an object from the vault.",
		opts: []option{{long: "itemid", value: "itemid"}, {long: "output", value: "output"}, {long: "organizationid", value: "organizationid"}},
		run:  (*app).get},
	{name: "create", args: []argument{{"object", true}, {"encodedJson", false}}, summary: "Create an object in the vault.",
		opts: []option{{long: "file", value: "file"}, {long: "itemid", value: "itemid"}, {long: "organizationid", value: "organizationid"}},
		run:  (*app).create},
	{name: "edit", args: []argument{{"object", true}, {"id", true}, {"encodedJson", false}}, summary: "Edit an object from the vault.",
		opts: []option{{long: "organizationid", value: "organizationid"}}, run: (*app).edit},
	{name: "delete", args: []argument{{"object", true}, {"id", true}}, summary: "Delete an object from the vault.",
		opts: []option{{long: "itemid", value: "itemid"}, {long: "organizationid", value: "organizationid"}, {long: "permanent", short: 'p'}},
		run:  (*app).delete},
	{name: "restore", args: []argument{{"object", true}, {"id", true}}, summary: "Restores an object from the trash or archive.", run: (*app).restore},
	{name: "archive", args: []argument{{"object", true}, {"id", true}}, summary: "Archive an object from the vault.", run: (*app).archive},
	{name: "help", args: []argument{{"command", false}}},
	unsupported("move", moveNote), unsupported("share", moveNote),
	unsupported("confirm", orgAdminNote), unsupported("device-approval", orgAdminNote),
	unsupported("import", readOnlyNote),
	unsupported("export", "gv does not export vaults yet; use the GoVault app's encrypted backup."),
	unsupported("send", "gv does not support Bitwarden Send."), unsupported("receive", "gv does not support Bitwarden Send."),
	unsupported("serve", "gv does not offer the bw serve HTTP API."),
	unsupported("completion", "gv does not generate shell completions yet."),
	unsupported("update", "gv updates with the GoVault app or your package manager."),
	unsupported("sdk-version", "gv does not use the Bitwarden SDK."),
}

func (a *app) run(argv []string) int {
	p, err := parse(argv, commands)
	var inv *invalidCommandError
	var perr *parseError
	switch {
	case errors.As(err, &inv):
		if p != nil {
			a.loadFlags(p)
		}
		a.writeLn(a.env.Stderr, a.env.StderrTTY, a.color(inv.Error(), "91"), false)
		a.writeLn(a.env.Stderr, a.env.StderrTTY, "See --help for a list of available commands.", true)
		return 1
	case errors.As(err, &perr):
		_, _ = io.WriteString(a.env.Stderr, perr.Error()+"\n")
		return 1
	case err != nil:
		_, _ = io.WriteString(a.env.Stderr, err.Error()+"\n")
		return 1
	}
	a.loadFlags(p)
	switch {
	case p.has("version"):
		_, _ = io.WriteString(a.env.Stdout, a.env.Version+"\n")
		return 0
	case p.cmd != nil && p.cmd.name == "help":
		return a.help(p.arg(0), a.env.Stdout, 0)
	case p.has("help"):
		name := ""
		if p.cmd != nil {
			name = p.cmd.name
		}
		return a.help(name, a.env.Stdout, 0)
	case p.cmd == nil:
		return a.help("", a.env.Stderr, 1)
	case p.cmd.unsupported != "":
		return a.render(failure(fmt.Sprintf("`%s` is not available in gv. %s", p.cmd.name, p.cmd.unsupported)))
	}
	return a.render(p.cmd.run(a, p))
}

// errResponse turns an error into bw's response for it.
func errResponse(err error) response {
	var already *profile.AlreadyLoggedInError
	switch {
	case errors.Is(err, profile.ErrNotLoggedIn):
		return failure("You are not logged in.")
	case errors.Is(err, profile.ErrLocked):
		return failure("Vault is locked.")
	case errors.As(err, &already):
		return failure("You are already logged in as " + already.Email + ".")
	}
	return failure(userMessage(err))
}

// userMessage strips the package prefix Go errors carry.
func userMessage(err error) string {
	s := err.Error()
	for _, p := range []string{"profile: ", "api: ", "state: ", "crypto: ", "keyring: "} {
		s = strings.TrimPrefix(s, p)
	}
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func (a *app) help(name string, w io.Writer, code int) int {
	var b strings.Builder
	if name != "" {
		for _, c := range commands {
			if c.name == name && c.unsupported == "" {
				b.WriteString("Usage: gv " + c.name)
				if len(c.opts) > 0 {
					b.WriteString(" [options]")
				}
				for _, arg := range c.args {
					if arg.required {
						b.WriteString(" <" + arg.name + ">")
					} else {
						b.WriteString(" [" + arg.name + "]")
					}
				}
				b.WriteString("\n\n" + c.summary + "\n")
				if len(c.opts) > 0 {
					b.WriteString("\nOptions:\n")
					for _, o := range c.opts {
						if o.short != 0 {
							b.WriteString(fmt.Sprintf("  -%c, %s\n", o.short, o.usage()))
						} else {
							b.WriteString("  " + o.usage() + "\n")
						}
					}
				}
				_, _ = io.WriteString(w, b.String())
				return code
			}
		}
	}
	b.WriteString("Usage: gv [options] [command]\n\nGoVault's read-only, bw-compatible command-line client.\n\nOptions:\n")
	for _, line := range []string{
		"--pretty           Format output. JSON is tabbed with two spaces.",
		"--raw              Return raw output instead of a descriptive message.",
		"--response         Return a JSON formatted version of response output.",
		"--cleanexit        Exit with a success exit code (0) unless an error is thrown.",
		"--quiet            Don't return anything to stdout.",
		"--nointeraction    Do not prompt for interactive user input.",
		"--session <key>    Pass session key instead of reading from env.",
		"-v, --version      Output the version number.",
		"-h, --help         Display help for command.",
	} {
		b.WriteString("  " + line + "\n")
	}
	b.WriteString("\nCommands:\n")
	for _, c := range commands {
		if c.unsupported == "" && c.run != nil {
			b.WriteString(fmt.Sprintf("  %-10s %s\n", c.name, c.summary))
		}
	}
	b.WriteString("\n  Examples:\n\n    gv login\n    BW_SESSION=$(gv unlock --raw) && export BW_SESSION\n    gv list items --search google\n    gv get password google.com\n")
	_, _ = io.WriteString(w, b.String())
	return code
}
