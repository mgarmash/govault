package cli

import (
	"fmt"
	"strings"
)

// option is a command-line option. long is its name without dashes.
type option struct {
	long  string
	short byte
	// value is the placeholder of an option that takes an argument, as in
	// "--search <search>"; "" for a flag.
	value string
	// optionalValue makes the argument optional, as in "--sso [id]".
	optionalValue bool
}

func (o option) usage() string {
	s := "--" + o.long
	if o.value != "" {
		s += " <" + o.value + ">"
	}
	return s
}

type argument struct {
	name     string
	required bool
}

type command struct {
	name    string
	args    []argument
	opts    []option
	summary string
	run     func(a *app, p *parsed) response
	// unsupported, when set, is why gv does not offer a bw command.
	unsupported string
}

var globalOptions = []option{
	{long: "pretty"}, {long: "raw"}, {long: "response"}, {long: "cleanexit"},
	{long: "quiet"}, {long: "nointeraction"}, {long: "session", value: "session"},
	{long: "version", short: 'v'}, {long: "help", short: 'h'},
}

// parsed is a parsed command line.
type parsed struct {
	cmd  *command
	args []string
	opts map[string]string
}

func (p *parsed) has(name string) bool { _, ok := p.opts[name]; return ok }

func (p *parsed) opt(name string) (string, bool) { v, ok := p.opts[name]; return v, ok }

func (p *parsed) arg(i int) string {
	if i < len(p.args) {
		return p.args[i]
	}
	return ""
}

// parseError is a commander usage error, printed as "error: ..." on stderr.
type parseError struct{ msg string }

func (e *parseError) Error() string { return "error: " + e.msg }

// parse reads argv the way commander does for bw: options may come before
// or after the command, long options take "--name value" or "--name=value",
// and short flags combine ("-lusn").
func parse(argv []string, commands []*command) (*parsed, error) {
	p := &parsed{opts: map[string]string{}}
	var positional []string
	find := func(long string, short byte) *option {
		lists := [][]option{globalOptions}
		if p.cmd != nil {
			lists = append(lists, p.cmd.opts)
		}
		for _, list := range lists {
			for i := range list {
				if (long != "" && list[i].long == long) || (short != 0 && list[i].short == short) {
					return &list[i]
				}
			}
		}
		return nil
	}
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		switch {
		case tok == "--":
			positional = append(positional, argv[i+1:]...)
			i = len(argv)
		case strings.HasPrefix(tok, "--"):
			name, val, hasVal := strings.Cut(tok[2:], "=")
			o := find(name, 0)
			if o == nil && lenient(p) {
				continue
			}
			if o == nil {
				return nil, &parseError{fmt.Sprintf("unknown option '%s'", tok)}
			}
			switch {
			case o.value == "" && hasVal:
				return nil, &parseError{fmt.Sprintf("option '%s' argument unexpected", o.usage())}
			case o.value == "":
				p.opts[o.long] = ""
			case hasVal:
				p.opts[o.long] = val
			case i+1 < len(argv) && !(o.optionalValue && strings.HasPrefix(argv[i+1], "-")):
				i++
				p.opts[o.long] = argv[i]
			case o.optionalValue:
				p.opts[o.long] = ""
			default:
				return nil, &parseError{fmt.Sprintf("option '%s' argument missing", o.usage())}
			}
		case strings.HasPrefix(tok, "-") && len(tok) > 1:
		shorts:
			for j := 1; j < len(tok); j++ {
				o := find("", tok[j])
				if o == nil && lenient(p) {
					break shorts
				}
				if o == nil {
					return nil, &parseError{fmt.Sprintf("unknown option '-%c'", tok[j])}
				}
				if o.value == "" {
					p.opts[o.long] = ""
					continue
				}
				switch {
				case j+1 < len(tok):
					p.opts[o.long] = tok[j+1:]
				case i+1 < len(argv):
					i++
					p.opts[o.long] = argv[i]
				default:
					return nil, &parseError{fmt.Sprintf("option '%s' argument missing", o.usage())}
				}
				break shorts
			}
		default:
			if p.cmd == nil && len(positional) == 0 {
				for _, c := range commands {
					if c.name == tok {
						p.cmd = c
					}
				}
				if p.cmd == nil {
					return p, &invalidCommandError{args: argv[i:]}
				}
				continue
			}
			positional = append(positional, tok)
		}
	}
	p.args = positional
	if p.cmd == nil || p.has("help") || p.has("version") || lenient(p) {
		return p, nil
	}
	required := 0
	for _, a := range p.cmd.args {
		if a.required {
			required++
		}
	}
	if len(positional) < required {
		return nil, &parseError{fmt.Sprintf("missing required argument '%s'", p.cmd.args[len(positional)].name)}
	}
	if len(positional) > len(p.cmd.args) {
		noun := "arguments"
		if len(p.cmd.args) == 1 {
			noun = "argument"
		}
		return nil, &parseError{fmt.Sprintf("too many arguments for '%s'. Expected %d %s but got %d.", p.cmd.name, len(p.cmd.args), noun, len(positional))}
	}
	return p, nil
}

// invalidCommandError names only the unknown command: the arguments after
// it can be a password or a session key.
type invalidCommandError struct{ args []string }

func (e *invalidCommandError) Error() string { return "Invalid command: " + e.args[0] }

// lenient: a command gv does not offer is reported as such whatever its
// options and arguments are.
func lenient(p *parsed) bool {
	return p.cmd != nil && (p.cmd.unsupported != "" || p.cmd.name == "help")
}
