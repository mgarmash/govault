package cli

import (
	"fmt"
	"strings"
)

func (a *app) completion(p *parsed) response {
	shell := optValue(p, "shell")
	if shell == "" {
		return failure("`shell` option was not provided.")
	}
	if shell != "zsh" {
		return failure("Unsupported shell.")
	}
	return success(message{title: zshCompletion(), noColor: true})
}

// zshCompletion renders a zsh completion script for gv's commands, laid
// out as bw's completion command lays out its own.
func zshCompletion() string {
	var cmds []*command
	for _, c := range commands {
		if c.run != nil && c.unsupported == "" {
			cmds = append(cmds, c)
		}
	}
	var b strings.Builder
	b.WriteString("#compdef _gv gv\n\n")
	b.WriteString(zshBlock("gv", globalOptions, cmds))
	for _, c := range cmds {
		b.WriteString("\n\n" + zshBlock("gv_"+c.name, c.opts, nil))
	}
	return b.String()
}

func zshBlock(name string, opts []option, cmds []*command) string {
	var args []string
	for _, o := range opts {
		if o.long == "help" {
			continue
		}
		desc := "[" + strings.ReplaceAll(o.long, "'", `'"'"'`) + "]"
		if o.short != 0 {
			args = append(args, fmt.Sprintf("'(-%c --%s)'{-%c,--%s}'%s'", o.short, o.long, o.short, o.long, desc))
		} else {
			args = append(args, fmt.Sprintf("'--%s%s'", o.long, desc))
		}
	}
	args = append(args, `'(-h --help)'{-h,--help}'[output usage information]'`)
	if len(cmds) > 0 {
		args = append(args, `"1: :->cmnds"`)
	}
	args = append(args, `"*::arg:->args"`)
	var parts []string
	if len(cmds) > 0 {
		parts = append(parts, "local -a commands")
	}
	parts = append(parts, "_arguments -C \\\n    "+strings.Join(args, " \\\n    "))
	if len(cmds) > 0 {
		var list, cases []string
		for _, c := range cmds {
			list = append(list, fmt.Sprintf(`"%s:%s"`, c.name, c.summary))
			cases = append(cases, fmt.Sprintf("%s)\n      _%s_%s\n      ;;", c.name, name, c.name))
		}
		parts = append(parts, "case $state in\n    cmnds)\n      commands=(\n        "+strings.Join(list, "\n        ")+
			"\n      )\n      _describe \"command\" commands\n      ;;\n  esac\n\n  case \"$words[1]\" in\n    "+strings.Join(cases, "\n    ")+"\n  esac")
	}
	return "function _" + name + " {\n  " + strings.Join(parts, "\n\n  ") + "\n}"
}
