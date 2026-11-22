package cli

import (
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/txchen/govault/internal/vaultcore/gen"
)

// intOption parses like bw's convertNumberOption: parseInt's leading
// integer, or def.
func intOption(p *parsed, name string, def int) int {
	v, ok := p.opt(name)
	if !ok {
		return def
	}
	v = strings.TrimSpace(v)
	end := 0
	for end < len(v) && (v[end] >= '0' && v[end] <= '9' || (end == 0 && (v[end] == '-' || v[end] == '+'))) {
		end++
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return def
	}
	return n
}

// generate mirrors bw's generate defaults (-uln --length 14, one digit),
// clamps (length 5 or more, 3 or more words) and separator spellings.
// bw also applies an organization's password generator policy when
// signed in; gv does not.
func (a *app) generate(p *parsed) response {
	upper, lower, number, special := p.has("uppercase"), p.has("lowercase"), p.has("number"), p.has("special")
	if !upper && !lower && !number && !special {
		upper, lower, number = true, true, true
	}
	length := max(intOption(p, "length", 14), 5)
	words := max(intOption(p, "words", 6), 3)
	separator := "-"
	if s, ok := p.opt("separator"); ok {
		separator = s
	}
	switch separator {
	case "space":
		separator = " "
	case "empty":
		separator = ""
	default:
		if utf8.RuneCountInString(separator) > 1 {
			r, _ := utf8.DecodeRuneInString(separator)
			separator = string(r)
		}
	}
	var out string
	var err error
	if p.has("passphrase") {
		out, err = gen.GeneratePassphrase(gen.PassphraseOptions{
			NumWords: words, Separator: separator, Capitalize: p.has("capitalize"), IncludeNum: p.has("includeNumber"),
		})
	} else {
		out, err = gen.GenerateClassPassword(gen.ClassRequest{
			Length: length, Uppercase: upper, Lowercase: lower, Numbers: number, Special: special,
			MinUppercase: 1, MinLowercase: 1, MinNumbers: intOption(p, "minNumber", 1), MinSpecial: intOption(p, "minSpecial", 0),
			AvoidAmbiguous: p.has("ambiguous"),
		})
	}
	if err != nil {
		return errResponse(err)
	}
	return str(out)
}

func (a *app) encode(p *parsed) response {
	if a.env.StdinTTY || a.env.Stdin == nil {
		return failure("No stdin was piped in.")
	}
	data, err := io.ReadAll(a.env.Stdin)
	if err != nil {
		return errResponse(err)
	}
	return str(base64.StdEncoding.EncodeToString([]byte(strings.ToValidUTF8(string(data), "\uFFFD"))))
}
