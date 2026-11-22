package gen

import "errors"

// ClassRequest asks for a password the way Bitwarden's generator builds
// one: at least Min characters of each enabled class, then characters from
// all enabled classes up to Length. Minimums win over Length.
type ClassRequest struct {
	Length                                 int
	Uppercase, Lowercase, Numbers, Special bool
	MinUppercase, MinLowercase, MinNumbers int
	MinSpecial                             int
	AvoidAmbiguous                         bool
}

const (
	bwUpperClear = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	bwLowerClear = "abcdefghijkmnopqrstuvwxyz"
)

// GenerateClassPassword implements ClassRequest. Its character sets are
// Bitwarden's: avoiding ambiguity drops I, O, l, 0 and 1.
func GenerateClassPassword(req ClassRequest) (string, error) {
	upper, lower, digits := uppercaseAll, lowercaseAll, numbersAll
	if req.AvoidAmbiguous {
		upper, lower, digits = bwUpperClear, bwLowerClear, numbersClear
	}
	var sets []string
	var all string
	add := func(on bool, min int, charset string) {
		if !on {
			return
		}
		for range max(min, 0) {
			sets = append(sets, charset)
		}
		all += charset
	}
	add(req.Uppercase, req.MinUppercase, upper)
	add(req.Lowercase, req.MinLowercase, lower)
	add(req.Numbers, req.MinNumbers, digits)
	add(req.Special, req.MinSpecial, specialChars)
	for len(sets) < req.Length {
		if all == "" {
			return "", errors.New("gen: no character class is enabled")
		}
		sets = append(sets, all)
	}
	for i := len(sets) - 1; i > 0; i-- {
		j, err := randomInt(i + 1)
		if err != nil {
			return "", err
		}
		sets[i], sets[j] = sets[j], sets[i]
	}
	out := make([]byte, len(sets))
	for i, cs := range sets {
		c, err := randomChar(cs)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	return string(out), nil
}
