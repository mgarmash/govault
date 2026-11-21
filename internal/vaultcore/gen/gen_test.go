package gen

import (
	"errors"
	"strings"
	"testing"
	"unicode"
)

func TestGeneratePassword_Constraints(t *testing.T) {
	opts := PasswordOptions{
		Length:         24,
		Uppercase:      true,
		Lowercase:      true,
		Numbers:        true,
		Special:        true,
		MinNumbers:     4,
		MinSpecial:     3,
		AvoidAmbiguous: true,
	}

	const ambiguous = "IOlo01"
	for range 20 {
		pw, err := GeneratePassword(opts)
		if err != nil {
			t.Fatalf("GeneratePassword failed: %v", err)
		}
		if len(pw) != opts.Length {
			t.Fatalf("len = %d, want %d", len(pw), opts.Length)
		}

		var upper, lower, num, spec int
		for _, r := range pw {
			if strings.ContainsRune(ambiguous, r) {
				t.Fatalf("password %q contains ambiguous char %q", pw, r)
			}
			switch {
			case strings.ContainsRune(uppercaseClear, r):
				upper++
			case strings.ContainsRune(lowercaseClear, r):
				lower++
			case strings.ContainsRune(numbersClear, r):
				num++
			case strings.ContainsRune(specialChars, r):
				spec++
			default:
				t.Fatalf("unexpected char %q in %q", r, pw)
			}
		}
		if upper < 1 || lower < 1 || num < opts.MinNumbers || spec < opts.MinSpecial {
			t.Fatalf("password %q violated class counts (upper=%d lower=%d num=%d spec=%d)", pw, upper, lower, num, spec)
		}
	}
}

func TestGeneratePassword_RejectsInvalidOptions(t *testing.T) {
	cases := []PasswordOptions{
		{Length: 0, Lowercase: true},
		{Length: 12},
		{Length: 8, Lowercase: true, MinNumbers: 1},
		{Length: 5, Uppercase: true, Lowercase: true, Numbers: true, Special: true, MinNumbers: 3, MinSpecial: 2},
	}
	for _, opts := range cases {
		if _, err := GeneratePassword(opts); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("GeneratePassword(%+v) = %v, want ErrInvalidOptions", opts, err)
		}
	}
}

func TestGeneratePassphrase(t *testing.T) {
	phrase, err := GeneratePassphrase(PassphraseOptions{
		NumWords:   5,
		Separator:  "-",
		Capitalize: true,
		IncludeNum: true,
	})
	if err != nil {
		t.Fatalf("GeneratePassphrase failed: %v", err)
	}

	parts := strings.Split(phrase, "-")
	if len(parts) != 5 {
		t.Fatalf("got %d words (%q), want 5", len(parts), phrase)
	}

	digits := 0
	for _, w := range parts {
		if len(w) == 0 || !unicode.IsUpper(rune(w[0])) {
			t.Errorf("word %q is not capitalized", w)
		}
		if w[len(w)-1] >= '0' && w[len(w)-1] <= '9' {
			digits++
		}
	}
	if digits != 1 {
		t.Errorf("expected exactly 1 word with trailing digit in %q, got %d", phrase, digits)
	}

	if _, err := GeneratePassphrase(PassphraseOptions{NumWords: 0}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("NumWords=0 got %v, want ErrInvalidOptions", err)
	}
}
