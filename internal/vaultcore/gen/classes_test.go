package gen

import (
	"strings"
	"testing"
)

func TestClassPasswordMinimumsWinOverLength(t *testing.T) {
	pw, err := GenerateClassPassword(ClassRequest{Length: 5, Numbers: true, MinNumbers: 4, Special: true, MinSpecial: 3, AvoidAmbiguous: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 7 {
		t.Fatalf("len(%q) = %d, want 7", pw, len(pw))
	}
	if strings.Trim(pw, numbersClear+specialChars) != "" {
		t.Fatalf("%q has characters outside the enabled classes", pw)
	}
	digits := 0
	for _, r := range pw {
		if strings.ContainsRune(numbersClear, r) {
			digits++
		}
	}
	if digits < 4 {
		t.Fatalf("%q has %d digits, want at least 4", pw, digits)
	}
}

// Bitwarden's unambiguous sets drop I, O, l, 0 and 1 but keep lowercase o.
func TestClassPasswordAmbiguousSets(t *testing.T) {
	if !strings.Contains(bwLowerClear, "o") || strings.Contains(bwLowerClear, "l") || strings.ContainsAny(bwUpperClear, "IO") || strings.ContainsAny(numbersClear, "01") {
		t.Fatal("unambiguous sets differ from Bitwarden's")
	}
}
