package locales

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nsgo-dev/nsgo/i18n"
)

// sourceKeys are the message keys of en.yaml, in order.
func sourceKeys(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("en.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	key := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*):`)
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := key.FindStringSubmatch(sc.Text()); m != nil {
			keys = append(keys, m[1])
		}
	}
	return keys
}

func exportName(key string) string {
	r, n := utf8.DecodeRuneInString(key)
	return string(unicode.ToUpper(r)) + key[n:]
}

// TestEveryMessageIsUsed keeps the catalog to what GoVault says, so
// translators spend no time on messages nothing shows. The compiler
// already checks that every message the code says exists.
func TestEveryMessageIsUsed(t *testing.T) {
	var code strings.Builder
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != ".." && filepath.Base(path) == "locales" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		code.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	src := code.String()
	for _, key := range sourceKeys(t) {
		if key == "appName" {
			continue // names the app in its packages
		}
		if !strings.Contains(src, "."+exportName(key)+"(") {
			t.Errorf("%s is in en.yaml but GoVault never says it", key)
		}
	}
}

// TestPseudoLocaleMarksEveryMessage checks the pseudo locale, which finds
// untranslated text, accents and brackets the catalog's messages.
func TestPseudoLocaleMarksEveryMessage(t *testing.T) {
	msgs := In(i18n.PseudoAccents)
	for _, s := range []string{msgs.AllItems(), msgs.ItemCount(3), msgs.RepromptPrompt("copyPassword")} {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
			t.Errorf("pseudo-localized %q is not bracketed", s)
		}
	}
	if got := In("en").ItemCount(1); got != "1 item" {
		t.Errorf("ItemCount(1) = %q", got)
	}
	if got := In("en").ItemCount(2); got != "2 items" {
		t.Errorf("ItemCount(2) = %q", got)
	}
}
