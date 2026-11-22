package gen

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The vector is from Bitwarden's legacy-compat-key.service.spec.ts.
func TestHashPhraseMatchesBitwarden(t *testing.T) {
	hash, _ := base64.StdEncoding.DecodeString("V5AQSk83YXd6kZqCncC6d9J72R7UZ60Xl1eIoDoWgTc=")
	if got := strings.Join(hashPhrase(hash), "-"); got != "predefine-hunting-pastime-enrich-unhearing" {
		t.Fatalf("phrase = %s", got)
	}
}
