package api

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Transport errors do not carry the signature of a download link.
func TestTransportErrorsDropURLSecrets(t *testing.T) {
	if got := RedactURL("https://user:pw@blob.example.com/att/1?sig=SECRET&se=2026#frag"); got != "https://blob.example.com/att/1" {
		t.Fatalf("RedactURL = %q", got)
	}
	err := &url.Error{Op: "Get", URL: "https://blob.example.com/a?sig=SECRET", Err: errors.New("connection reset")}
	if msg := redactURLError(err).Error(); strings.Contains(msg, "SECRET") || !strings.Contains(msg, "connection reset") {
		t.Fatalf("redacted = %q", msg)
	}
}
