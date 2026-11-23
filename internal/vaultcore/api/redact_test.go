package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	if msg := transportDiagnostic(err); strings.Contains(msg, "SECRET") || strings.Contains(msg, "connection reset") {
		t.Fatalf("redacted = %q", msg)
	}
}

// Nested errors are not formatted: a malformed redirect's message quotes
// its Location.
func TestTransportDiagnosticsDoNotFormatNestedErrors(t *testing.T) {
	inner := errors.New(`failed to parse Location header "https://evil.example/x?sig=SECRET": invalid`)
	err := &url.Error{Op: "Get", URL: "https://vault.example/api/x?token=SECRET2", Err: inner}
	msg := transportDiagnostic(err)
	if strings.Contains(msg, "SECRET") || !strings.Contains(msg, "https://vault.example/api/x") {
		t.Fatalf("diagnostic = %q", msg)
	}
}

// A refused redirect reports the sentinel, not the refused target.
func TestRefusedRedirectsAreNotQuoted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/steal?sig=SECRET", http.StatusFound)
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{ServerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.do(context.Background(), http.MethodGet, "/api/sync", "", "tok", nil, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "elsewhere") {
		t.Fatalf("redirect error = %v", err)
	}
}
