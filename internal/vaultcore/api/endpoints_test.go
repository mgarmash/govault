package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerURLsResolveLikeBitwarden(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Endpoints
	}{
		{"", usCloud},
		{"bitwarden.com", usCloud},
		{"https://vault.bitwarden.eu/", Endpoints{Base: "https://vault.bitwarden.eu", API: "https://api.bitwarden.eu", Identity: "https://identity.bitwarden.eu"}},
		{"vault.example.com", Endpoints{Base: "https://vault.example.com", API: "https://vault.example.com/api", Identity: "https://vault.example.com/identity"}},
		{"http://10.0.0.5:8080/vw//", Endpoints{Base: "http://10.0.0.5:8080/vw", API: "http://10.0.0.5:8080/vw/api", Identity: "http://10.0.0.5:8080/vw/identity"}},
	} {
		got, err := ResolveEndpoints(FormatServerURL(c.in))
		if err != nil || got != c.want {
			t.Errorf("%q: %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	if _, err := ResolveEndpoints("https://x.example.com/?q=1"); err == nil {
		t.Error("a base URL with a query was accepted")
	}
}

// Identity and API requests go to their own hosts, and neither follows a
// redirect to another origin.
func TestSplitServicesRouteAndRefuseCrossOriginRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("credentials followed a redirect to %s", r.URL)
	}))
	defer elsewhere.Close()
	var identityHits int
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityHits++
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer identity.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/revision-date" {
			t.Errorf("API request to %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("1700000000000"))
	}))
	defer apiSrv.Close()

	c, err := NewClient(ClientConfig{APIURL: apiSrv.URL, IdentityURL: identity.URL, ClientID: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RevisionDate(context.Background(), "tok"); err != nil {
		t.Fatalf("API request: %v", err)
	}
	_, err = c.LoginAPIKey(context.Background(), "user.x", "secret")
	if !errors.Is(err, ErrRedirectRefused) || identityHits != 1 {
		t.Fatalf("redirected identity request = %v (hits %d), want ErrRedirectRefused", err, identityHits)
	}
}

func TestTokenSubject(t *testing.T) {
	tok := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","exp":1}`)) + ".s"
	if sub, err := TokenSubject(tok); err != nil || sub != "user-1" {
		t.Fatalf("TokenSubject = %q, %v", sub, err)
	}
	if _, err := TokenSubject("opaque"); err == nil {
		t.Fatal("an opaque token has a subject")
	}
}
