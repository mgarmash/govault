package api

import (
	"fmt"
	"net/url"
	"strings"
)

// Endpoints are the services of one server. Base is "" for Bitwarden's
// US cloud, the default.
type Endpoints struct {
	Base     string `json:"base"`
	API      string `json:"api"`
	Identity string `json:"identity"`
}

var (
	usCloud = Endpoints{API: "https://api.bitwarden.com", Identity: "https://identity.bitwarden.com"}
	euCloud = Endpoints{API: "https://api.bitwarden.eu", Identity: "https://identity.bitwarden.eu"}
)

// FormatServerURL normalizes a server base URL the way Bitwarden clients
// do: surrounding space and trailing slashes are dropped and a missing
// scheme becomes https. "", "null", "bitwarden.com" and
// "https://bitwarden.com" select the default US cloud and give "".
func FormatServerURL(raw string) string {
	s := strings.TrimSpace(raw)
	switch s {
	case "", "null", "bitwarden.com", "https://bitwarden.com":
		return ""
	}
	s = strings.TrimRight(s, "/")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// FormatServiceURL normalizes a service URL as FormatServerURL does,
// without the cloud shortcuts.
func FormatServiceURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s != "" && !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// ResolveEndpoints maps a base URL from FormatServerURL to its services.
// Bitwarden's US and EU clouds have fixed API and identity hosts; any
// other server serves them under its base path.
func ResolveEndpoints(base string) (Endpoints, error) {
	if base == "" {
		return usCloud, nil
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Endpoints{}, fmt.Errorf("api: invalid server URL %q", base)
	}
	if u.Scheme == "https" && u.Port() == "" && (u.Path == "" || u.Path == "/") {
		switch strings.ToLower(u.Hostname()) {
		case "bitwarden.com", "vault.bitwarden.com":
			e := usCloud
			e.Base = base
			return e, nil
		case "bitwarden.eu", "vault.bitwarden.eu":
			e := euCloud
			e.Base = base
			return e, nil
		}
	}
	return Endpoints{Base: base, API: base + "/api", Identity: base + "/identity"}, nil
}
