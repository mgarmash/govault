package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// vaultOrigin is set by the linker for each local build. Never ship a default.
var vaultOrigin string

var errVaultDestination = errors.New("GoVault only connects to its configured Vaultwarden server over HTTPS")

func vaultHTTPClient(origin string) (*http.Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") || (u.Path != "" && u.Path != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, errVaultDestination
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	t := &vaultTransport{host: host}
	if !t.allows(u, u.Host) {
		return nil, errVaultDestination
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.transport = transport
	return &http.Client{Transport: t, Timeout: 30 * time.Second}, nil
}

type vaultTransport struct {
	host      string
	transport *http.Transport
}

func (t *vaultTransport) allows(u *url.URL, hostHeader string) bool {
	return u.Scheme == "https" && u.Opaque == "" && u.User == nil &&
		t.matchesHost(u.Host) && (hostHeader == "" || t.matchesHost(hostHeader))
}

func (t *vaultTransport) matchesHost(host string) bool {
	return strings.EqualFold(host, t.host) || strings.EqualFold(host, t.host+":443")
}

func (t *vaultTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Check every request, including redirects, before DNS, TLS or sending data.
	if !t.allows(r.URL, r.Host) {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errVaultDestination
	}
	return t.transport.RoundTrip(r)
}
