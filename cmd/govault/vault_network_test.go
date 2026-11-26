package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestVaultHTTPClientBlocksOffOriginBeforeDial(t *testing.T) {
	const origin = "https://vault.example"
	for _, invalid := range []string{"", "http://vault.example", origin + ":444", origin + ":", origin + "/api", origin + "?", "https://user@vault.example"} {
		if _, err := vaultHTTPClient(invalid); !errors.Is(err, errVaultDestination) {
			t.Fatalf("configured origin %q was not rejected: %v", invalid, err)
		}
	}

	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://foreign.example/collect", http.StatusTemporaryRedirect)
		case "/icons/example.org/icon.png":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := vaultHTTPClient(origin)
	if err != nil {
		t.Fatal(err)
	}
	inner := client.Transport.(*vaultTransport).transport
	inner.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	inner.TLSClientConfig.ServerName = "127.0.0.1"
	inner.DisableKeepAlives = true
	var dials atomic.Int32
	inner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		if addr != "vault.example:443" {
			return nil, errors.New("unexpected dial destination: " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}

	resp, err := client.Get(origin + ":443/icons/example.org/icon.png")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("icon request status = %d", resp.StatusCode)
	}

	for _, target := range []string{"https://foreign.example/api", "http://vault.example/api", origin + ":444/api", "https://vault.example.foreign.example/api", origin + "/redirect"} {
		if _, err := client.Get(target); !errors.Is(err, errVaultDestination) {
			t.Errorf("request to %s not rejected by origin policy: %v", target, err)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dialed %d times; only the allowed icon and first redirect hop may dial", got)
	}
}
