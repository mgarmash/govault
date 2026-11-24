package realtime

import "testing"

// The cloud presets connect to Bitwarden's notifications hosts; any other
// server to its own /notifications/hub.
func TestHubURL(t *testing.T) {
	for server, want := range map[string]string{
		"https://vault.bitwarden.com":      "wss://notifications.bitwarden.com/hub",
		"https://vault.bitwarden.eu":       "wss://notifications.bitwarden.eu/hub",
		"https://vault.example.com":        "wss://vault.example.com/notifications/hub",
		"https://example.com/vaultwarden/": "wss://example.com/vaultwarden/notifications/hub",
		"http://127.0.0.1:8080":            "ws://127.0.0.1:8080/notifications/hub",
	} {
		c, err := NewClient(Config{ServerURL: server})
		if err != nil {
			t.Fatal(err)
		}
		if c.hubBaseURL != want {
			t.Errorf("%s: hub %s, want %s", server, c.hubBaseURL, want)
		}
	}
}
