package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

const testOTP = "ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded"

func TestNormalizeYubiKeyOTP(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  string
		valid bool
	}{
		{testOTP, testOTP, true},
		{"  " + testOTP + "\n", testOTP, true},
		{"CCCCCCBCGUJHINGJRDEJHGFNUETRGIGVEJHHGBKUGDED", testOTP, true}, // Caps Lock
		{testOTP[:43], testOTP[:43], false},
		{testOTP + "c", testOTP + "c", false},
		{testOTP[:43] + "a", testOTP[:43] + "a", false}, // "a" is not modhex
		{"123456", "123456", false},
		{"", "", false},
	} {
		got, ok := NormalizeYubiKeyOTP(tc.in)
		if got != tc.want || ok != tc.valid {
			t.Errorf("NormalizeYubiKeyOTP(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.valid)
		}
	}
}

// TestClient_YubiKeyLogin follows Vaultwarden's YubiKey login
// (src/api/identity.rs, src/api/core/two_factor/yubikey.rs): the challenge
// lists "3" with {"Nfc": bool}, the OTP goes in twoFactorToken with
// twoFactorProvider=3, and a rejected OTP is an HTTP 400 error model.
func TestClient_YubiKeyLogin(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = append(got, map[string]string{
			"provider": r.FormValue("twoFactorProvider"),
			"token":    r.FormValue("twoFactorToken"),
			"remember": r.FormValue("twoFactorRemember"),
		})
		switch r.FormValue("twoFactorToken") {
		case "":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Two factor required.",` +
				`"TwoFactorProviders":["0","3"],"TwoFactorProviders2":{"0":null,"3":{"Nfc":true}},"MasterPasswordPolicy":{"object":"masterPasswordPolicy"}}`))
		case testOTP:
			_, _ = w.Write([]byte(`{"access_token":"tok","refresh_token":"ref","Key":"k","TwoFactorToken":"remember-me"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"Failed to verify Yubikey against OTP server","validationErrors":{"":["Failed to verify Yubikey against OTP server"]},` +
				`"errorModel":{"message":"Failed to verify Yubikey against OTP server","object":"error"},"error":"","error_description":"","object":"error"}`))
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, DeviceID: "dev-1", DeviceType: 7, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", nil)
	var tfErr *TwoFactorRequiredError
	if !errors.As(err, &tfErr) {
		t.Fatalf("got %v, want TwoFactorRequiredError", err)
	}
	if want := []TwoFactorProvider{TwoFactorAuthenticator, TwoFactorYubiKey}; !slices.Equal(tfErr.Challenge.Providers, want) {
		t.Fatalf("providers = %v, want %v", tfErr.Challenge.Providers, want)
	}
	var data struct{ Nfc bool }
	if err := json.Unmarshal(tfErr.Challenge.ProviderData[TwoFactorYubiKey], &data); err != nil || !data.Nfc {
		t.Fatalf("YubiKey provider data = %s (%v)", tfErr.Challenge.ProviderData[TwoFactorYubiKey], err)
	}

	used := "ccccccbcgujhcccccccccccccccccccccccccccccccc"
	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", &TwoFactorLogin{Provider: TwoFactorYubiKey, Token: used})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest || apiErr.Message != "Failed to verify Yubikey against OTP server" {
		t.Fatalf("rejected OTP got %v", err)
	}

	tok, err := c.LoginPassword(ctx, "alice@example.com", "hash", &TwoFactorLogin{Provider: TwoFactorYubiKey, Token: testOTP, Remember: true})
	if err != nil || tok.TwoFactorToken != "remember-me" {
		t.Fatalf("YubiKey login = (%+v, %v)", tok, err)
	}
	want := []map[string]string{
		{"provider": "", "token": "", "remember": ""},
		{"provider": "3", "token": used, "remember": "0"},
		{"provider": "3", "token": testOTP, "remember": "1"},
	}
	if !slices.EqualFunc(got, want, func(a, b map[string]string) bool {
		return a["provider"] == b["provider"] && a["token"] == b["token"] && a["remember"] == b["remember"]
	}) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}
