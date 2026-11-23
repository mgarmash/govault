package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ndvServer imitates Bitwarden's identity server with new device
// verification on (DeviceValidator.cs): a password grant from an unknown
// device without newDeviceOtp is refused and a code is issued for that
// device; a wrong code is refused; the right one is consumed and the device
// becomes known. API keys and two-step accounts are never asked.
type ndvServer struct {
	t         *testing.T
	mu        sync.Mutex
	twoStep   bool
	known     map[string]bool
	codes     map[string]string // device -> pending code
	issued    int
	resends   []map[string]string
	resendDev []string
	nextCode  string
}

func newNDVServer(t *testing.T) (*ndvServer, *httptest.Server) {
	s := &ndvServer{t: t, known: map[string]bool{}, codes: map[string]string{}, nextCode: "111111"}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	return s, srv
}

func (s *ndvServer) issue(device string) {
	s.codes[device] = s.nextCode
	s.issued++
}

func (s *ndvServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/identity/connect/token":
		_ = r.ParseForm()
		device := r.FormValue("deviceIdentifier")
		if r.FormValue("grant_type") == "client_credentials" {
			_, _ = w.Write([]byte(`{"access_token":"api-tok","expires_in":3600}`))
			return
		}
		if s.twoStep {
			if r.FormValue("twoFactorToken") != "654321" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0"],"TwoFactorProviders2":{"0":null}}`))
				return
			}
			if r.Form.Has("newDeviceOtp") {
				s.t.Errorf("two-step login sent newDeviceOtp")
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","Key":"k"}`))
			return
		}
		otp := r.FormValue("newDeviceOtp")
		if otp == "" && s.known[device] {
			_, _ = w.Write([]byte(`{"access_token":"tok","Key":"k"}`))
			return
		}
		if otp == "" {
			s.issue(device)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"device_error","error_description":"New device verification required","ErrorModel":{"Message":"new device verification required","Object":"error"}}`))
			return
		}
		if want, ok := s.codes[device]; !ok || want != otp {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"device_error","error_description":"Invalid New Device OTP","ErrorModel":{"Message":"invalid new device otp","Object":"error"}}`))
			return
		}
		delete(s.codes, device)
		s.known[device] = true
		_, _ = w.Write([]byte(`{"access_token":"tok","Key":"k"}`))
	case "/api/accounts/resend-new-device-otp":
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
			s.t.Errorf("resend method=%s auth=%q", r.Method, r.Header.Get("Authorization"))
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.resends = append(s.resends, body)
		dev := r.Header.Get("Device-Identifier")
		s.resendDev = append(s.resendDev, dev)
		if body["masterPasswordHash"] == "hash" && dev != "" {
			s.issue(dev)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestClient_NewDeviceVerification(t *testing.T) {
	fake, srv := newNDVServer(t)
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, DeviceID: "dev-1", DeviceType: 7, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", nil)
	var ndErr *NewDeviceVerificationRequiredError
	if !errors.As(err, &ndErr) || !errors.Is(err, ErrNewDeviceVerificationRequired) || errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("got %v, want NewDeviceVerificationRequiredError", err)
	}

	// Resend sends the device so the code is bound to it.
	fake.nextCode = "222222"
	if err := c.ResendNewDeviceOTP(ctx, " Alice@Example.com", "hash"); err != nil {
		t.Fatalf("ResendNewDeviceOTP: %v", err)
	}
	if len(fake.resends) != 1 || fake.resends[0]["email"] != "alice@example.com" || fake.resends[0]["masterPasswordHash"] != "hash" || fake.resendDev[0] != "dev-1" {
		t.Fatalf("resend = %v device %v", fake.resends, fake.resendDev)
	}

	// The superseded code is refused, with the server's message.
	_, err = c.LoginPasswordWith(ctx, "alice@example.com", "hash", PasswordLoginOptions{NewDeviceOTP: "111111"})
	var apiErr *APIError
	if !errors.Is(err, ErrInvalidNewDeviceOTP) || !errors.As(err, &apiErr) || apiErr.Message != "invalid new device otp" || apiErr.StatusCode != 400 {
		t.Fatalf("wrong code got %v", err)
	}
	if errors.Is(err, ErrNewDeviceVerificationRequired) {
		t.Fatal("a wrong code is not a new challenge")
	}

	if tok, err := c.LoginPasswordWith(ctx, "alice@example.com", "hash", PasswordLoginOptions{NewDeviceOTP: " 222 222 "}); err != nil || tok.AccessToken != "tok" {
		t.Fatalf("login with code = (%+v, %v)", tok, err)
	}
	// The device is now known: no further challenge.
	if _, err := c.LoginPassword(ctx, "alice@example.com", "hash", nil); err != nil {
		t.Fatalf("known device: %v", err)
	}
	if fake.issued != 2 {
		t.Fatalf("issued %d codes, want 2", fake.issued)
	}
}

func TestClient_NewDeviceVerificationSkipped(t *testing.T) {
	fake, srv := newNDVServer(t)
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, DeviceID: "dev-2", DeviceType: 7, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.LoginAPIKey(ctx, "user.x", "secret"); err != nil {
		t.Fatalf("API key login: %v", err)
	}
	fake.twoStep = true
	_, err = c.LoginPassword(ctx, "alice@example.com", "hash", nil)
	if !errors.Is(err, ErrTwoFactorRequired) || errors.Is(err, ErrNewDeviceVerificationRequired) {
		t.Fatalf("two-step account got %v", err)
	}
	if _, err := c.LoginPassword(ctx, "alice@example.com", "hash", &TwoFactorLogin{Provider: TwoFactorAuthenticator, Token: "654321"}); err != nil {
		t.Fatalf("two-step login: %v", err)
	}
	if fake.issued != 0 {
		t.Fatalf("issued %d codes", fake.issued)
	}
}

func TestClassifyError_DeviceErrors(t *testing.T) {
	// Other device_error answers stay plain API errors.
	err := classifyError(400, []byte(`{"error":"device_error","error_description":"No device information provided","ErrorModel":{"Message":"no device information provided","Object":"error"}}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || errors.Is(err, ErrNewDeviceVerificationRequired) || errors.Is(err, ErrInvalidNewDeviceOTP) {
		t.Fatalf("got %v", err)
	}
	// Case-insensitive keys, as the server's serializer may camel-case them.
	if err := classifyError(400, []byte(`{"error":"device_error","errorModel":{"message":"new device verification required"}}`)); !errors.Is(err, ErrNewDeviceVerificationRequired) {
		t.Fatalf("camel case got %v", err)
	}
}
