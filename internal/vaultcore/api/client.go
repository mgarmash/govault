package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

const defaultUserAgent = "GoVault/0.1"

type ClientConfig struct {
	ServerURL  string
	DeviceID   string
	DeviceName string
	DeviceType int
	HTTPClient *http.Client
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	deviceID   string
	deviceName string
	deviceType int
	userAgent  string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if base == "" {
		return nil, errors.New("api: ServerURL is required")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("api: invalid ServerURL %q", cfg.ServerURL)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &Client{
		baseURL:    base,
		httpClient: httpClient,
		deviceID:   cfg.DeviceID,
		deviceName: cfg.DeviceName,
		deviceType: cfg.DeviceType,
		userAgent:  defaultUserAgent,
	}, nil
}

func (c *Client) Prelogin(ctx context.Context, email string) (crypto.KDFConfig, error) {
	var cfg crypto.KDFConfig
	body, err := json.Marshal(struct {
		Email string `json:"email"`
	}{Email: crypto.NormalizeEmail(email)})
	if err != nil {
		return cfg, err
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/accounts/prelogin", "application/json", "", nil, body)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Client) LoginPassword(ctx context.Context, email, masterPasswordHash string, twoFactor *TwoFactorLogin) (*TokenResponse, error) {
	normEmail := crypto.NormalizeEmail(email)
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {normEmail},
		"password":         {masterPasswordHash},
		"scope":            {"api offline_access"},
		"client_id":        {"desktop"},
		"deviceIdentifier": {c.deviceID},
		"deviceName":       {c.deviceName},
		"deviceType":       {strconv.Itoa(c.deviceType)},
	}
	if twoFactor != nil {
		form.Set("twoFactorProvider", strconv.Itoa(int(twoFactor.Provider)))
		form.Set("twoFactorToken", strings.Join(strings.Fields(twoFactor.Token), ""))
		if twoFactor.Remember {
			form.Set("twoFactorRemember", "1")
		} else {
			form.Set("twoFactorRemember", "0")
		}
	}
	headers := map[string]string{
		"Auth-Email": base64.RawURLEncoding.EncodeToString([]byte(normEmail)),
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", headers, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"desktop"},
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", nil, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RevisionDate(ctx context.Context, accessToken string) (time.Time, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/accounts/revision-date", "", accessToken, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if ms, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}

	var iso string
	if err := json.Unmarshal(raw, &iso); err != nil {
		return time.Time{}, fmt.Errorf("api: invalid revision-date %q: %w", trimmed, err)
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func (c *Client) Sync(ctx context.Context, accessToken string) (*SyncResponse, []byte, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/sync?excludeDomains=true", "", accessToken, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var resp SyncResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, nil, err
	}
	return &resp, raw, nil
}

func (c *Client) CreateCipher(ctx context.Context, accessToken string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) UpdateCipher(ctx context.Context, accessToken, cipherID string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) SoftDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/delete", "", accessToken, nil, nil)
	return err
}

func (c *Client) RestoreCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/restore", "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) HardDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/ciphers/"+url.PathEscape(cipherID), "", accessToken, nil, nil)
	return err
}

func (c *Client) CreateFolder(ctx context.Context, accessToken, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/folders", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) UpdateFolder(ctx context.Context, accessToken, folderID, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/folders/"+url.PathEscape(folderID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) DeleteFolder(ctx context.Context, accessToken, folderID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/folders/"+url.PathEscape(folderID), "", accessToken, nil, nil)
	return err
}

func DoWithRefresh[T any](
	ctx context.Context,
	accessToken string,
	refresh func(context.Context) (string, error),
	fn func(token string) (T, error),
) (T, error) {
	res, err := fn(accessToken)
	if err == nil || !errors.Is(err, ErrUnauthorized) || refresh == nil {
		return res, err
	}
	newToken, refreshErr := refresh(ctx)
	if refreshErr != nil {
		var zero T
		return zero, refreshErr
	}
	return fn(newToken)
}

func (c *Client) do(
	ctx context.Context,
	method, path, contentType, accessToken string,
	headers map[string]string,
	body []byte,
) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrNetworkOffline, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	return nil, classifyError(resp.StatusCode, raw)
}

func classifyError(status int, body []byte) error {
	if status == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if status == http.StatusConflict {
		return ErrRevisionConflict
	}

	if status == http.StatusBadRequest {
		if tfErr, ok := parseTwoFactorChallenge(body); ok {
			return tfErr
		}
	}

	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
		ErrorModel       *struct {
			Message string `json:"message"`
		} `json:"errorModel"`
	}
	_ = json.Unmarshal(body, &parsed)

	msg := parsed.Message
	if msg == "" && parsed.ErrorModel != nil {
		msg = parsed.ErrorModel.Message
	}
	if msg == "" {
		msg = parsed.ErrorDescription
	}
	if msg == "" {
		msg = parsed.Error
	}

	if status == http.StatusBadRequest && strings.Contains(strings.ToLower(msg), "revision") {
		return ErrRevisionConflict
	}

	return &APIError{
		StatusCode: status,
		Message:    msg,
		Body:       string(body),
	}
}
