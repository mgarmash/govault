package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// RenewAttachmentUploadURL asks the server for a fresh upload URL of an
// attachment that is not uploaded yet.
func (c *Client) RenewAttachmentUploadURL(ctx context.Context, accessToken, cipherID, attachmentID string) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/ciphers/"+url.PathEscape(cipherID)+"/attachment/"+url.PathEscape(attachmentID)+"/renew", "", accessToken, nil, nil)
	if err != nil {
		return "", err
	}
	var resp AttachmentUploadResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", err
	}
	if resp.URL == "" {
		return "", fmt.Errorf("api: the server renewed no upload URL")
	}
	return resp.URL, nil
}

// AzureUploadExpired reports whether a signed blob URL expires within a
// second, as Bitwarden's clients check before they upload: its se
// parameter, or an hour from now without one.
func AzureUploadExpired(raw string, now time.Time) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	expiry, err := time.Parse(time.RFC3339, u.Query().Get("se"))
	if err != nil {
		return false
	}
	return expiry.Before(now.Add(time.Second))
}

// UploadAzureBlob puts encrypted attachment data to a signed blob storage
// URL in one block blob, as Bitwarden's clients do for files up to
// 256 MiB. The URL's signature authorizes it; no bearer token is sent.
func (c *Client) UploadAzureBlob(ctx context.Context, blobURL string, data []byte) error {
	u, err := url.Parse(blobURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || InsecureServer(blobURL))) {
		return fmt.Errorf("api: invalid attachment upload URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", u.Query().Get("sv"))
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))
	hc := *c.httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %v", ErrNetworkOffline, redactURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("api: the attachment upload to storage failed with status %d", resp.StatusCode)
	}
	return nil
}
