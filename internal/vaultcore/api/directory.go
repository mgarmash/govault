package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// UserPublicKey returns the public key (SPKI DER, base64) of userID.
func (c *Client) UserPublicKey(ctx context.Context, accessToken, userID string) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/users/"+url.PathEscape(userID)+"/public-key", "", accessToken, nil, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", err
	}
	return resp.PublicKey, nil
}

// OrganizationCollections lists every collection of orgID, which needs
// permission to view all of them.
func (c *Client) OrganizationCollections(ctx context.Context, accessToken, orgID string) ([]EncryptedCollection, error) {
	return c.collections(ctx, accessToken, "/api/organizations/"+url.PathEscape(orgID)+"/collections")
}

// UserCollections lists the collections the user is assigned to.
func (c *Client) UserCollections(ctx context.Context, accessToken string) ([]EncryptedCollection, error) {
	return c.collections(ctx, accessToken, "/api/collections")
}

func (c *Client) collections(ctx context.Context, accessToken, path string) ([]EncryptedCollection, error) {
	raw, err := c.do(ctx, http.MethodGet, path, "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []EncryptedCollection `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}
