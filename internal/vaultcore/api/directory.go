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

// UpdateCipherCollections sets the collections of an organization item
// (PUT /api/ciphers/{id}/collections_v2) and returns the item, or nil when
// the user can no longer see it.
func (c *Client) UpdateCipherCollections(ctx context.Context, accessToken, cipherID string, collectionIDs []string) (*EncryptedCipher, error) {
	if collectionIDs == nil {
		collectionIDs = []string{}
	}
	body, err := json.Marshal(struct {
		CollectionIDs []string `json:"collectionIds"`
	}{collectionIDs})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/collections_v2", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Unavailable bool             `json:"unavailable"`
		Cipher      *EncryptedCipher `json:"cipher"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.Unavailable {
		return nil, nil
	}
	return resp.Cipher, nil
}

// CreateOrganizationCipher creates an organization item in collections
// (POST /api/ciphers/create): an item posted to /api/ciphers would belong
// to the organization but to none of its collections.
func (c *Client) CreateOrganizationCipher(ctx context.Context, accessToken string, payload *CipherPayload, collectionIDs []string) (*EncryptedCipher, error) {
	if collectionIDs == nil {
		collectionIDs = []string{}
	}
	body, err := json.Marshal(struct {
		Cipher        *CipherPayload `json:"cipher"`
		CollectionIDs []string       `json:"collectionIds"`
	}{payload, collectionIDs})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers/create", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}
