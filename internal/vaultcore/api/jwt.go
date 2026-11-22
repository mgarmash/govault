package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var ErrInvalidAccessToken = errors.New("api: access token is not a JWT")

// TokenSubject returns the user ID (the sub claim) an access token was
// issued for. The signature is not checked: the token came from the server
// over the trusted connection, and this only guards against using it for
// a different account.
func TokenSubject(accessToken string) (string, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return "", ErrInvalidAccessToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", ErrInvalidAccessToken
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return "", ErrInvalidAccessToken
	}
	return claims.Sub, nil
}
