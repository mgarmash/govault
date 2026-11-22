package api

import (
	"errors"
	"fmt"
)

var (
	ErrUnauthorized      = errors.New("api: unauthorized")
	ErrTwoFactorRequired = errors.New("api: two-factor authentication required")
	ErrRevisionConflict  = errors.New("api: revision conflict")
	ErrNetworkOffline    = errors.New("api: network offline")
	ErrNotFound          = errors.New("api: not found")
	// ErrRedirectRefused means the server redirected an API request to
	// another scheme, host or port, which GoVault never follows.
	ErrRedirectRefused = errors.New("api: the server redirected to another address")
)

type APIError struct {
	StatusCode int
	Message    string
	// Code is the OAuth error code of an identity error, such as
	// "invalid_client".
	Code string
	Body string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("api: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("api: HTTP %d", e.StatusCode)
}

// notFoundError is an APIError that also matches ErrNotFound.
type notFoundError struct{ APIError }

func (e *notFoundError) Error() string { return e.APIError.Error() }

func (e *notFoundError) Is(target error) bool { return target == ErrNotFound }
