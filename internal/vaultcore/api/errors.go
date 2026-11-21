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
)

type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("api: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("api: HTTP %d", e.StatusCode)
}
