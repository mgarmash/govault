package main

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/store"
)

const biometricKeyPrefix = "userkey:"

type OSStatusError int32

func (e OSStatusError) Error() string { return fmt.Sprintf("keychain: OSStatus %d", int32(e)) }

const (
	errUserCanceled          OSStatusError = -128
	errAuthFailed            OSStatusError = -25293
	errItemNotFound          OSStatusError = -25300
	errInteractionNotAllowed OSStatusError = -25308
	errMissingEntitlement    OSStatusError = -34018
)

func statusError(status int32) error {
	if status == 0 {
		return nil
	}
	return OSStatusError(status)
}

type accessControlError struct{ code int }

func (e *accessControlError) Error() string {
	return fmt.Sprintf("keychain: biometric access control unavailable (CFError %d)", e.code)
}

// hardwareKeychain stores secrets that macOS releases only after Touch ID.
type hardwareKeychain interface {
	Add(account string, secret []byte) error
	Copy(account, prompt string) ([]byte, error)
	Exists(account string) (bool, error)
	Delete(account string) error
}

// BiometricSecretStore keeps macOS biometric keys only in the hardware-gated
// store. Credentials and biometric keys on other platforms use the platform store.
type BiometricSecretStore struct {
	fallback store.SecretStore
	hw       hardwareKeychain
	// prompt completes the system's Touch ID prompt, “GoVault is trying
	// to …”, in the language shown; "" leaves the keychain's default.
	prompt atomic.Value
}

func NewBiometricSecretStore(fallback store.SecretStore, hw hardwareKeychain) *BiometricSecretStore {
	return &BiometricSecretStore{fallback: fallback, hw: hw}
}

// SetPrompt sets the reason the hardware keychain's Touch ID prompt gives.
func (s *BiometricSecretStore) SetPrompt(reason string) { s.prompt.Store(reason) }

func (s *BiometricSecretStore) promptReason() string {
	reason, _ := s.prompt.Load().(string)
	return reason
}

func isBiometricKey(account string) bool { return strings.HasPrefix(account, biometricKeyPrefix) }

func biometricStoreError(err error) error {
	if errors.Is(err, errMissingEntitlement) {
		return fmt.Errorf("GoVault needs an Apple provisioning profile for Touch ID: %w", err)
	}
	return err
}

func (s *BiometricSecretStore) Get(account string) (string, bool, error) {
	if s.hw != nil && isBiometricKey(account) {
		data, err := s.hw.Copy(account, s.promptReason())
		switch {
		case err == nil:
			return string(data), true, nil
		case errors.Is(err, errUserCanceled), errors.Is(err, errAuthFailed):
			return "", false, fmt.Errorf("%w: %v", govaultui.ErrBiometricCancelled, err)
		case errors.Is(err, errItemNotFound):
			return "", false, nil
		default:
			return "", false, biometricStoreError(err)
		}
	}
	return s.fallback.Get(account)
}

func (s *BiometricSecretStore) Set(account, value string) error {
	if s.hw != nil && isBiometricKey(account) {
		if err := s.hw.Delete(account); err != nil && !errors.Is(err, errItemNotFound) {
			return biometricStoreError(err)
		}
		return biometricStoreError(s.hw.Add(account, []byte(value)))
	}
	return s.fallback.Set(account, value)
}

func (s *BiometricSecretStore) Delete(account string) error {
	if s.hw != nil && isBiometricKey(account) {
		err := s.hw.Delete(account)
		if errors.Is(err, errItemNotFound) {
			return nil
		}
		return biometricStoreError(err)
	}
	return s.fallback.Delete(account)
}

// HardwareBound reports whether the biometric key of accountID is held by
// the hardware-gated keychain, which prompts for Touch ID by itself.
func (s *BiometricSecretStore) HardwareBound(accountID string) bool {
	if s.hw == nil || accountID == "" {
		return false
	}
	ok, err := s.hw.Exists(biometricKeyPrefix + accountID)
	return err == nil && ok
}
