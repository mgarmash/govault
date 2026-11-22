// Package keyring keeps small secrets in the operating system's credential
// store: the login Keychain on macOS, Credential Manager on Windows and
// the Secret Service on Linux. It has no fallback: a caller that finds no
// store decides what to do instead.
package keyring

import (
	"errors"
	"sync"
)

var (
	// ErrUnavailable means this system has no usable credential store.
	ErrUnavailable = errors.New("keyring: no credential store is available")
	// ErrNotFound means the store has no such item.
	ErrNotFound = errors.New("keyring: item not found")
)

// Store is a credential store holding secrets by service and account.
type Store interface {
	// Name identifies the backend, such as "macos-keychain".
	Name() string
	// Get returns the secret, or ErrNotFound.
	Get(service, account string) ([]byte, error)
	// Set creates or replaces the secret.
	Set(service, account string, secret []byte) error
	// Delete removes the secret; a missing item is not an error.
	Delete(service, account string) error
}

// System returns this system's credential store, or ErrUnavailable.
func System() (Store, error) { return system() }

// Memory is a Store kept in process memory, for tests.
type Memory struct {
	mu    sync.Mutex
	items map[[2]string][]byte
	// Fail, when set, is returned by every call.
	Fail error
}

func NewMemory() *Memory { return &Memory{items: map[[2]string][]byte{}} }

func (m *Memory) Name() string { return "memory" }

func (m *Memory) Get(service, account string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return nil, m.Fail
	}
	v, ok := m.items[[2]string{service, account}]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *Memory) Set(service, account string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.items[[2]string{service, account}] = append([]byte(nil), secret...)
	return nil
}

func (m *Memory) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	delete(m.items, [2]string{service, account})
	return nil
}

// Len counts the items held.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}
