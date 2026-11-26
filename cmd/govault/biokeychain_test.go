package main

import (
	"errors"
	"sync"
	"testing"

	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

type memSecrets struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memSecrets) Get(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memSecrets) Set(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func (s *memSecrets) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}

type fakeHardware struct {
	items     map[string][]byte
	addErr    error
	copyErr   error
	deleteErr error
	prompts   int
}

func (f *fakeHardware) Add(account string, secret []byte) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.items[account] = append([]byte(nil), secret...)
	return nil
}

func (f *fakeHardware) Copy(account, _ string) ([]byte, error) {
	if f.addErr != nil {
		return nil, f.addErr
	}
	if f.copyErr != nil {
		return nil, f.copyErr
	}
	v, ok := f.items[account]
	if !ok {
		return nil, errItemNotFound
	}
	f.prompts++
	return v, nil
}

func (f *fakeHardware) Exists(account string) (bool, error) {
	if f.addErr != nil {
		return false, nil
	}
	_, ok := f.items[account]
	return ok, nil
}

func (f *fakeHardware) Delete(account string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if f.addErr != nil {
		return f.addErr
	}
	if _, ok := f.items[account]; !ok {
		return errItemNotFound
	}
	delete(f.items, account)
	return nil
}

func TestBiometricSecretStoreNeverFallsBackOnMac(t *testing.T) {
	const account = "userkey:acct"
	fallback := &memSecrets{m: map[string]string{account: "legacy"}}
	hw := &fakeHardware{items: map[string][]byte{}, addErr: errMissingEntitlement}
	s := NewBiometricSecretStore(fallback, hw)
	if err := s.Set(account, "wrapped"); !errors.Is(err, errMissingEntitlement) {
		t.Fatalf("Set without entitlement: %v", err)
	}
	if _, ok, err := s.Get(account); ok || !errors.Is(err, errMissingEntitlement) {
		t.Fatalf("Get without entitlement: found=%v, err=%v", ok, err)
	}
	hw.addErr = nil
	if _, ok, err := s.Get(account); ok || err != nil {
		t.Fatalf("missing hardware item consulted login: found=%v, err=%v", ok, err)
	}
	if err := s.Delete(account); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := fallback.Get(account); !ok || v != "legacy" || err != nil {
		t.Fatal("hardware operations modified the old login item")
	}
}

func TestBiometricSecretStoreUsesHardwareKeychain(t *testing.T) {
	fallback := &memSecrets{m: map[string]string{"userkey:acct": "legacy", "refresh_token:acct": "rt"}}
	hw := &fakeHardware{items: map[string][]byte{}}
	s := NewBiometricSecretStore(fallback, hw)

	if err := s.Set("userkey:acct", "wrapped"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, ok, _ := fallback.Get("userkey:acct"); !ok || v != "legacy" {
		t.Fatal("hardware enrollment touched the previous store")
	}
	if !s.HardwareBound("acct") {
		t.Fatal("HardwareBound = false after hardware save")
	}
	if v, ok, err := s.Get("userkey:acct"); err != nil || !ok || v != "wrapped" || hw.prompts != 1 {
		t.Fatalf("Get = (%q, %v, %v), prompts=%d", v, ok, err, hw.prompts)
	}
	if err := s.Set("refresh_token:acct", "rt2"); err != nil || len(hw.items) != 1 {
		t.Fatal("non-biometric secret routed to the hardware keychain")
	}

	hw.copyErr = errUserCanceled
	if _, _, err := s.Get("userkey:acct"); !errors.Is(err, govaultui.ErrBiometricCancelled) {
		t.Fatalf("cancelled Get = %v", err)
	}
	hw.copyErr = nil

	if err := s.Delete("userkey:acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(hw.items) != 0 || s.HardwareBound("acct") {
		t.Fatal("hardware item survived Delete")
	}
	if err := s.Delete("userkey:acct"); err != nil {
		t.Fatalf("Delete of a missing item: %v", err)
	}

	hw.items["userkey:acct"] = []byte("wrapped")
	hw.deleteErr = errInteractionNotAllowed
	if err := s.Delete("userkey:acct"); !errors.Is(err, errInteractionNotAllowed) {
		t.Fatalf("transient hardware delete error = %v, want it surfaced", err)
	}
}
