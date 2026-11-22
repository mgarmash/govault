package crypto

import (
	"errors"
	"testing"
)

func TestSealBindsKeyAndAssociatedData(t *testing.T) {
	key, err := SealKey([]byte("secret"), "purpose A")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(key, []byte("user key"), []byte("profile 1"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := Open(key, sealed, []byte("profile 1")); err != nil || string(plain) != "user key" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
	if _, err := Open(key, sealed, []byte("profile 2")); !errors.Is(err, ErrSealOpen) {
		t.Fatalf("other associated data = %v", err)
	}
	other, _ := SealKey([]byte("secret"), "purpose B")
	if _, err := Open(other, sealed, []byte("profile 1")); !errors.Is(err, ErrSealOpen) {
		t.Fatalf("key for another purpose = %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(key, sealed, []byte("profile 1")); !errors.Is(err, ErrSealOpen) {
		t.Fatalf("tampered data = %v", err)
	}
}
