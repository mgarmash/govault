package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// ErrSealOpen means sealed data failed authentication: a wrong key, other
// associated data, or tampering.
var ErrSealOpen = errors.New("crypto: sealed data failed authentication")

// SealKey derives a 256-bit AEAD key from secret for one purpose, named
// by info, so one secret never keys two uses.
func SealKey(secret []byte, info string) ([32]byte, error) {
	var key [32]byte
	raw, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return key, err
	}
	copy(key[:], raw)
	ZeroBytes(raw)
	return key, nil
}

// Seal encrypts plaintext with AES-256-GCM under key, authenticating ad.
// The result is nonce || ciphertext.
func Seal(key [32]byte, plaintext, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

// Open reverses Seal; any mismatch of key, ad or data is ErrSealOpen.
func Open(key [32]byte, sealed, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrSealOpen
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil {
		return nil, ErrSealOpen
	}
	return plain, nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
