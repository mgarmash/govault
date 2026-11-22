package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// sealedKeyID names a key without revealing it, so a save can tell whether
// it encrypts under the key the server copies of an item were sealed with.
func sealedKeyID(key *crypto.SymmetricKey) string {
	raw := key.Bytes()
	defer crypto.ZeroBytes(raw[:])
	sum := sha256.Sum256(raw[:])
	return hex.EncodeToString(sum[:16])
}

// keepSealed returns the unknown fields to send back with a save.
//
// Under the key they were sealed with they are kept byte for byte. Under
// another key (a clone, an import copy, a move to another key) an encrypted
// value can no longer be decrypted by anyone, so every value that is or
// contains an EncString is dropped; plaintext values (booleans, numbers,
// plain strings, null) are kept.
func keepSealed(m map[string]json.RawMessage, sameKey bool) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		if !sameKey && containsEncString(v) {
			continue
		}
		out[k] = append(json.RawMessage(nil), v...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsEncString(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return true
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case string:
			_, err := crypto.ParseEncString(t)
			return err == nil
		case []any:
			for _, e := range t {
				if walk(e) {
					return true
				}
			}
		case map[string]any:
			for _, e := range t {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

// uriChecksum is the checksum Bitwarden stores with each login URI: the
// base64 SHA-256 of the URI text, encrypted with the cipher key
// (bitwarden/sdk-internal, LoginUriView::generate_checksum).
func uriChecksum(uri string, key *crypto.SymmetricKey) (*string, error) {
	sum := sha256.Sum256([]byte(uri))
	enc, err := crypto.EncryptString(base64.StdEncoding.EncodeToString(sum[:]), key)
	if err != nil {
		return nil, err
	}
	return &enc, nil
}
