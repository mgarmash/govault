package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

// ErrSealedField means an item holds encrypted data GoVault does not know
// and cannot carry to a new key, so the save is refused instead of
// silently dropping or corrupting it.
var ErrSealedField = errors.New("state: this item holds encrypted data GoVault cannot copy to a new key")

// keepSealed returns the unknown fields to send back with a save.
//
// Under the key they were sealed with they are kept byte for byte. Under
// another key (a clone, an import copy, a move to another key) an encrypted
// value can no longer be decrypted by anyone, so each EncString is removed
// where it sits and every plaintext value around it is kept. The save is
// refused with ErrSealedField instead when an EncString sits in an array
// (removing it would shift the rest) or when a value might be an EncString
// of a type GoVault does not know (see crypto.ClassifyEncString).
func keepSealed(m map[string]json.RawMessage, sameKey bool) (map[string]json.RawMessage, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		if sameKey {
			out[k] = append(json.RawMessage(nil), v...)
			continue
		}
		kept, keep, err := stripSealed(v)
		if err != nil {
			return nil, fmt.Errorf("%w (field %q)", err, k)
		}
		if keep {
			out[k] = kept
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// stripSealed removes the EncStrings from one JSON value. keep is false
// when the value itself is an EncString.
func stripSealed(raw json.RawMessage) (json.RawMessage, bool, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false, ErrSealedField
	}
	switch sealedKind(v) {
	case crypto.NotEncString:
		return append(json.RawMessage(nil), raw...), true, nil
	case crypto.MaybeEncString:
		return nil, false, fmt.Errorf("%w: it may hold encrypted data of an unknown kind", ErrSealedField)
	}
	var strip func(v any) (any, bool, error)
	strip = func(v any) (any, bool, error) {
		switch t := v.(type) {
		case string:
			return t, crypto.ClassifyEncString(t) == crypto.NotEncString, nil
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok && crypto.ClassifyEncString(s) != crypto.NotEncString {
					return nil, false, fmt.Errorf("%w: a list holds encrypted data", ErrSealedField)
				}
			}
			for i, e := range t {
				ne, _, err := strip(e)
				if err != nil {
					return nil, false, err
				}
				t[i] = ne
			}
			return t, true, nil
		case map[string]any:
			for k, e := range t {
				ne, keep, err := strip(e)
				if err != nil {
					return nil, false, err
				}
				if keep {
					t[k] = ne
				} else {
					delete(t, k)
				}
			}
			return t, true, nil
		}
		return v, true, nil
	}
	nv, keep, err := strip(v)
	if err != nil || !keep {
		return nil, false, err
	}
	out, err := json.Marshal(nv)
	return out, err == nil, err
}

// sealedKind is the strongest kind found anywhere in v: MaybeEncString
// over IsEncString over NotEncString.
func sealedKind(v any) crypto.EncStringKind {
	kind := crypto.NotEncString
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			switch crypto.ClassifyEncString(t) {
			case crypto.MaybeEncString:
				kind = crypto.MaybeEncString
			case crypto.IsEncString:
				if kind == crypto.NotEncString {
					kind = crypto.IsEncString
				}
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return kind
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
