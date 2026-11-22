package export

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// Protect wraps plaintext, a plain JSON export, into a password-protected
// export laid out as Bitwarden's CLI writes it: the KDF fields of cfg only,
// pretty-printed with two spaces. Read opens it.
func Protect(plaintext, password []byte, cfg crypto.KDFConfig) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("export: a password is required")
	}
	var saltBytes [16]byte
	if _, err := rand.Read(saltBytes[:]); err != nil {
		return nil, err
	}
	salt := base64.StdEncoding.EncodeToString(saltBytes[:])
	key, err := deriveKey(password, salt, cfg)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	validation, err := crypto.EncryptString(randomGUID(), key)
	if err != nil {
		return nil, err
	}
	data, err := crypto.EncryptBytes(plaintext, key)
	if err != nil {
		return nil, err
	}
	type kv struct {
		k string
		v any
	}
	fields := []kv{{"encrypted", true}, {"passwordProtected", true}, {"salt", salt}, {"kdfType", int(cfg.Type)}, {"kdfIterations", cfg.Iterations}}
	if cfg.Type == crypto.KDFArgon2id {
		fields = append(fields, kv{"kdfMemory", cfg.MemoryMB}, kv{"kdfParallelism", cfg.Parallelism})
	}
	fields = append(fields, kv{"encKeyValidation_DO_NOT_EDIT", validation}, kv{"data", data.String()})
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, f := range fields {
		k, _ := json.Marshal(f.k)
		v, _ := json.Marshal(f.v)
		b.WriteString("  " + string(k) + ": " + string(v))
		if i < len(fields)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}")
	return b.Bytes(), nil
}

// AccountExport is an export encrypted with the account's own key: the
// items and folders as the server stores them.
type AccountExport struct {
	Encrypted        bool              `json:"encrypted"`
	EncKeyValidation string            `json:"encKeyValidation_DO_NOT_EDIT"`
	Folders          []json.RawMessage `json:"folders"`
	Items            []json.RawMessage `json:"items"`
}

// IsAccountExport reports whether data is an account-key export.
func IsAccountExport(data []byte) bool {
	var head struct {
		Encrypted         bool `json:"encrypted"`
		PasswordProtected bool `json:"passwordProtected"`
	}
	return json.Unmarshal(data, &head) == nil && head.Encrypted && !head.PasswordProtected
}
