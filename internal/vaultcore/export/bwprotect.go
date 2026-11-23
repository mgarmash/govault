package export

import (
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
	f, err := sealWithPassword(plaintext, password, cfg)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(bwProtectedFile(f), "", "  ")
}

// bwProtectedFile is protectedFile as Bitwarden's CLI writes it, which
// leaves out the KDF fields its KDF has none of.
type bwProtectedFile struct {
	Encrypted         bool    `json:"encrypted"`
	PasswordProtected bool    `json:"passwordProtected"`
	Salt              string  `json:"salt"`
	KDFType           int     `json:"kdfType"`
	KDFIterations     uint32  `json:"kdfIterations"`
	KDFMemory         *uint32 `json:"kdfMemory,omitempty"`
	KDFParallelism    *uint32 `json:"kdfParallelism,omitempty"`
	EncKeyValidation  string  `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string  `json:"data"`
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
