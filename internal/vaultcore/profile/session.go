package profile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
)

const sessionInfo = "govault-cli session v1"

// sessionBinding is what a session record is valid for. It is the
// authenticated data of the sealed user key.
type sessionBinding struct {
	Version    int           `json:"version"`
	ProfileID  string        `json:"profileId"`
	AccountID  string        `json:"accountId"`
	LoginID    string        `json:"loginId"`
	Endpoints  api.Endpoints `json:"endpoints"`
	Generation uint64        `json:"generation"`
}

type sessionRecord struct {
	sessionBinding
	Sealed []byte `json:"sealed"`
}

func bindingFor(ps *profileState, acct *accountState, generation uint64) sessionBinding {
	return sessionBinding{
		Version:    formatVersion,
		ProfileID:  ps.ProfileID,
		AccountID:  acct.AccountID,
		LoginID:    acct.LoginID,
		Endpoints:  acct.Endpoints,
		Generation: generation,
	}
}

// newSession seals userKey under a fresh random secret and writes the
// record for generation; it returns the secret, which is never stored.
// The caller holds the state lock exclusively.
func (p *Profile) newSession(ps *profileState, acct *accountState, generation uint64, userKey *crypto.SymmetricKey) (string, error) {
	var secret [64]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(secret[:])
	key, err := crypto.SealKey(secret[:], sessionInfo)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(key[:])
	binding := bindingFor(ps, acct, generation)
	ad, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	raw := userKey.Bytes()
	sealed, err := crypto.Seal(key, raw[:], ad)
	crypto.ZeroBytes(raw[:])
	if err != nil {
		return "", err
	}
	if err := writeJSON(p.path(sessionFile), sessionRecord{sessionBinding: binding, Sealed: sealed}); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(secret[:]), nil
}

// openSession returns the user key the session key unlocks, or ErrLocked
// when the key is missing, wrong, or from an earlier session.
func (p *Profile) openSession(ps *profileState, acct *accountState, sessionKey string) (*crypto.SymmetricKey, error) {
	if sessionKey == "" {
		return nil, ErrLocked
	}
	secret, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil || len(secret) != 64 {
		return nil, ErrLocked
	}
	defer crypto.ZeroBytes(secret)
	var rec sessionRecord
	if err := readJSON(p.path(sessionFile), &rec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrLocked
		}
		return nil, err
	}
	want := bindingFor(ps, acct, ps.Generation)
	if rec.sessionBinding != want {
		return nil, ErrLocked
	}
	key, err := crypto.SealKey(secret, sessionInfo)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key[:])
	ad, err := json.Marshal(want)
	if err != nil {
		return nil, err
	}
	raw, err := crypto.Open(key, rec.Sealed, ad)
	if err != nil {
		return nil, ErrLocked
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

// RandomSessionKey is a key in the session format that unlocks nothing,
// which `login --apikey` prints as Bitwarden's does.
func RandomSessionKey() string {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}
