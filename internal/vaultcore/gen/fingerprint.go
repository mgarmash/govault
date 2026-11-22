package gen

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"math"
	"math/big"
)

// FingerprintPhrase is Bitwarden's fingerprint phrase for a public key
// (SPKI DER) and its owner's user ID: HKDF-Expand-SHA256 of SHA-256(key)
// with the user ID as info, read as a big-endian number in base 7776 and
// spelled with the EFF large wordlist, least significant digit first, in
// as many words as 64 bits of entropy need (5).
func FingerprintPhrase(userID string, publicKey []byte) ([]string, error) {
	if len(publicKey) == 0 {
		return nil, errors.New("gen: public key is required for a fingerprint")
	}
	keyHash := sha256.Sum256(publicKey)
	userHash, err := hkdf.Expand(sha256.New, keyHash[:], userID, 32)
	if err != nil {
		return nil, err
	}
	return hashPhrase(userHash), nil
}

func hashPhrase(hash []byte) []string {
	n := len(passphraseWords)
	numWords := int(math.Ceil(64 / math.Log2(float64(n))))
	num := new(big.Int).SetBytes(hash)
	base := big.NewInt(int64(n))
	words := make([]string, 0, numWords)
	for range numWords {
		rem := new(big.Int)
		num.DivMod(num, base, rem)
		words = append(words, passphraseWords[rem.Int64()])
	}
	return words
}
