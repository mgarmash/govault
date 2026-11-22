package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type EncType int

const (
	EncAesCbc256B64           EncType = 0
	EncAesCbc256HmacSha256B64 EncType = 2
	EncRsa2048OaepSha256B64   EncType = 3
	EncRsa2048OaepSha1B64     EncType = 4

	EncRsa2048OaepSha256HmacSha256B64 EncType = 5
	EncRsa2048OaepSha1HmacSha256B64   EncType = 6
)

type EncString struct {
	Type EncType
	IV   []byte
	CT   []byte
	MAC  []byte
}

func ParseEncString(s string) (*EncString, error) {
	typeStr, body, ok := strings.Cut(s, ".")
	if !ok || typeStr == "" || body == "" {
		return nil, ErrInvalidEncString
	}

	typeNum, err := strconv.Atoi(typeStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid type prefix", ErrInvalidEncString)
	}
	encType := EncType(typeNum)

	switch encType {
	case EncAesCbc256B64:
		parts := strings.Split(body, "|")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, ErrInvalidEncString
		}
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(iv) != aes.BlockSize {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, IV: iv, CT: ct}, nil

	case EncAesCbc256HmacSha256B64:
		parts := strings.Split(body, "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, ErrInvalidEncString
		}
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(iv) != aes.BlockSize {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		mac, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(mac) != sha256.Size {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, IV: iv, CT: ct, MAC: mac}, nil

	case EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64:
		if strings.Contains(body, "|") {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(body)
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		return &EncString{Type: encType, CT: ct}, nil

	case EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64:
		parts := strings.Split(body, "|")
		if len(parts) > 2 || parts[0] == "" {
			return nil, ErrInvalidEncString
		}
		ct, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil || len(ct) == 0 {
			return nil, ErrInvalidEncString
		}
		out := &EncString{Type: encType, CT: ct}
		if len(parts) == 2 {
			if out.MAC, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
				return nil, ErrInvalidEncString
			}
		}
		return out, nil

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncType, encType)
	}
}

func (e *EncString) String() string {
	if e == nil {
		return ""
	}
	switch e.Type {
	case EncAesCbc256B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.IV) + "|" +
			base64.StdEncoding.EncodeToString(e.CT)
	case EncAesCbc256HmacSha256B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.IV) + "|" +
			base64.StdEncoding.EncodeToString(e.CT) + "|" +
			base64.StdEncoding.EncodeToString(e.MAC)
	case EncRsa2048OaepSha256B64, EncRsa2048OaepSha1B64:
		return strconv.Itoa(int(e.Type)) + "." +
			base64.StdEncoding.EncodeToString(e.CT)
	case EncRsa2048OaepSha256HmacSha256B64, EncRsa2048OaepSha1HmacSha256B64:
		out := strconv.Itoa(int(e.Type)) + "." + base64.StdEncoding.EncodeToString(e.CT)
		if len(e.MAC) > 0 {
			out += "|" + base64.StdEncoding.EncodeToString(e.MAC)
		}
		return out
	default:
		return ""
	}
}

// LooksLikeEncString reports whether s has the shape of an EncString of any
// type, including types this package cannot decrypt: a numeric type, a dot,
// then one to three non-empty standard base64 parts separated by "|".
func LooksLikeEncString(s string) bool {
	typeStr, body, ok := strings.Cut(s, ".")
	if !ok || len(typeStr) == 0 || len(typeStr) > 2 || body == "" {
		return false
	}
	for _, r := range typeStr {
		if r < '0' || r > '9' {
			return false
		}
	}
	parts := strings.Split(body, "|")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if b, err := base64.StdEncoding.DecodeString(p); err != nil || len(b) == 0 {
			return false
		}
	}
	return true
}
