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
	default:
		return ""
	}
}
