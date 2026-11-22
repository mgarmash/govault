//go:build windows

package keyring

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	// Credential Manager limits a generic credential to 5 * 512 bytes.
	credMaxBlobSize = 2560
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

// credman stores generic credentials in the user's Windows Credential
// Manager, which only that user can read.
type credman struct{}

func system() (Store, error) {
	if err := advapi32.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return credman{}, nil
}

func (credman) Name() string { return "windows-credential-manager" }

func target(service, account string) (*uint16, error) {
	return windows.UTF16PtrFromString(service + ":" + account)
}

func (credman) Get(service, account string) ([]byte, error) {
	name, err := target(service, account)
	if err != nil {
		return nil, err
	}
	var cred *credential
	r, _, callErr := procCredRead.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&cred)))
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring: CredRead: %w", callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))
	out := make([]byte, cred.CredentialBlobSize)
	if cred.CredentialBlobSize > 0 {
		copy(out, unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize))
	}
	return out, nil
}

func (credman) Set(service, account string, secret []byte) error {
	if len(secret) > credMaxBlobSize {
		return fmt.Errorf("keyring: secret of %d bytes exceeds the Credential Manager limit", len(secret))
	}
	name, err := target(service, account)
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         name,
		CredentialBlobSize: uint32(len(secret)),
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	if len(secret) > 0 {
		cred.CredentialBlob = &secret[0]
	}
	if r, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0); r == 0 {
		return fmt.Errorf("keyring: CredWrite: %w", callErr)
	}
	return nil
}

func (credman) Delete(service, account string) error {
	name, err := target(service, account)
	if err != nil {
		return err
	}
	if r, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0); r == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("keyring: CredDelete: %w", callErr)
	}
	return nil
}
