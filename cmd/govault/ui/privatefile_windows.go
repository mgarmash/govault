//go:build windows

package ui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createPrivateTemp creates a new temporary file in dir that only the
// current user can access. Windows ignores Chmod's permission bits, so the
// file is created with a protected DACL granting the user alone full
// access: it inherits nothing from a shared folder, before any byte is
// written. Renaming or hard-linking it keeps that DACL.
func createPrivateTemp(dir, pattern string) (*os.File, error) {
	sddl, err := currentUserOnlySDDL()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	prefix, suffix, _ := strings.Cut(pattern, "*")
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(b[:])+suffix)
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, 0, sa,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "create", Path: name, Err: err}
		}
		return os.NewFile(uintptr(h), name), nil
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: os.ErrExist}
}

// currentUserOnlySDDL is a protected DACL with one entry: full access for
// the user this process runs as.
func currentUserOnlySDDL() (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return "D:P(A;;FA;;;" + user.User.Sid.String() + ")", nil
}
