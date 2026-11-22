//go:build windows

package ui

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPrivateTempFileHasAUserOnlyProtectedDACL(t *testing.T) {
	f, err := createPrivateTemp(t.TempDir(), ".secret.*")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	_, _ = f.Write([]byte("plaintext"))
	_ = f.Close()
	defer os.Remove(name)

	sd, err := windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL inherits from the folder")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL = %v, %v", dacl, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL has %d entries, want only the current user", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user.User.Sid) {
		t.Fatalf("the only entry is for %v, want the current user %v", sid, user.User.Sid)
	}
}
