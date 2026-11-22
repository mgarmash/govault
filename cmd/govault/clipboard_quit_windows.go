//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
)

const cfUnicodeText = 13

// clearClipboardIfOwned empties the clipboard now if it still holds secret,
// leaving anything the user copied since alone.
var clearClipboardIfOwned = func(secret string) {
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return
	}
	text := windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p)))
	procGlobalUnlock.Call(h)
	if text == secret {
		procEmptyClipboard.Call()
	}
}
