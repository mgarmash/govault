//go:build darwin && !ios

package main

import (
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// AppKit's secure text fields enable Secure Event Input while they edit. A
// field removed while first responder, or left focused as the app
// deactivates, can leave it on for the whole process, which blocks system
// shortcuts such as Option-? everywhere.

const secureInputMaxDisables = 16

var (
	secureOnce sync.Once
	secureOK   bool

	dispatchAsyncF func(queue, ctx, work uintptr)
	mainQueue      uintptr
	secureWork     uintptr

	isSecureEventInputEnabled func() bool
	disableSecureEventInput   func() int32

	cgSessionCopyCurrentDictionary func() uintptr
	cfDictionaryGetValue           func(dict, key uintptr) uintptr
	cfNumberGetValue               func(num uintptr, kind int, out unsafe.Pointer) bool
	cfStringCreateWithCString      func(alloc uintptr, s string, encoding uint32) uintptr
	cfRelease                      func(uintptr)
	securePIDKey                   uintptr

	secureQueued atomic.Bool
	secureForce  atomic.Bool

	clsNSApplication, clsSecureTextView, clsSecureTextField      objc.Class
	selSharedApplication, selWindows, selCount, selObjectAtIndex objc.SEL
	selFirstResponder, selMakeFirstResponder, selIsKindOfClass   objc.SEL
)

func initSecureInput() bool {
	secureOnce.Do(func() {
		open := func(path string) uintptr {
			h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err != nil {
				return 0
			}
			return h
		}
		libSystem := open("/usr/lib/libSystem.B.dylib")
		carbon := open("/System/Library/Frameworks/Carbon.framework/Carbon")
		cf := open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
		cg := open("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
		appKit := open("/System/Library/Frameworks/AppKit.framework/AppKit")
		if libSystem == 0 || carbon == 0 || cf == 0 || cg == 0 || appKit == 0 {
			return
		}
		var err error
		if mainQueue, err = purego.Dlsym(libSystem, "_dispatch_main_q"); err != nil {
			return
		}
		purego.RegisterLibFunc(&dispatchAsyncF, libSystem, "dispatch_async_f")
		purego.RegisterLibFunc(&isSecureEventInputEnabled, carbon, "IsSecureEventInputEnabled")
		purego.RegisterLibFunc(&disableSecureEventInput, carbon, "DisableSecureEventInput")
		purego.RegisterLibFunc(&cgSessionCopyCurrentDictionary, cg, "CGSessionCopyCurrentDictionary")
		purego.RegisterLibFunc(&cfDictionaryGetValue, cf, "CFDictionaryGetValue")
		purego.RegisterLibFunc(&cfNumberGetValue, cf, "CFNumberGetValue")
		purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")
		const cfStringEncodingUTF8 = 0x08000100
		securePIDKey = cfStringCreateWithCString(0, "kCGSSessionSecureInputPID", cfStringEncodingUTF8)

		clsNSApplication = objc.GetClass("NSApplication")
		clsSecureTextView = objc.GetClass("NSSecureTextView")
		clsSecureTextField = objc.GetClass("NSSecureTextField")
		selSharedApplication = objc.RegisterName("sharedApplication")
		selWindows = objc.RegisterName("windows")
		selCount = objc.RegisterName("count")
		selObjectAtIndex = objc.RegisterName("objectAtIndex:")
		selFirstResponder = objc.RegisterName("firstResponder")
		selMakeFirstResponder = objc.RegisterName("makeFirstResponder:")
		selIsKindOfClass = objc.RegisterName("isKindOfClass:")

		secureWork = purego.NewCallback(func(uintptr) uintptr {
			secureQueued.Store(false)
			releaseSecureInputOnMain(secureForce.Swap(false))
			return 0
		})
		secureOK = clsNSApplication != 0 && securePIDKey != 0
	})
	return secureOK
}

// ReleaseSecureInput ends the Secure Event Input this process left on, on
// the main thread. With force it first resigns any password field that is
// first responder; without it, a focused password field keeps its secure
// input.
func ReleaseSecureInput(force bool) {
	if !initSecureInput() {
		return
	}
	if force {
		secureForce.Store(true)
	}
	if secureQueued.CompareAndSwap(false, true) {
		dispatchAsyncF(mainQueue, 0, secureWork)
	}
}

func releaseSecureInputOnMain(force bool) {
	app := objc.ID(clsNSApplication).Send(selSharedApplication)
	if app == 0 {
		return
	}
	focused := false
	windows := app.Send(selWindows)
	for i := 0; i < objc.Send[int](windows, selCount); i++ {
		w := windows.Send(selObjectAtIndex, i)
		fr := w.Send(selFirstResponder)
		if fr == 0 || !isSecureResponder(fr) {
			continue
		}
		if force {
			objc.Send[bool](w, selMakeFirstResponder, objc.ID(0))
		} else {
			focused = true
		}
	}
	if focused {
		return
	}
	for i := 0; i < secureInputMaxDisables && secureInputHeldByUs(); i++ {
		disableSecureEventInput()
	}
}

func isSecureResponder(fr objc.ID) bool {
	return (clsSecureTextView != 0 && objc.Send[bool](fr, selIsKindOfClass, objc.ID(clsSecureTextView))) ||
		(clsSecureTextField != 0 && objc.Send[bool](fr, selIsKindOfClass, objc.ID(clsSecureTextField)))
}

func secureInputHeldByUs() bool {
	if !isSecureEventInputEnabled() {
		return false
	}
	dict := cgSessionCopyCurrentDictionary()
	if dict == 0 {
		return false
	}
	defer cfRelease(dict)
	num := cfDictionaryGetValue(dict, securePIDKey)
	if num == 0 {
		return false
	}
	var pid int32
	const cfNumberSInt32Type = 3
	if !cfNumberGetValue(num, cfNumberSInt32Type, unsafe.Pointer(&pid)) {
		return false
	}
	return int(pid) == os.Getpid()
}
