//go:build darwin && !ios

package main

import (
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

const (
	pasteboardTypeString    = "public.utf8-plain-text"
	pasteboardTypeConcealed = "org.nspasteboard.ConcealedType"
	pasteboardTypeTransient = "org.nspasteboard.TransientType"

	nsUTF8StringEncoding = 4
)

var (
	pbInitOnce sync.Once
	pbInitErr  error

	clsNSPasteboard      objc.Class
	clsNSString          objc.Class
	clsNSData            objc.Class
	clsNSAutoreleasePool objc.Class

	selAlloc                       objc.SEL
	selInit                        objc.SEL
	selRelease                     objc.SEL
	selDrain                       objc.SEL
	selGeneralPasteboard           objc.SEL
	selClearContents               objc.SEL
	selChangeCount                 objc.SEL
	selSetStringForType            objc.SEL
	selSetDataForType              objc.SEL
	selStringForType               objc.SEL
	selDataForType                 objc.SEL
	selTypes                       objc.SEL
	selContainsObject              objc.SEL
	selUTF8String                  objc.SEL
	selInitWithBytesLengthEncoding objc.SEL
)

func initPasteboard() error {
	pbInitOnce.Do(func() {
		for _, framework := range []string{
			"/System/Library/Frameworks/Foundation.framework/Foundation",
			"/System/Library/Frameworks/AppKit.framework/AppKit",
		} {
			if _, err := purego.Dlopen(framework, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
				pbInitErr = err
				return
			}
		}

		clsNSPasteboard = objc.GetClass("NSPasteboard")
		clsNSString = objc.GetClass("NSString")
		clsNSData = objc.GetClass("NSData")
		clsNSAutoreleasePool = objc.GetClass("NSAutoreleasePool")
		if clsNSPasteboard == 0 || clsNSString == 0 || clsNSData == 0 || clsNSAutoreleasePool == 0 {
			pbInitErr = errors.New("clipboard: AppKit/Foundation classes unavailable")
			return
		}

		selAlloc = objc.RegisterName("alloc")
		selInit = objc.RegisterName("init")
		selRelease = objc.RegisterName("release")
		selDrain = objc.RegisterName("drain")
		selGeneralPasteboard = objc.RegisterName("generalPasteboard")
		selClearContents = objc.RegisterName("clearContents")
		selChangeCount = objc.RegisterName("changeCount")
		selSetStringForType = objc.RegisterName("setString:forType:")
		selSetDataForType = objc.RegisterName("setData:forType:")
		selStringForType = objc.RegisterName("stringForType:")
		selDataForType = objc.RegisterName("dataForType:")
		selTypes = objc.RegisterName("types")
		selContainsObject = objc.RegisterName("containsObject:")
		selUTF8String = objc.RegisterName("UTF8String")
		selInitWithBytesLengthEncoding = objc.RegisterName("initWithBytes:length:encoding:")
	})
	return pbInitErr
}

func withAutoreleasePool(fn func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(clsNSAutoreleasePool).Send(selAlloc).Send(selInit)
	defer pool.Send(selDrain)
	fn()
}

func newNSString(s string) objc.ID {
	if len(s) == 0 {
		return objc.ID(clsNSString).Send(selAlloc).Send(selInit)
	}
	b := []byte(s)
	id := objc.ID(clsNSString).Send(selAlloc).Send(
		selInitWithBytesLengthEncoding,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(nsUTF8StringEncoding),
	)
	runtime.KeepAlive(b)
	return id
}

func generalPasteboard() objc.ID {
	return objc.ID(clsNSPasteboard).Send(selGeneralPasteboard)
}

type ConcealedClipboard struct {
	mu    sync.Mutex
	timer *time.Timer
}

func NewConcealedClipboard() *ConcealedClipboard {
	return &ConcealedClipboard{}
}

func (c *ConcealedClipboard) Copy(secret string, clearAfter time.Duration) (int, error) {
	if err := initPasteboard(); err != nil {
		return 0, err
	}

	var changeCount int
	var writeOK bool

	withAutoreleasePool(func() {
		pb := generalPasteboard()
		pb.Send(selClearContents)

		nsSecret := newNSString(secret)
		defer nsSecret.Send(selRelease)
		nsTextType := newNSString(pasteboardTypeString)
		defer nsTextType.Send(selRelease)

		writeOK = pb.Send(selSetStringForType, nsSecret, nsTextType) != 0

		// Empty NSData markers tell macOS clipboard managers to ignore this secret.
		emptyData := objc.ID(clsNSData).Send(selAlloc).Send(selInit)
		defer emptyData.Send(selRelease)

		nsConcealed := newNSString(pasteboardTypeConcealed)
		defer nsConcealed.Send(selRelease)
		nsTransient := newNSString(pasteboardTypeTransient)
		defer nsTransient.Send(selRelease)

		pb.Send(selSetDataForType, emptyData, nsConcealed)
		pb.Send(selSetDataForType, emptyData, nsTransient)

		changeCount = int(pb.Send(selChangeCount))
	})

	if !writeOK {
		return 0, errors.New("clipboard: NSPasteboard setString:forType: failed")
	}

	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if clearAfter > 0 {
		savedCount := changeCount
		c.timer = time.AfterFunc(clearAfter, func() {
			c.ClearIfUnchanged(savedCount)
		})
	}
	c.mu.Unlock()

	return changeCount, nil
}

func (c *ConcealedClipboard) ClearIfUnchanged(expectedChangeCount int) bool {
	if err := initPasteboard(); err != nil {
		return false
	}

	var cleared bool
	withAutoreleasePool(func() {
		pb := generalPasteboard()
		if int(pb.Send(selChangeCount)) != expectedChangeCount {
			return
		}
		pb.Send(selClearContents)
		cleared = true
	})
	return cleared
}

func (c *ConcealedClipboard) Cancel() {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
}
