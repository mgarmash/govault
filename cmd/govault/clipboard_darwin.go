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
	clsNSPasteboardItem  objc.Class
	clsNSArray           objc.Class

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
	selArrayWithObject             objc.SEL
	selWriteObjects                objc.SEL
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
		clsNSPasteboardItem = objc.GetClass("NSPasteboardItem")
		clsNSArray = objc.GetClass("NSArray")
		if clsNSPasteboard == 0 || clsNSString == 0 || clsNSData == 0 || clsNSAutoreleasePool == 0 || clsNSPasteboardItem == 0 || clsNSArray == 0 {
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
		selArrayWithObject = objc.RegisterName("arrayWithObject:")
		selWriteObjects = objc.RegisterName("writeObjects:")
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
	mu      sync.Mutex
	timer   *time.Timer
	pending int
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
		nsSecret := newNSString(secret)
		defer nsSecret.Send(selRelease)
		nsTextType := newNSString(pasteboardTypeString)
		defer nsTextType.Send(selRelease)
		nsConcealed := newNSString(pasteboardTypeConcealed)
		defer nsConcealed.Send(selRelease)
		nsTransient := newNSString(pasteboardTypeTransient)
		defer nsTransient.Send(selRelease)
		emptyData := objc.ID(clsNSData).Send(selAlloc).Send(selInit)
		defer emptyData.Send(selRelease)

		// One item carries the text and the markers, so clipboard managers
		// never observe the secret without them.
		item := objc.ID(clsNSPasteboardItem).Send(selAlloc).Send(selInit)
		defer item.Send(selRelease)
		if item.Send(selSetStringForType, nsSecret, nsTextType) == 0 ||
			item.Send(selSetDataForType, emptyData, nsConcealed) == 0 ||
			item.Send(selSetDataForType, emptyData, nsTransient) == 0 {
			return
		}
		items := objc.ID(clsNSArray).Send(selArrayWithObject, item)

		pb := generalPasteboard()
		pb.Send(selClearContents)
		writeOK = pb.Send(selWriteObjects, items) != 0
		changeCount = int(pb.Send(selChangeCount))
	})

	if !writeOK {
		return 0, errors.New("clipboard: NSPasteboard writeObjects: failed")
	}

	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.pending = 0
	if clearAfter > 0 {
		savedCount := changeCount
		c.pending = savedCount
		c.timer = time.AfterFunc(clearAfter, func() {
			c.mu.Lock()
			if c.pending == savedCount {
				c.pending = 0
			}
			c.mu.Unlock()
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
	c.pending = 0
	c.mu.Unlock()
}

// ClearPending clears a copied secret whose auto-clear has not run yet,
// as long as nothing else was copied since. It is called on quit.
func (c *ConcealedClipboard) ClearPending() {
	c.mu.Lock()
	pending := c.pending
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.pending = 0
	c.mu.Unlock()
	if pending != 0 {
		c.ClearIfUnchanged(pending)
	}
}
