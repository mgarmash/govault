//go:build darwin && !ios

package main

import (
	"testing"
	"time"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

func pasteboardHasType(pbType string) bool {
	if err := initPasteboard(); err != nil {
		return false
	}
	var has bool
	withAutoreleasePool(func() {
		pb := generalPasteboard()
		types := pb.Send(selTypes)
		if types == 0 {
			return
		}
		nsType := newNSString(pbType)
		defer nsType.Send(selRelease)
		has = types.Send(selContainsObject, nsType) != 0
	})
	return has
}

func pasteboardReadString() string {
	if err := initPasteboard(); err != nil {
		return ""
	}
	var out string
	withAutoreleasePool(func() {
		pb := generalPasteboard()
		nsType := newNSString(pasteboardTypeString)
		defer nsType.Send(selRelease)
		str := pb.Send(selStringForType, nsType)
		if str == 0 {
			return
		}
		p := objc.Send[*byte](str, selUTF8String)
		if p == nil {
			return
		}
		out = cStringCopy(p)
	})
	return out
}

func pasteboardWritePlain(s string) int {
	if err := initPasteboard(); err != nil {
		return 0
	}
	var count int
	withAutoreleasePool(func() {
		pb := generalPasteboard()
		pb.Send(selClearContents)
		nsVal := newNSString(s)
		defer nsVal.Send(selRelease)
		nsType := newNSString(pasteboardTypeString)
		defer nsType.Send(selRelease)
		pb.Send(selSetStringForType, nsVal, nsType)
		count = int(pb.Send(selChangeCount))
	})
	return count
}

func cStringCopy(p *byte) string {
	var n int
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}

func TestConcealedClipboardMarkersAndAutoClear(t *testing.T) {
	cb := NewConcealedClipboard()
	defer cb.Cancel()
	defer func() {
		if err := initPasteboard(); err == nil {
			withAutoreleasePool(func() {
				generalPasteboard().Send(selClearContents)
			})
		}
	}()

	const secret = "govault-unit-test-secret"
	changeCount, err := cb.Copy(secret, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("Copy failed: %v", err)
	}
	if changeCount <= 0 {
		t.Fatalf("expected positive changeCount, got %d", changeCount)
	}

	if got := pasteboardReadString(); got != secret {
		t.Fatalf("pasteboard text = %q, want %q", got, secret)
	}
	if !pasteboardHasType(pasteboardTypeConcealed) {
		t.Fatalf("missing pasteboard type %q", pasteboardTypeConcealed)
	}
	if !pasteboardHasType(pasteboardTypeTransient) {
		t.Fatalf("missing pasteboard type %q", pasteboardTypeTransient)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pasteboardReadString() == "" {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("pasteboard was not cleared after auto-clear timeout; still %q", pasteboardReadString())
}

func TestConcealedClipboardSkipsClearWhenChangeCountChanged(t *testing.T) {
	cb := NewConcealedClipboard()
	defer cb.Cancel()
	defer func() {
		if err := initPasteboard(); err == nil {
			withAutoreleasePool(func() {
				generalPasteboard().Send(selClearContents)
			})
		}
	}()

	savedCount, err := cb.Copy("govault-old-secret", 0)
	if err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	const userText = "user-copied-something-else"
	newCount := pasteboardWritePlain(userText)
	if newCount == savedCount {
		t.Fatalf("expected changeCount to advance after external write (still %d)", savedCount)
	}

	if cleared := cb.ClearIfUnchanged(savedCount); cleared {
		t.Fatalf("ClearIfUnchanged returned true despite changed changeCount")
	}
	if got := pasteboardReadString(); got != userText {
		t.Fatalf("external clipboard content was clobbered: got %q, want %q", got, userText)
	}
}

func TestConcealedClipboardClearPendingOnQuit(t *testing.T) {
	cb := NewConcealedClipboard()
	if _, err := cb.Copy("govault-quit-secret", time.Hour); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}
	cb.ClearPending()
	if got := pasteboardReadString(); got != "" {
		t.Fatalf("pending secret survived quit: %q", got)
	}
}
