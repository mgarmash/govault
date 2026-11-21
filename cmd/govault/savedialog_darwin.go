//go:build darwin && !ios

package main

import (
	"errors"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

const nsModalResponseOK = 1

var saveDialogOpen atomic.Bool

// chooseSavePath asks where to save a file named name and reports the path
// without creating, truncating or otherwise touching it. NSSavePanel already
// confirms replacing an existing file. done runs on another goroutine.
func chooseSavePath(name string, done func(path string, ok bool, err error)) {
	if !saveDialogOpen.CompareAndSwap(false, true) {
		done("", false, errors.New("savedialog: another save dialog is open"))
		return
	}
	err := runOnMain(func() {
		path, ok := runSavePanel(name)
		saveDialogOpen.Store(false)
		go done(path, ok, nil)
	})
	if err != nil {
		saveDialogOpen.Store(false)
		done("", false, err)
	}
}

func runSavePanel(name string) (string, bool) {
	var path string
	var ok bool
	withAutoreleasePool(func() {
		panel := objc.ID(objc.GetClass("NSSavePanel")).Send(objc.RegisterName("savePanel"))
		if panel == 0 {
			return
		}
		nsName := newNSString(name)
		defer nsName.Send(selRelease)
		panel.Send(objc.RegisterName("setNameFieldStringValue:"), nsName)
		panel.Send(objc.RegisterName("setCanCreateDirectories:"), true)
		if int(panel.Send(objc.RegisterName("runModal"))) != nsModalResponseOK {
			return
		}
		url := panel.Send(objc.RegisterName("URL"))
		if url == 0 {
			return
		}
		str := url.Send(objc.RegisterName("path"))
		if str == 0 {
			return
		}
		p := objc.Send[*byte](str, selUTF8String)
		if p == nil {
			return
		}
		n := 0
		for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
			n++
		}
		path, ok = string(unsafe.Slice(p, n)), n > 0
	})
	return path, ok
}
