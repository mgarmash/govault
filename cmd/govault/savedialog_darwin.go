//go:build darwin && !ios

package main

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

const nsModalResponseOK = 1

var (
	saveDialogOnce sync.Once
	saveDialogErr  error

	saveDispatchAsyncF func(queue, context, work uintptr)
	saveDispatchMainQ  uintptr
	saveDialogInvoke   uintptr

	saveDialogMu      sync.Mutex
	saveDialogPending *saveDialogRequest
)

type saveDialogRequest struct {
	name string
	done func(path string, ok bool, err error)
}

func initSaveDialog() error {
	saveDialogOnce.Do(func() {
		if saveDialogErr = initPasteboard(); saveDialogErr != nil {
			return
		}
		lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			saveDialogErr = err
			return
		}
		purego.RegisterLibFunc(&saveDispatchAsyncF, lib, "dispatch_async_f")
		if saveDispatchMainQ, err = purego.Dlsym(lib, "_dispatch_main_q"); err != nil {
			saveDialogErr = err
			return
		}
		saveDialogInvoke = purego.NewCallback(func(uintptr) uintptr {
			saveDialogMu.Lock()
			req := saveDialogPending
			saveDialogPending = nil
			saveDialogMu.Unlock()
			if req != nil {
				path, ok := runSavePanel(req.name)
				go req.done(path, ok, nil)
			}
			return 0
		})
	})
	return saveDialogErr
}

// chooseSavePath asks where to save a file named name and reports the path
// without creating, truncating or otherwise touching it. NSSavePanel already
// confirms replacing an existing file. done runs on another goroutine.
func chooseSavePath(name string, done func(path string, ok bool, err error)) {
	if err := initSaveDialog(); err != nil {
		done("", false, err)
		return
	}
	saveDialogMu.Lock()
	if saveDialogPending != nil {
		saveDialogMu.Unlock()
		done("", false, errors.New("savedialog: another save dialog is open"))
		return
	}
	saveDialogPending = &saveDialogRequest{name: name, done: done}
	saveDialogMu.Unlock()
	saveDispatchAsyncF(saveDispatchMainQ, 0, saveDialogInvoke)
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
