//go:build darwin && !ios

package main

import (
	"sync"

	"github.com/ebitengine/purego"
)

var (
	mainQueueOnce sync.Once
	mainQueueErr  error

	mainDispatchAsyncF func(queue, context, work uintptr)
	mainDispatchQueue  uintptr
	mainQueueCallback  uintptr

	mainQueueMu   sync.Mutex
	mainQueueWork []func()
)

// runOnMain runs fn on the AppKit main thread. AppKit loads before any
// caller needs it, through initPasteboard.
func runOnMain(fn func()) error {
	mainQueueOnce.Do(func() {
		if mainQueueErr = initPasteboard(); mainQueueErr != nil {
			return
		}
		lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			mainQueueErr = err
			return
		}
		purego.RegisterLibFunc(&mainDispatchAsyncF, lib, "dispatch_async_f")
		if mainDispatchQueue, err = purego.Dlsym(lib, "_dispatch_main_q"); err != nil {
			mainQueueErr = err
			return
		}
		mainQueueCallback = purego.NewCallback(func(uintptr) uintptr {
			mainQueueMu.Lock()
			var next func()
			if len(mainQueueWork) > 0 {
				next = mainQueueWork[0]
				mainQueueWork = mainQueueWork[1:]
			}
			mainQueueMu.Unlock()
			if next != nil {
				next()
			}
			return 0
		})
	})
	if mainQueueErr != nil {
		return mainQueueErr
	}
	mainQueueMu.Lock()
	mainQueueWork = append(mainQueueWork, fn)
	mainQueueMu.Unlock()
	mainDispatchAsyncF(mainDispatchQueue, 0, mainQueueCallback)
	return nil
}
