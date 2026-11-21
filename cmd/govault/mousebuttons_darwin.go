//go:build darwin && !ios

package main

import (
	"sync"

	"github.com/ebitengine/purego/objc"
)

const (
	nsEventMaskOtherMouseDown = 1 << 25
	mouseButtonBack           = 3
	mouseButtonForward        = 4
)

// startMouseNavigation reports the Back and Forward side buttons of a mouse
// pressed over GoVault: a local NSEvent monitor only sees events sent to
// this app while it is active. The buttons are consumed; other clicks pass
// through. stop removes the monitor.
func startMouseNavigation(onBack, onForward func()) (stop func(), err error) {
	var (
		mu      sync.Mutex
		monitor objc.ID
		stopped bool
	)
	selButtonNumber := objc.RegisterName("buttonNumber")
	handler := objc.NewBlock(func(_ objc.Block, event objc.ID) objc.ID {
		switch objc.Send[int](event, selButtonNumber) {
		case mouseButtonBack:
			onBack()
			return 0
		case mouseButtonForward:
			onForward()
			return 0
		}
		return event
	})
	err = runOnMain(func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		monitor = objc.ID(objc.GetClass("NSEvent")).Send(
			objc.RegisterName("addLocalMonitorForEventsMatchingMask:handler:"),
			uint64(nsEventMaskOtherMouseDown), handler)
		if monitor != 0 {
			monitor.Send(objc.RegisterName("retain"))
		}
	})
	if err != nil {
		handler.Release()
		return func() {}, err
	}
	return func() {
		_ = runOnMain(func() {
			mu.Lock()
			defer mu.Unlock()
			if stopped {
				return
			}
			stopped = true
			if monitor != 0 {
				objc.ID(objc.GetClass("NSEvent")).Send(objc.RegisterName("removeMonitor:"), monitor)
				monitor.Send(objc.RegisterName("release"))
				monitor = 0
			}
			handler.Release()
		})
	}, nil
}
