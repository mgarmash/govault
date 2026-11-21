//go:build darwin && !ios

package main

import (
	"errors"
	"sync"

	"github.com/ebitengine/purego/objc"
)

const (
	sleepLockSupported = true

	workspaceWillSleepNotification = "NSWorkspaceWillSleepNotification"
	screenLockedNotification       = "com.apple.screenIsLocked"
)

var (
	sleepLockOnce  sync.Once
	sleepLockErr   error
	sleepLockClass objc.Class

	sleepLockMu       sync.Mutex
	sleepLockHandlers = map[objc.ID]func(){}

	selNew, selLockEvent, selAddObserver, selRemoveObserver     objc.SEL
	selSharedWorkspace, selNotificationCenter, selDefaultCenter objc.SEL
	clsNSWorkspace, clsNSDistributedNotificationCenter          objc.Class
)

func initSleepLock() error {
	sleepLockOnce.Do(func() {
		if sleepLockErr = initPasteboard(); sleepLockErr != nil {
			return
		}
		clsNSWorkspace = objc.GetClass("NSWorkspace")
		clsNSDistributedNotificationCenter = objc.GetClass("NSDistributedNotificationCenter")
		if clsNSWorkspace == 0 || clsNSDistributedNotificationCenter == 0 {
			sleepLockErr = errors.New("sleeplock: NSWorkspace or NSDistributedNotificationCenter unavailable")
			return
		}
		selNew = objc.RegisterName("new")
		selLockEvent = objc.RegisterName("govaultLockEvent:")
		selAddObserver = objc.RegisterName("addObserver:selector:name:object:")
		selRemoveObserver = objc.RegisterName("removeObserver:")
		selSharedWorkspace = objc.RegisterName("sharedWorkspace")
		selNotificationCenter = objc.RegisterName("notificationCenter")
		selDefaultCenter = objc.RegisterName("defaultCenter")

		sleepLockClass, sleepLockErr = objc.RegisterClass(
			"GoVaultSleepLockObserver",
			objc.GetClass("NSObject"),
			nil,
			nil,
			[]objc.MethodDef{{
				Cmd: selLockEvent,
				Fn: func(self objc.ID, _ objc.SEL, _ objc.ID) {
					sleepLockMu.Lock()
					handler := sleepLockHandlers[self]
					sleepLockMu.Unlock()
					if handler != nil {
						handler()
					}
				},
			}},
		)
	})
	return sleepLockErr
}

func workspaceNotificationCenter() objc.ID {
	return objc.ID(clsNSWorkspace).Send(selSharedWorkspace).Send(selNotificationCenter)
}

func distributedNotificationCenter() objc.ID {
	return objc.ID(clsNSDistributedNotificationCenter).Send(selDefaultCenter)
}

// startSleepLockListener calls onLock, on the AppKit thread, when the Mac is
// about to sleep or the screen locks, until stop is called.
func startSleepLockListener(onLock func()) (stop func(), err error) {
	if err := initSleepLock(); err != nil {
		return nil, err
	}
	var observer objc.ID
	withAutoreleasePool(func() {
		observer = objc.ID(sleepLockClass).Send(selNew)
		if observer == 0 {
			return
		}
		sleepLockMu.Lock()
		sleepLockHandlers[observer] = onLock
		sleepLockMu.Unlock()

		sleepName := newNSString(workspaceWillSleepNotification)
		defer sleepName.Send(selRelease)
		lockedName := newNSString(screenLockedNotification)
		defer lockedName.Send(selRelease)

		workspaceNotificationCenter().Send(selAddObserver, observer, selLockEvent, sleepName, objc.ID(0))
		distributedNotificationCenter().Send(selAddObserver, observer, selLockEvent, lockedName, objc.ID(0))
	})
	if observer == 0 {
		return nil, errors.New("sleeplock: could not create observer")
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			withAutoreleasePool(func() {
				workspaceNotificationCenter().Send(selRemoveObserver, observer)
				distributedNotificationCenter().Send(selRemoveObserver, observer)
			})
			sleepLockMu.Lock()
			delete(sleepLockHandlers, observer)
			sleepLockMu.Unlock()
			observer.Send(selRelease)
		})
	}, nil
}
