//go:build darwin && !ios

package main

import (
	"sync/atomic"
	"testing"

	"github.com/ebitengine/purego/objc"
)

func postWorkspaceWillSleep() {
	withAutoreleasePool(func() {
		name := newNSString(workspaceWillSleepNotification)
		defer name.Send(selRelease)
		workspaceNotificationCenter().Send(objc.RegisterName("postNotificationName:object:"), name, objc.ID(0))
	})
}

func TestSleepLockListenerRegistersAndCleansUp(t *testing.T) {
	var fired atomic.Int32
	stop, err := startSleepLockListener(func() { fired.Add(1) })
	if err != nil {
		t.Fatalf("startSleepLockListener: %v", err)
	}
	other, err := startSleepLockListener(func() {})
	if err != nil {
		t.Fatalf("second listener: %v", err)
	}
	defer other()

	postWorkspaceWillSleep()
	if got := fired.Load(); got != 1 {
		t.Fatalf("fired = %d after sleep notification, want 1", got)
	}

	stop()
	stop()
	postWorkspaceWillSleep()
	if got := fired.Load(); got != 1 {
		t.Fatalf("fired = %d after stop, want 1", got)
	}
}
