package main

import (
	"testing"
	"time"
)

func TestClearOnQuitClearsAnOwnedTimedSecret(t *testing.T) {
	var cleared []string
	old := clearClipboardIfOwned
	clearClipboardIfOwned = func(s string) { cleared = append(cleared, s) }
	t.Cleanup(func() { clearClipboardIfOwned = old })

	c := &ClipboardAdapter{concealed: NewConcealedClipboard()}
	c.mu.Lock()
	c.owned = "hunter2"
	c.timer = time.AfterFunc(time.Hour, func() {})
	c.mu.Unlock()
	c.ClearOnQuit()
	if len(cleared) != 1 || cleared[0] != "hunter2" {
		t.Fatalf("cleared = %v, want the owned secret cleared at quit", cleared)
	}
	c.ClearOnQuit()
	if len(cleared) != 1 {
		t.Fatal("quit cleared the clipboard again with nothing owned")
	}
}

func TestClipboardStaysOwnedUntilTheClearIsConfirmed(t *testing.T) {
	var cleared []string
	old := clearClipboardIfOwned
	clearClipboardIfOwned = func(s string) { cleared = append(cleared, s) }
	t.Cleanup(func() { clearClipboardIfOwned = old })

	board := ""
	var pending []func()
	c := &ClipboardAdapter{
		concealed: NewConcealedClipboard(),
		post:      func(f func()) { pending = append(pending, f) },
		read:      func(f func(string)) { pending = append(pending, func() { f(board) }) },
		write:     func(s string) { board = s },
	}
	c.mu.Lock()
	c.owned = "hunter2"
	c.mu.Unlock()
	board = "hunter2"

	c.expire("hunter2")
	// The timer fired and its clear is queued, but nothing ran yet: the app
	// quits now.
	c.ClearOnQuit()
	if len(cleared) != 1 || cleared[0] != "hunter2" {
		t.Fatalf("quitting while the clear was queued cleared %v", cleared)
	}

	// Run the queued work: the clear happens and is confirmed.
	c.mu.Lock()
	c.owned = "hunter2"
	c.mu.Unlock()
	for len(pending) > 0 {
		f := pending[0]
		pending = pending[1:]
		f()
	}
	if board != "" {
		t.Fatalf("clipboard = %q", board)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owned != "" {
		t.Fatal("still owned after a confirmed clear")
	}
}
