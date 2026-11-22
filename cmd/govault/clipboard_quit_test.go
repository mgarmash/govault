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

func newFakeClipboard(board *string, pending *[]func()) *ClipboardAdapter {
	return &ClipboardAdapter{
		concealed: NewConcealedClipboard(),
		post:      func(f func()) { *pending = append(*pending, f) },
		read:      func(f func(string)) { *pending = append(*pending, func() { f(*board) }) },
		write:     func(s string) { *board = s },
		later:     func(f func()) { *pending = append(*pending, f) },
	}
}

func run(pending *[]func()) {
	for len(*pending) > 0 {
		f := (*pending)[0]
		*pending = (*pending)[1:]
		f()
	}
}

func (c *ClipboardAdapter) isOwned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.owned != ""
}

func TestClipboardOwnershipFollowsWhatReadsProve(t *testing.T) {
	var cleared []string
	old := clearClipboardIfOwned
	clearClipboardIfOwned = func(s string) { cleared = append(cleared, s) }
	t.Cleanup(func() { clearClipboardIfOwned = old })

	// Quitting while the timed clear is only queued still clears it.
	board, pending := "hunter2", []func(){}
	c := newFakeClipboard(&board, &pending)
	c.owned = "hunter2"
	c.expire("hunter2")
	c.ClearOnQuit()
	if len(cleared) != 1 || cleared[0] != "hunter2" {
		t.Fatalf("quitting while the clear was queued cleared %v", cleared)
	}

	// A clear GoVault made leaves an empty clipboard, which proves nothing,
	// so the secret stays owned and quitting clears again harmlessly.
	board, pending = "hunter2", nil
	c = newFakeClipboard(&board, &pending)
	c.owned = "hunter2"
	c.expire("hunter2")
	run(&pending)
	if board != "" || !c.isOwned() {
		t.Fatalf("after the clear: clipboard %q, owned %v", board, c.isOwned())
	}

	// Windows refusing the clipboard reads as "": ownership stays and the
	// clear is retried, up to a limit.
	board, pending = "", nil
	c = newFakeClipboard(&board, &pending)
	c.owned = "hunter2"
	c.expire("hunter2")
	run(&pending)
	if !c.isOwned() || c.retries != clipboardRetries {
		t.Fatalf("after failed reads: owned %v, retries %d", c.isOwned(), c.retries)
	}

	// Only a read showing something else proves the secret was replaced.
	board, pending = "something the user copied", nil
	c = newFakeClipboard(&board, &pending)
	c.owned = "hunter2"
	c.expire("hunter2")
	run(&pending)
	if c.isOwned() || board != "something the user copied" {
		t.Fatalf("after a replacement: owned %v, clipboard %q", c.isOwned(), board)
	}
}
