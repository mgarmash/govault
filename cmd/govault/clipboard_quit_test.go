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
