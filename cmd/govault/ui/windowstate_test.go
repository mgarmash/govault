package ui

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
)

func TestMainWindowPlacement(t *testing.T) {
	if f, w, h, max := MainWindowPlacement(nil); f.Move || w != 1100 || h != 720 || max {
		t.Fatalf("first launch = %+v %vx%v %v, want 1100x720 centered", f, w, h, max)
	}
	f, w, h, max := MainWindowPlacement(&WindowState{X: 40, Y: 60, Width: 1400, Height: 900, Move: true, Maximized: true})
	if !f.Move || f.X != 40 || f.Y != 60 || f.Width != 1400 || f.Height != 900 || w != 1400 || h != 900 || !max {
		t.Fatalf("saved = %+v %vx%v %v", f, w, h, max)
	}
	f, w, h, _ = MainWindowPlacement(&WindowState{X: 10, Y: 10, Width: 500, Height: 300, Move: true})
	if f.Width != 900 || f.Height != 560 || w != 900 || h != 560 {
		t.Fatalf("not clamped to the minimum: %+v %vx%v", f, w, h)
	}
	if f, w, h, _ := MainWindowPlacement(&WindowState{Width: 1300, Height: 800}); f.Move || w != 1300 || h != 800 {
		t.Fatalf("size-only (Linux) = %+v %vx%v", f, w, h)
	}
}

func TestWindowTrackerSavesChangesNotFullScreen(t *testing.T) {
	var saved []WindowState
	posted := make(chan func(), 4)
	tr := NewWindowTracker(func(st WindowState) { saved = append(saved, st) }, func(fn func()) { posted <- fn })
	frame := func(x, y, w, h core.Points) core.WindowFrame {
		return core.WindowFrame{X: x, Y: y, Width: w, Height: h, Move: true}
	}

	// An opening window passes through other frames before it settles.
	tr.Observe(frame(0, 328, 1100, 752), false, false)
	tr.Observe(frame(410, 105, 1100, 752), false, false)
	tr.Observe(frame(100, 100, 1100, 720), false, false)
	tr.Flush()
	if len(saved) != 0 {
		t.Fatalf("saved frames from while the window opened: %+v", saved)
	}
	tr.mu.Lock()
	tr.settleUntil = time.Time{}
	tr.mu.Unlock()

	tr.Observe(frame(100, 100, 1100, 720), false, false)
	tr.Observe(frame(100, 100, 1100, 720), false, false)
	tr.Flush()
	if len(saved) != 0 {
		t.Fatalf("saved an untouched first-launch window: %+v", saved)
	}

	tr.Observe(frame(0, 0, 0, 0), false, false)
	tr.Observe(frame(120, 90, 1300, 800), false, false)
	tr.Observe(frame(140, 90, 1320, 810), false, false)
	if len(saved) != 0 {
		t.Fatal("frame changes were saved without the delay")
	}
	select {
	case fn := <-posted:
		fn()
	case <-time.After(2 * time.Second):
		t.Fatal("delayed save never ran")
	}
	if len(saved) != 1 || saved[0] != (WindowState{X: 140, Y: 90, Width: 1320, Height: 810, Move: true}) {
		t.Fatalf("debounced save = %+v", saved)
	}

	tr.Observe(frame(140, 90, 1320, 810), true, false)
	if len(saved) != 2 || !saved[1].Maximized || saved[1].Width != 1320 {
		t.Fatalf("maximize not saved at once: %+v", saved)
	}

	tr.Observe(frame(140, 90, 1320, 810), false, true)
	tr.Observe(frame(0, 0, 1920, 1080), false, true)
	tr.Flush()
	if len(saved) != 2 {
		t.Fatalf("full screen was saved: %+v", saved[2:])
	}

	var p UserPrefs
	if err := json.Unmarshal([]byte(`{"mainWindow":{"x":1,"y":2,"width":1300,"height":800,"move":true,"maximized":true}}`), &p); err != nil || p.MainWindow == nil || !p.MainWindow.Maximized || p.MainWindow.Width != 1300 {
		t.Fatalf("prefs round trip = %+v, %v", p.MainWindow, err)
	}
	if DefaultUserPrefs().MainWindow != nil {
		t.Fatal("default prefs carry a window frame")
	}
}
