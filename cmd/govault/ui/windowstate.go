package ui

import (
	"sync"
	"time"

	"github.com/nsgo-dev/nsgo/core"
)

const (
	MainWindowWidth     core.Points = 1100
	MainWindowHeight    core.Points = 720
	MainWindowMinWidth  core.Points = 900
	MainWindowMinHeight core.Points = 560

	windowSaveDelay = 500 * time.Millisecond
	// windowSettle is how long an opening window keeps reporting the frames
	// it passes through (unplaced, then with and without its title bar)
	// before the one it opened at.
	windowSettle = time.Second
)

// WindowState is the main window as it was last left: its normal frame
// (the one it has when not maximized or in full screen) and whether it was
// maximized. Move is false where the platform reports no position (Linux),
// so only the size comes back there.
type WindowState struct {
	X         float32 `json:"x"`
	Y         float32 `json:"y"`
	Width     float32 `json:"width"`
	Height    float32 `json:"height"`
	Move      bool    `json:"move"`
	Maximized bool    `json:"maximized"`
}

// MainWindowPlacement is how to open the main window: at the saved frame,
// at least the minimum size, or at the default size centered when nothing
// was saved, and whether to maximize it once it is open.
func MainWindowPlacement(saved *WindowState) (frame core.WindowFrame, width, height core.Points, maximize bool) {
	if saved == nil || saved.Width <= 0 || saved.Height <= 0 {
		return core.WindowFrame{}, MainWindowWidth, MainWindowHeight, false
	}
	width = max(core.Points(saved.Width), MainWindowMinWidth)
	height = max(core.Points(saved.Height), MainWindowMinHeight)
	if saved.Move {
		frame = core.WindowFrame{X: core.Points(saved.X), Y: core.Points(saved.Y), Move: true, Width: width, Height: height}
	}
	return frame, width, height, saved.Maximized
}

// WindowTracker turns the frame and state changes of the main window into
// saved WindowStates. It ignores full screen, so leaving the app in full
// screen keeps the frame and maximized flag from before it, and it saves
// nothing until the window was moved, resized or (un)maximized after it
// settled, so a first launch keeps the default. Frame changes are saved after a short delay so
// a drag does not write on every step; Flush saves at once.
type WindowTracker struct {
	save func(WindowState)
	post func(func())

	mu          sync.Mutex
	settleUntil time.Time
	baseline    *WindowState
	current     WindowState
	dirty       bool
	timer       *time.Timer
}

// NewWindowTracker saves through save; post runs the delayed save where
// save may run, such as the engine goroutine.
func NewWindowTracker(save func(WindowState), post func(func())) *WindowTracker {
	return &WindowTracker{save: save, post: post, settleUntil: time.Now().Add(windowSettle)}
}

// Observe records the window as it is now.
func (t *WindowTracker) Observe(frame core.WindowFrame, maximized, fullScreen bool) {
	if fullScreen || frame.Width <= 0 || frame.Height <= 0 {
		return
	}
	st := WindowState{
		X: float32(frame.X), Y: float32(frame.Y), Move: frame.Move,
		Width: float32(frame.Width), Height: float32(frame.Height),
		Maximized: maximized,
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.baseline == nil || time.Now().Before(t.settleUntil) {
		t.baseline = &st
		t.current = st
		return
	}
	if st == t.current {
		return
	}
	maximizedChanged := st.Maximized != t.current.Maximized
	t.current = st
	if !t.dirty && st == *t.baseline {
		return
	}
	t.dirty = true
	if maximizedChanged {
		t.flushLocked()
		return
	}
	if t.timer != nil {
		t.timer.Stop()
	}
	t.timer = time.AfterFunc(windowSaveDelay, func() { t.post(t.Flush) })
}

// Flush saves a pending change now.
func (t *WindowTracker) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushLocked()
}

func (t *WindowTracker) flushLocked() {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	if !t.dirty {
		return
	}
	t.dirty = false
	t.save(t.current)
}

// SaveMainWindow stores the main window state in the preferences.
func (m *AppModel) SaveMainWindow(st WindowState) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		cp := st
		p.MainWindow = &cp
		return p
	})
}
