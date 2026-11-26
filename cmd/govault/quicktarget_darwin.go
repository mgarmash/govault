//go:build darwin && !ios

package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

// Quick Access fills the frontmost application's focused text field with
// CoreGraphics Unicode key events posted to that process only. It never uses
// the clipboard, Return, a global event tap or another key window. The panel
// is nonactivating, so the target app stays frontmost while it is key; every
// phase re-reads the frontmost PID and bundle and aborts without typing when
// they changed. Accessibility is consulted only for the window title and the
// browser origin shown in the panel, never to decide whether fill is allowed.

const (
	quickAXMaxAncestors = 64
	quickAXTimeout      = 2.0
	quickAXRoleWindow   = "AXWindow"
	quickAXRoleSheet    = "AXSheet"
	quickAXRoleApp      = "AXApplication"
	quickAXRoleWebArea  = "AXWebArea"

	quickKeyTab      = 48 // kVK_Tab
	quickTabWait     = 250 * time.Millisecond
	quickTabPoll     = 10 * time.Millisecond
	quickTabFallback = 80 * time.Millisecond

	// CGEventKeyboardSetUnicodeString takes at most 20 UTF-16 units per event.
	quickUnicodeChunk = 20
)

var (
	errQuickAccessPermission  = errors.New("macOS blocked sending keystrokes. Use Enable typing in Quick Access.")
	errQuickAccessUnavailable = errors.New("quick access: macOS input events are unavailable")
	errQuickTargetUnavailable = errors.New("quick access: no text field is available")
	errQuickTargetChanged     = errors.New("quick access: the destination app changed")
	errQuickValueRejected     = errors.New("quick access: the value contains a line break or control character")
)

// Only known browsers may report a trustworthy AX web-area URL. Any other app
// with web ancestry is not asked for an origin, so suggestions stay copy-only.
var quickSupportedBrowsers = map[string]bool{
	"com.apple.Safari":                    true,
	"com.apple.SafariTechnologyPreview":   true,
	"com.google.Chrome":                   true,
	"com.google.Chrome.beta":              true,
	"com.google.Chrome.canary":            true,
	"com.microsoft.edgemac":               true,
	"com.microsoft.edgemac.Beta":          true,
	"com.microsoft.edgemac.Dev":           true,
	"com.microsoft.edgemac.Canary":        true,
	"org.mozilla.firefox":                 true,
	"org.mozilla.firefoxdeveloperedition": true,
	"com.brave.Browser":                   true,
	"com.brave.Browser.beta":              true,
	"com.brave.Browser.dev":               true,
	"com.brave.Browser.nightly":           true,
	"com.vivaldi.Vivaldi":                 true,
	"company.thebrowser.Browser":          true,
	"com.operasoftware.Opera":             true,
	"com.operasoftware.OperaGX":           true,
	"app.zen-browser.zen":                 true,
}

// System surfaces, password managers and terminals are never fill targets,
// even when their focused control looks like a text field.
var quickBlockedApps = map[string]bool{
	"com.apple.loginwindow":        true,
	"com.apple.SecurityAgent":      true,
	"com.apple.keychainaccess":     true,
	"com.apple.Passwords":          true,
	"com.apple.ScreenSaver.Engine": true,
	"com.1password.1password":      true,
	"com.agilebits.onepassword7":   true,
	"com.bitwarden.desktop":        true,
	"org.keepassxc.keepassxc":      true,
	"com.lastpass.LastPass":        true,
	"com.dashlane.Dashlane":        true,
	"com.nordpass.NordPass":        true,
	"in.sinew.Enpass-Desktop":      true,
	"com.apple.Terminal":           true,
	"com.googlecode.iterm2":        true,
	"dev.warp.Warp-Stable":         true,
	"io.alacritty":                 true,
	"net.kovidgoyal.kitty":         true,
	"com.github.wez.wezterm":       true,
	"com.mitchellh.ghostty":        true,
	"co.zeit.hyper":                true,
	"org.tabby":                    true,
	"com.termius.mac":              true,
}

type quickCoreFoundation struct {
	release          func(uintptr)
	retain           func(uintptr) uintptr
	equal            func(uintptr, uintptr) bool
	stringCreate     func(uintptr, *byte, int64, uint32, bool) uintptr
	stringLength     func(uintptr) int64
	stringMaxSize    func(int64, uint32) int64
	stringGetCString func(uintptr, *byte, int64, uint32) bool
	urlGetString     func(uintptr) uintptr
	getTypeID        func(uintptr) uintptr
	urlTypeID        func() uintptr
	stringTypeID     func() uintptr
}

type quickCoreGraphics struct {
	eventCreateKeyboard func(uintptr, uint16, bool) uintptr
	eventSetUnicode     func(uintptr, uint64, *uint16)
	eventPostToPid      func(int32, uintptr)
	preflightPostEvent  func() bool
	requestPostEvent    func() bool
}

type quickAccessibility struct {
	createApplication func(int32) uintptr
	copyAttribute     func(uintptr, uintptr, *uintptr) int32
	setTimeout        func(uintptr, float32) int32
	processTrusted    func() bool
}

type quickAXAttributes struct {
	focusedUIElement uintptr
	focusedWindow    uintptr
	role             uintptr
	title            uintptr
	parent           uintptr
	url              uintptr
}

type quickWorkspaceNames struct {
	workspace                  objc.Class
	shared, frontmost          objc.SEL
	pid, bundle, localizedName objc.SEL
}

var (
	quickAXOnce sync.Once
	quickAXErr  error
	quickCF     quickCoreFoundation
	quickCG     quickCoreGraphics
	quickAX     quickAccessibility
	quickAttr   quickAXAttributes
	quickWorks  quickWorkspaceNames
)

func initQuickAccessTarget() error {
	quickAXOnce.Do(func() {
		cfLib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			quickAXErr = err
			return
		}
		for _, path := range []string{
			"/System/Library/Frameworks/Foundation.framework/Foundation",
			"/System/Library/Frameworks/AppKit.framework/AppKit",
		} {
			if _, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
				quickAXErr = err
				return
			}
		}
		axLib, err := purego.Dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			quickAXErr = err
			return
		}
		if _, err := purego.Dlsym(axLib, "AXUIElementCreateApplication"); err != nil {
			// AX normally comes through the umbrella's HIServices re-export.
			axLib, err = purego.Dlopen("/System/Library/Frameworks/ApplicationServices.framework/Frameworks/HIServices.framework/HIServices", purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err != nil {
				quickAXErr = err
				return
			}
		}

		purego.RegisterLibFunc(&quickCF.release, cfLib, "CFRelease")
		purego.RegisterLibFunc(&quickCF.retain, cfLib, "CFRetain")
		purego.RegisterLibFunc(&quickCF.equal, cfLib, "CFEqual")
		purego.RegisterLibFunc(&quickCF.stringCreate, cfLib, "CFStringCreateWithBytes")
		purego.RegisterLibFunc(&quickCF.stringLength, cfLib, "CFStringGetLength")
		purego.RegisterLibFunc(&quickCF.stringMaxSize, cfLib, "CFStringGetMaximumSizeForEncoding")
		purego.RegisterLibFunc(&quickCF.stringGetCString, cfLib, "CFStringGetCString")
		purego.RegisterLibFunc(&quickCF.urlGetString, cfLib, "CFURLGetString")
		purego.RegisterLibFunc(&quickCF.getTypeID, cfLib, "CFGetTypeID")
		purego.RegisterLibFunc(&quickCF.urlTypeID, cfLib, "CFURLGetTypeID")
		purego.RegisterLibFunc(&quickCF.stringTypeID, cfLib, "CFStringGetTypeID")

		cgLib, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			quickAXErr = err
			return
		}
		purego.RegisterLibFunc(&quickCG.eventCreateKeyboard, cgLib, "CGEventCreateKeyboardEvent")
		purego.RegisterLibFunc(&quickCG.eventSetUnicode, cgLib, "CGEventKeyboardSetUnicodeString")
		purego.RegisterLibFunc(&quickCG.eventPostToPid, cgLib, "CGEventPostToPid")
		purego.RegisterLibFunc(&quickCG.preflightPostEvent, cgLib, "CGPreflightPostEventAccess")
		purego.RegisterLibFunc(&quickCG.requestPostEvent, cgLib, "CGRequestPostEventAccess")

		purego.RegisterLibFunc(&quickAX.createApplication, axLib, "AXUIElementCreateApplication")
		purego.RegisterLibFunc(&quickAX.copyAttribute, axLib, "AXUIElementCopyAttributeValue")
		purego.RegisterLibFunc(&quickAX.setTimeout, axLib, "AXUIElementSetMessagingTimeout")
		purego.RegisterLibFunc(&quickAX.processTrusted, axLib, "AXIsProcessTrusted")

		quickWorks.workspace = objc.GetClass("NSWorkspace")
		if quickWorks.workspace == 0 {
			quickAXErr = errors.New("quick access: AppKit unavailable")
			return
		}
		quickWorks.shared = objc.RegisterName("sharedWorkspace")
		quickWorks.frontmost = objc.RegisterName("frontmostApplication")
		quickWorks.pid = objc.RegisterName("processIdentifier")
		quickWorks.bundle = objc.RegisterName("bundleIdentifier")
		quickWorks.localizedName = objc.RegisterName("localizedName")

		// AX compares CFStrings by value; these live for the process.
		for name, dst := range map[string]*uintptr{
			"AXFocusedUIElement": &quickAttr.focusedUIElement,
			"AXFocusedWindow":    &quickAttr.focusedWindow,
			"AXRole":             &quickAttr.role,
			"AXTitle":            &quickAttr.title,
			"AXParent":           &quickAttr.parent,
			"AXURL":              &quickAttr.url,
		} {
			*dst = quickNewCFString(name)
			if *dst == 0 {
				quickAXErr = errors.New("quick access: attribute names unavailable")
				return
			}
		}
	})
	return quickAXErr
}

// Explicit length: CFStringCreateWithCString would truncate a value at NUL.
func quickNewCFString(s string) uintptr {
	b := []byte(s)
	var p *byte
	if len(b) > 0 {
		p = &b[0]
	}
	ref := quickCF.stringCreate(0, p, int64(len(b)), kCFStringEncodingUTF8, false)
	runtime.KeepAlive(b)
	return ref
}

// quickCFString converts a CFStringRef or a toll-free bridged NSString.
func quickCFString(ref uintptr) (string, bool) {
	if ref == 0 || quickCF.getTypeID(ref) != quickCF.stringTypeID() {
		return "", false
	}
	n := quickCF.stringLength(ref)
	if n < 0 {
		return "", false
	}
	size := quickCF.stringMaxSize(n, kCFStringEncodingUTF8)
	if size < 0 || size > 1<<20 {
		return "", false
	}
	buf := make([]byte, size+1)
	if !quickCF.stringGetCString(ref, &buf[0], size+1, kCFStringEncodingUTF8) {
		return "", false
	}
	s := string(buf)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s, true
}

func quickAttrString(el, attr uintptr) (string, bool) {
	v, code := quickCopyAttribute(el, attr)
	if code != 0 {
		return "", false
	}
	defer quickCF.release(v)
	return quickCFString(v)
}

func quickCopyAttribute(el, attr uintptr) (uintptr, int32) {
	var v uintptr
	code := quickAX.copyAttribute(el, attr, &v)
	if code != 0 {
		quickRelease(v)
		return 0, code
	}
	if v == 0 {
		return 0, -25212 // kAXErrorNoValue
	}
	return v, 0
}

func quickRelease(refs ...uintptr) {
	for _, ref := range refs {
		if ref != 0 {
			quickCF.release(ref)
		}
	}
}

func quickFrontmostApp() (pid int32, bundle, name string, ok bool) {
	ws := objc.ID(quickWorks.workspace).Send(quickWorks.shared)
	if ws == 0 {
		return 0, "", "", false
	}
	app := ws.Send(quickWorks.frontmost)
	if app == 0 {
		return 0, "", "", false
	}
	pid = objc.Send[int32](app, quickWorks.pid)
	if pid <= 0 {
		return 0, "", "", false
	}
	bundle = quickObjCString(app.Send(quickWorks.bundle))
	name = quickObjCString(app.Send(quickWorks.localizedName))
	if name == "" {
		name = bundle
	}
	return pid, bundle, name, true
}

func quickObjCString(v objc.ID) string {
	if v == 0 {
		return ""
	}
	s, _ := quickCFString(uintptr(v))
	return s
}

// quickTrustedOrigin returns the common origin of a web-area chain. "" means
// no area, unverified area or a cross-origin nested frame, so a spoofing
// wrapper never supplies its own origin.
func quickTrustedOrigin(origins []string) string {
	if len(origins) == 0 || origins[0] == "" {
		return ""
	}
	for _, origin := range origins[1:] {
		if origin != origins[0] {
			return ""
		}
	}
	return origins[0]
}

type quickWebChain struct {
	window uintptr
	origin string
}

// quickWebChainOf returns the window containing el and the origin its web
// areas share. ok is false when the chain cannot be read to a window or
// application root; callers use it for the origin suggestion only.
func quickWebChainOf(el uintptr) (chain quickWebChain, ok bool) {
	if el == 0 {
		return quickWebChain{}, false
	}
	cur := quickCF.retain(el)
	if cur == 0 {
		return quickWebChain{}, false
	}
	var origins []string
	root := false
	for range quickAXMaxAncestors {
		role, roleOK := quickAttrString(cur, quickAttr.role)
		if !roleOK {
			break
		}
		switch role {
		case quickAXRoleWebArea:
			raw, _ := quickAttrURL(cur, quickAttr.url)
			origins = append(origins, govaultui.QuickWebOrigin(raw))
		case quickAXRoleWindow, quickAXRoleSheet:
			chain.window = quickCF.retain(cur)
			root = true
		case quickAXRoleApp:
			root = true
		}
		if root {
			break
		}
		parent, code := quickCopyAttribute(cur, quickAttr.parent)
		if code != 0 {
			break
		}
		quickCF.release(cur)
		cur = parent
	}
	quickCF.release(cur)
	if !root {
		quickRelease(chain.window)
		return quickWebChain{}, false
	}
	chain.origin = quickTrustedOrigin(origins)
	return chain, true
}

func quickAttrURL(el, attr uintptr) (string, bool) {
	v, code := quickCopyAttribute(el, attr)
	if code != 0 {
		return "", false
	}
	defer quickCF.release(v)
	if quickCF.getTypeID(v) == quickCF.urlTypeID() {
		return quickCFString(quickCF.urlGetString(v))
	}
	return quickCFString(v)
}

// quickCaptureContext reads the focused window title and, for a supported
// browser, the trusted origin of its focused field. It never fails a fill:
// without Accessibility both strings are empty and the panel shows Copy only.
func quickCaptureContext(pid int32, browser bool) (title, origin string) {
	if !quickAX.processTrusted() {
		return "", ""
	}
	app := quickAX.createApplication(pid)
	if app == 0 {
		return "", ""
	}
	defer quickCF.release(app)
	if quickAX.setTimeout(app, quickAXTimeout) != 0 {
		return "", ""
	}
	window, code := quickCopyAttribute(app, quickAttr.focusedWindow)
	if code != 0 {
		return "", ""
	}
	defer quickCF.release(window)
	role, ok := quickAttrString(window, quickAttr.role)
	if !ok || (role != quickAXRoleWindow && role != quickAXRoleSheet) {
		return "", ""
	}
	title, _ = quickAttrString(window, quickAttr.title)
	if !browser {
		return title, ""
	}
	field, code := quickCopyAttribute(app, quickAttr.focusedUIElement)
	if code != 0 {
		return title, ""
	}
	defer quickCF.release(field)
	chain, ok := quickWebChainOf(field)
	if !ok {
		return title, ""
	}
	defer quickRelease(chain.window)
	if chain.window == 0 || !quickCF.equal(chain.window, window) {
		return title, ""
	}
	return title, chain.origin
}

// quickCaptureTarget describes the frontmost application's focused field
// without prompting. Only a missing or blocked target disables its writer;
// the writer checks keyboard permission each time it is used.
func captureQuickTarget() govaultui.QuickTarget {
	if err := initQuickAccessTarget(); err != nil {
		return govaultui.QuickTarget{}
	}
	pid, bundle, name, ok := quickFrontmostApp()
	if !ok || int(pid) == os.Getpid() {
		return govaultui.QuickTarget{}
	}
	if quickBlockedApps[bundle] {
		return govaultui.QuickTarget{App: name}
	}
	title, origin := quickCaptureContext(pid, quickSupportedBrowsers[bundle])
	return govaultui.QuickTarget{
		App: name, Window: title, Origin: origin,
		Fill: func(user, password string, tab bool) error {
			return quickFill(pid, bundle, user, password, tab)
		},
	}
}

// quickAutofillAvailable reports whether macOS lets this process post the
// synthetic key events autofill needs. It never prompts; Accessibility is not
// required because origin and window are suggestions, not a gate.
func quickAutofillAvailable() bool {
	if err := initQuickAccessTarget(); err != nil {
		return false
	}
	return quickCG.preflightPostEvent()
}

func quickPermissionStatus() (interfaceAccess, keyboardAccess bool) {
	if err := initQuickAccessTarget(); err != nil {
		return false, false
	}
	return quickAX.processTrusted(), quickCG.preflightPostEvent()
}

func requestQuickAutofill() bool {
	if err := initQuickAccessTarget(); err != nil {
		return false
	}
	return quickCG.requestPostEvent()
}

type quickFillStep struct {
	text string
	tab  bool
}

// quickFillSteps is the one place that decides what a fill types: a single
// field takes the first value, a login pair takes username, Tab, password.
func quickFillSteps(user, password string, tab bool) ([]quickFillStep, error) {
	if tab {
		if user == "" || password == "" {
			return nil, errQuickTargetUnavailable
		}
		return []quickFillStep{{text: user}, {tab: true}, {text: password}}, nil
	}
	if user == "" {
		return nil, errQuickTargetUnavailable
	}
	return []quickFillStep{{text: user}}, nil
}

// quickTextSafe rejects ASCII C0 controls and DEL, notably CR, LF and Tab:
// no value may submit the form or trigger a shortcut. It scans the UTF-8 bytes
// in place, so no extra string copy is made.
func quickTextSafe(s string) bool {
	for i := range s {
		if b := s[i]; b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

// quickTargetFrontmost is the target guard: the captured process must still be
// the frontmost application and must not be GoVault itself or a blocked app.
func quickTargetFrontmost(capturedPID int32, capturedBundle string, frontPID int32, frontBundle string) bool {
	return capturedPID > 0 && frontPID == capturedPID && frontBundle == capturedBundle &&
		frontPID != int32(os.Getpid()) && !quickBlockedApps[capturedBundle]
}

// Injectable send seams: tests replace these to record a plan, production uses
// the CoreGraphics writer below.
var (
	quickDeliverText = quickPostText
	quickDeliverTab  = quickPostTab
)

// quickFill types the credential through the captured process. The frontmost
// PID and bundle are re-checked before every phase, including after Tab; any
// change aborts without sending the remaining value.
func quickFill(pid int32, bundle, user, password string, tab bool) error {
	steps, err := quickFillSteps(user, password, tab)
	if err != nil {
		return err
	}
	// Validate the whole plan before the first event: a line break or control
	// character could submit the form or trigger a shortcut.
	for _, step := range steps {
		if !step.tab && !quickTextSafe(step.text) {
			return errQuickValueRejected
		}
	}
	if err := initQuickAccessTarget(); err != nil {
		return errQuickAccessUnavailable
	}
	if !quickAutofillAvailable() {
		return errQuickAccessPermission
	}
	for _, step := range steps {
		if err := quickGuardFront(pid, bundle); err != nil {
			return err
		}
		if step.tab {
			if err := quickTabAndWait(pid, bundle); err != nil {
				return err
			}
			if err := quickGuardFront(pid, bundle); err != nil {
				return err
			}
			continue
		}
		if err := quickDeliverText(pid, step.text); err != nil {
			return err
		}
	}
	return nil
}

func quickGuardFront(pid int32, bundle string) error {
	front, frontBundle, _, ok := quickFrontmostApp()
	if !ok || !quickTargetFrontmost(pid, bundle, front, frontBundle) {
		return errQuickTargetChanged
	}
	return nil
}

// quickTabAndWait posts Tab to the captured process, then gives the app a
// chance to move focus before the password is sent. If Accessibility could
// read the focused element before and still reports the same one afterwards,
// the fill fails instead of typing the password over the username. When focus
// is unreadable, the short fallback delay keeps the original blind Tab fill.
func quickTabAndWait(pid int32, bundle string) error {
	var app, before uintptr
	if quickAX.processTrusted() {
		app = quickAX.createApplication(pid)
		if app != 0 && quickAX.setTimeout(app, quickAXTimeout) == 0 {
			before, _ = quickCopyAttribute(app, quickAttr.focusedUIElement)
		}
	}
	defer func() { quickRelease(before, app) }()

	// The AX pre-read above may take a moment, so re-guard as close to the
	// Tab post as possible.
	if err := quickGuardFront(pid, bundle); err != nil {
		return err
	}
	if err := quickDeliverTab(pid); err != nil {
		return err
	}
	if before == 0 {
		time.Sleep(quickTabFallback)
		return nil
	}
	readSucceeded := false
	for deadline := time.Now().Add(quickTabWait); time.Now().Before(deadline); time.Sleep(quickTabPoll) {
		cur, code := quickCopyAttribute(app, quickAttr.focusedUIElement)
		if code != 0 {
			continue
		}
		readSucceeded = true
		moved := !quickCF.equal(cur, before)
		quickCF.release(cur)
		if moved {
			return nil
		}
	}
	return quickTabVerdict(before != 0, readSucceeded)
}

// quickTabVerdict is the post-Tab decision: a focus read before Tab that still
// succeeds and stays unchanged means the password would overwrite the
// username, so abort with a static error. Unreadable focus is not a gate.
func quickTabVerdict(readable, readSucceeded bool) error {
	if readable && readSucceeded {
		return errQuickTargetChanged
	}
	return nil
}

// quickPostText types s as CoreGraphics Unicode key events delivered to the
// captured process. No key code mapping, clipboard or Return is involved.
func quickPostText(pid int32, s string) error {
	units := utf16.Encode([]rune(s))
	if len(units) == 0 {
		return errQuickTargetUnavailable
	}
	for len(units) > 0 {
		n := min(len(units), quickUnicodeChunk)
		// Never split a surrogate pair across two events.
		if n < len(units) && units[n-1] >= 0xD800 && units[n-1] <= 0xDBFF &&
			units[n] >= 0xDC00 && units[n] <= 0xDFFF {
			n++
		}
		if err := quickPostUnits(pid, units[:n]); err != nil {
			return err
		}
		units = units[n:]
	}
	return nil
}

func quickPostUnits(pid int32, units []uint16) error {
	event := quickCG.eventCreateKeyboard(0, 0, true)
	if event == 0 {
		return errQuickAccessUnavailable
	}
	quickCG.eventSetUnicode(event, uint64(len(units)), &units[0])
	quickCG.eventPostToPid(pid, event)
	quickCF.release(event)
	runtime.KeepAlive(units)
	return nil
}

func quickPostTab(pid int32) error {
	for _, down := range []bool{true, false} {
		event := quickCG.eventCreateKeyboard(0, quickKeyTab, down)
		if event == 0 {
			return errQuickAccessUnavailable
		}
		quickCG.eventPostToPid(pid, event)
		quickCF.release(event)
	}
	return nil
}
