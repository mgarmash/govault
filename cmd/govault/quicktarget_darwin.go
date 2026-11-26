//go:build darwin && !ios

package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
)

// Quick Access captures one focused text field of the frontmost application
// and fills it with AXUIElementSetAttributeValue. It never injects keys, uses
// the clipboard or activates the app. Before every write the field, window,
// PID, role and browser web areas are checked again; any change or AX error
// fails closed instead of targeting another element.

const (
	quickAXMaxAncestors    = 256
	quickAXTimeout         = 2.0
	quickAXErrorNoValue    = -25212
	quickAXRoleWindow      = "AXWindow"
	quickAXRoleSheet       = "AXSheet"
	quickAXRoleApplication = "AXApplication"
	quickAXRoleTextField   = "AXTextField"
	quickAXRoleWebArea     = "AXWebArea"
	quickAXSecureField     = "AXSecureTextField"
)

var (
	errQuickTargetUnavailable = errors.New("quick access: target is unavailable")
	errQuickTargetChanged     = errors.New("quick access: target changed")
)

// Only known browsers may report a trustworthy AX web-area URL. Any other app
// with web ancestry is rejected rather than filled.
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
	booleanTypeID    func() uintptr
	booleanValue     func(uintptr) bool
}

type quickAccessibility struct {
	createApplication func(int32) uintptr
	copyAttribute     func(uintptr, uintptr, *uintptr) int32
	setAttribute      func(uintptr, uintptr, uintptr) int32
	isSettable        func(uintptr, uintptr, *uint8) int32
	setTimeout        func(uintptr, float32) int32
	elementPID        func(uintptr, *int32) int32
	processTrusted    func() bool
}

type quickAXAttributes struct {
	focusedUIElement uintptr
	focusedWindow    uintptr
	role             uintptr
	subrole          uintptr
	title            uintptr
	parent           uintptr
	url              uintptr
	value            uintptr
	enabled          uintptr
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
		purego.RegisterLibFunc(&quickCF.booleanTypeID, cfLib, "CFBooleanGetTypeID")
		purego.RegisterLibFunc(&quickCF.booleanValue, cfLib, "CFBooleanGetValue")

		purego.RegisterLibFunc(&quickAX.createApplication, axLib, "AXUIElementCreateApplication")
		purego.RegisterLibFunc(&quickAX.copyAttribute, axLib, "AXUIElementCopyAttributeValue")
		purego.RegisterLibFunc(&quickAX.setAttribute, axLib, "AXUIElementSetAttributeValue")
		purego.RegisterLibFunc(&quickAX.isSettable, axLib, "AXUIElementIsAttributeSettable")
		purego.RegisterLibFunc(&quickAX.setTimeout, axLib, "AXUIElementSetMessagingTimeout")
		purego.RegisterLibFunc(&quickAX.elementPID, axLib, "AXUIElementGetPid")
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
			"AXSubrole":          &quickAttr.subrole,
			"AXTitle":            &quickAttr.title,
			"AXParent":           &quickAttr.parent,
			"AXURL":              &quickAttr.url,
			"AXValue":            &quickAttr.value,
			"AXEnabled":          &quickAttr.enabled,
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

// Explicit length: CFStringCreateWithCString would truncate a secret at NUL.
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
	s, code := quickAttrStringCode(el, attr)
	return s, code == 0
}

func quickAttrStringCode(el, attr uintptr) (string, int32) {
	v, code := quickCopyAttribute(el, attr)
	if code != 0 {
		return "", code
	}
	defer quickCF.release(v)
	if s, ok := quickCFString(v); ok {
		return s, 0
	}
	return "", quickAXErrorNoValue
}

func quickAttrBool(el, attr uintptr) (bool, int32) {
	v, code := quickCopyAttribute(el, attr)
	if code != 0 {
		return false, code
	}
	defer quickCF.release(v)
	if quickCF.getTypeID(v) != quickCF.booleanTypeID() {
		return false, quickAXErrorNoValue
	}
	return quickCF.booleanValue(v), 0
}

func quickCopyAttribute(el, attr uintptr) (uintptr, int32) {
	var v uintptr
	code := quickAX.copyAttribute(el, attr, &v)
	if code != 0 {
		quickRelease(v)
		return 0, code
	}
	if v == 0 {
		return 0, quickAXErrorNoValue
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

// quickAppFocus re-reads the application's focused window and UI element and
// requires them to be the captured ones. AXFocusedUIElement is an application
// attribute; the window may not answer it.
func quickAppFocus(pid int32, app, window, field uintptr) bool {
	front, _, _, ok := quickFrontmostApp()
	if !ok || front != pid || int(front) == os.Getpid() {
		return false
	}
	focusedWindow, code := quickCopyAttribute(app, quickAttr.focusedWindow)
	if code != 0 {
		return false
	}
	sameWindow := quickCF.equal(focusedWindow, window)
	quickCF.release(focusedWindow)
	if !sameWindow {
		return false
	}
	focusedField, code := quickCopyAttribute(app, quickAttr.focusedUIElement)
	if code != 0 {
		return false
	}
	sameField := quickCF.equal(focusedField, field)
	quickCF.release(focusedField)
	return sameField
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
	window, nearest, top uintptr
	origin               string
}

// quickWebChainOf returns the window containing el, the nearest and outermost
// AXWebArea, and the origin they all share. ok is false when the chain cannot
// be read to a window or application root; callers fail closed.
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
			if chain.nearest == 0 {
				chain.nearest = quickCF.retain(cur)
			}
			quickRelease(chain.top)
			chain.top = quickCF.retain(cur)
		case quickAXRoleWindow, quickAXRoleSheet:
			chain.window = quickCF.retain(cur)
			root = true
		case quickAXRoleApplication:
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
		quickRelease(chain.window, chain.nearest, chain.top)
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

// Only single-line text fields qualify; a multiline chat composer must never
// receive a credential, and a password needs the secure subrole.
func quickRoleFieldAllowed(role, subrole string, field govaultui.QuickField) bool {
	if field == govaultui.QuickPassword {
		return role == quickAXRoleTextField && subrole == quickAXSecureField
	}
	return role == quickAXRoleTextField && subrole != quickAXSecureField
}

// quickFieldFlags reads the field once and reports which QuickFields it can
// take. Browsers do not expose AXEditable; a successful AXValue write is
// authoritative, and settability is used when the app reports it reliably.
func quickFieldFlags(el uintptr) (allowed [3]bool) {
	role, ok := quickAttrString(el, quickAttr.role)
	if !ok {
		return allowed
	}
	subrole, code := quickAttrStringCode(el, quickAttr.subrole)
	if code != 0 && code != quickAXErrorNoValue {
		return allowed
	}
	enabled, code := quickAttrBool(el, quickAttr.enabled)
	if code != 0 || !enabled {
		return allowed
	}
	var settable uint8
	if code := quickAX.isSettable(el, quickAttr.value, &settable); code == 0 && settable == 0 {
		return allowed
	}
	allowed[0] = quickRoleFieldAllowed(role, subrole, govaultui.QuickUsername)
	allowed[1] = quickRoleFieldAllowed(role, subrole, govaultui.QuickPassword)
	allowed[2] = quickRoleFieldAllowed(role, subrole, govaultui.QuickTOTP)
	return allowed
}

func quickFieldAllowed(allowed [3]bool, field govaultui.QuickField) bool {
	return int(field) < len(allowed) && allowed[field]
}

type quickAXTarget struct {
	mu         sync.Mutex
	closed     bool
	pid        int32
	browser    bool
	app        uintptr
	window     uintptr
	field      uintptr
	windowRole string
	webArea    uintptr
	topArea    uintptr
	origin     string
}

// captureQuickTarget describes the frontmost application's focused field. It
// never prompts for Accessibility: without the permission, or without a
// suitable field, Fill stays nil and only the app/window label is exposed.
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
	if !quickAX.processTrusted() {
		return govaultui.QuickTarget{App: name}
	}

	app := quickAX.createApplication(pid)
	if app == 0 {
		return govaultui.QuickTarget{App: name}
	}
	// Bound every AX query so a hung app cannot stall the panel or lock.
	if quickAX.setTimeout(app, quickAXTimeout) != 0 {
		quickRelease(app)
		return govaultui.QuickTarget{App: name}
	}
	window, code := quickCopyAttribute(app, quickAttr.focusedWindow)
	if code != 0 {
		quickRelease(app)
		return govaultui.QuickTarget{App: name}
	}
	windowRole, ok := quickAttrString(window, quickAttr.role)
	if !ok || (windowRole != quickAXRoleWindow && windowRole != quickAXRoleSheet) {
		quickRelease(window, app)
		return govaultui.QuickTarget{App: name}
	}
	title, _ := quickAttrString(window, quickAttr.title)
	field, code := quickCopyAttribute(app, quickAttr.focusedUIElement)
	if code != 0 {
		quickRelease(window, app)
		return govaultui.QuickTarget{App: name, Window: title}
	}

	chain, walkOK := quickWebChainOf(field)
	browser := quickSupportedBrowsers[bundle]
	if !walkOK || chain.window == 0 || !quickCF.equal(chain.window, window) ||
		(chain.nearest != 0 && !browser) ||
		(browser && (chain.nearest == 0 || chain.origin == "")) {
		quickRelease(chain.window, chain.nearest, chain.top, field, window, app)
		return govaultui.QuickTarget{App: name, Window: title}
	}
	quickRelease(chain.window) // the same element as window, verified above
	if !quickAppFocus(pid, app, window, field) {
		quickRelease(chain.nearest, chain.top, field, window, app)
		return govaultui.QuickTarget{App: name, Window: title}
	}
	allowed := quickFieldFlags(field)
	if !allowed[0] && !allowed[1] && !allowed[2] {
		quickRelease(chain.nearest, chain.top, field, window, app)
		return govaultui.QuickTarget{App: name, Window: title, Origin: chain.origin}
	}
	t := &quickAXTarget{
		pid: pid, browser: browser, app: app, window: window, field: field,
		windowRole: windowRole, webArea: chain.nearest, topArea: chain.top, origin: chain.origin,
	}
	return govaultui.QuickTarget{
		App: name, Window: title, Origin: chain.origin,
		Fill: t.fill, Close: t.close,
		CanFill: func(field govaultui.QuickField) bool {
			return quickFieldAllowed(allowed, field)
		},
	}
}

func (t *quickAXTarget) fill(field govaultui.QuickField, value string) error {
	if value == "" {
		return errQuickTargetUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.app == 0 {
		return errQuickTargetUnavailable
	}
	if err := initQuickAccessTarget(); err != nil || !quickAX.processTrusted() {
		return errQuickTargetUnavailable
	}

	// Every retained AX object must still belong to the captured process and
	// the application must still report it as its focused element.
	for _, el := range []uintptr{t.app, t.window, t.field} {
		var elPID int32
		if el == 0 || quickAX.elementPID(el, &elPID) != 0 || elPID != t.pid {
			return errQuickTargetChanged
		}
	}
	if role, ok := quickAttrString(t.window, quickAttr.role); !ok || role != t.windowRole {
		return errQuickTargetChanged
	}

	chain, walkOK := quickWebChainOf(t.field)
	if !walkOK {
		return errQuickTargetChanged
	}
	sameWindow := chain.window != 0 && quickCF.equal(chain.window, t.window)
	web := chain.nearest != 0
	sameWeb := !t.browser && !web
	if t.browser {
		sameWeb = web && chain.origin != "" && chain.origin == t.origin &&
			t.webArea != 0 && t.topArea != 0 &&
			quickCF.equal(chain.nearest, t.webArea) && quickCF.equal(chain.top, t.topArea)
	}
	quickRelease(chain.window, chain.nearest, chain.top)
	if !sameWindow || !sameWeb {
		return errQuickTargetChanged
	}

	// Keep the final focus check as close to the write as possible.
	if !quickAppFocus(t.pid, t.app, t.window, t.field) ||
		!quickFieldAllowed(quickFieldFlags(t.field), field) {
		return errQuickTargetChanged
	}

	cfValue := quickNewCFString(value)
	if cfValue == 0 {
		return errQuickTargetUnavailable
	}
	code := quickAX.setAttribute(t.field, quickAttr.value, cfValue)
	quickCF.release(cfValue)
	if code != 0 {
		return errQuickTargetUnavailable
	}
	return nil
}

func (t *quickAXTarget) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	quickRelease(t.webArea, t.topArea, t.field, t.window, t.app)
	t.webArea, t.topArea, t.field, t.window, t.app = 0, 0, 0, 0, 0
}
