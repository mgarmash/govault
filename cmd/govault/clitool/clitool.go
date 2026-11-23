// Package clitool installs, repairs and removes the link that puts the gv
// command inside GoVault's app bundle on the macOS PATH. It changes only
// links that point into a GoVault bundle and never replaces another gv.
//
// The link serves every user of the Mac, so it is made only to the gv of
// a GoVault.app in /Applications that GoVault's Developer ID signs, along
// paths no one but root and administrators can change.
package clitool

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LinkPath is where Install puts the gv link.
const LinkPath = "/usr/local/bin/gv"

// bundleSuffix ends every gv path inside a GoVault app bundle.
const bundleSuffix = "/GoVault.app/Contents/MacOS/gv"

// TrustedBundle is the only app bundle a link may point into.
const TrustedBundle = "/Applications/GoVault.app"

// TeamID is the Apple team that signs GoVault releases.
const TeamID = "68S3R4UWP6"

// DeveloperOverride, set to 1 in the environment of a build with the
// govaultdev tag, lets it install the link from outside /Applications or
// without GoVault's signature. Release builds ignore it.
const DeveloperOverride = "GOVAULT_CLI_TOOL_DEVELOPER"

// ErrUntrusted means this copy of GoVault may not be linked for all users.
var ErrUntrusted = errors.New("clitool: this copy of GoVault cannot provide the gv command for all users")

// State is what Inspect found.
type State int

const (
	// Unavailable: this copy of GoVault carries no gv.
	Unavailable State = iota
	NotInstalled
	Installed
	// Homebrew: the cask linked gv into Homebrew's bin directory.
	Homebrew
	// Broken: the link points into a GoVault bundle that is gone.
	Broken
	// OtherCopy: the link points to gv in another GoVault bundle.
	OtherCopy
	// Foreign: something other than a GoVault link is at LinkPath.
	Foreign
)

// Report is the state with the path it concerns. Shadow names a gv that
// is not GoVault's in a directory the default PATH searches before the
// link's; Later names one searched after it, which does not run instead.
// Untrusted, when set, is why this copy may not be installed or repaired.
type Report struct {
	State     State
	Path      string
	Shadow    string
	Later     string
	Untrusted error
}

// Action is a change Apply makes.
type Action int

const (
	Install Action = iota
	Repair
	Uninstall
)

// Actions are what a report allows. A foreign gv and Homebrew's link are
// never changed.
func (r Report) Actions() []Action {
	if r.Untrusted != nil {
		if r.State == Installed || r.State == Broken || r.State == OtherCopy {
			return []Action{Uninstall}
		}
		return nil
	}
	switch r.State {
	case NotInstalled:
		return []Action{Install}
	case Installed:
		return []Action{Uninstall}
	case Broken, OtherCopy:
		return []Action{Repair, Uninstall}
	}
	return nil
}

// ErrChanged means the link changed between Inspect and Apply.
var ErrChanged = errors.New("clitool: the gv link changed; check it again")

// ErrCancelled means the user declined the administrator prompt.
var ErrCancelled = errors.New("clitool: cancelled")

// Tool inspects and changes the link for one bundled gv.
type Tool struct {
	// Bundled is the gv inside this app bundle.
	Bundled string
	// Link is LinkPath; tests point it elsewhere.
	Link string
	// HomebrewBins are the bin directories of Homebrew prefixes.
	HomebrewBins []string
	// SearchDirs are the default PATH's directories, in its order.
	SearchDirs []string
	// RunPrivileged runs a shell script as an administrator.
	RunPrivileged func(script, prompt string) error
	// Trust checks that Bundled may be linked for all users and that the
	// link's directory is safe; nil means trusted.
	Trust func(bundled, linkDir string) error
	// TrustedOwner is the shell test the privileged script applies to the
	// owner's user ID ($1) of the link's directory.
	TrustedOwner string
}

// New returns the Tool for the gv beside this executable.
func New() (*Tool, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Tool{
		Bundled:       filepath.Join(filepath.Dir(exe), "gv"),
		Link:          LinkPath,
		HomebrewBins:  []string{"/opt/homebrew/bin", "/usr/local/bin"},
		SearchDirs:    defaultPath(),
		RunPrivileged: osascript,
		Trust:         trustInstall,
		TrustedOwner:  `[ "$1" = 0 ] || /usr/sbin/dseditgroup -o checkmember -m "$(/usr/bin/id -nu "$1")" admin >/dev/null 2>&1`,
	}, nil
}

// defaultPath is the PATH macOS's path_helper gives login shells:
// /etc/paths, then each file in /etc/paths.d in name order. A shell's own
// startup files may change it; Settings reports only this order.
func defaultPath() []string {
	var dirs []string
	add := func(file string) {
		if raw, err := os.ReadFile(file); err == nil {
			dirs = append(dirs, strings.Fields(string(raw))...)
		}
	}
	add("/etc/paths")
	if names, err := filepath.Glob("/etc/paths.d/*"); err == nil {
		for _, n := range names {
			add(n)
		}
	}
	return dirs
}

// trustInstall accepts only the signed GoVault.app in /Applications, or
// any bundle under DeveloperOverride, along safe paths.
func trustInstall(bundled, linkDir string) error {
	app := strings.TrimSuffix(bundled, "/Contents/MacOS/gv")
	if !developerOverride() {
		if real, err := filepath.EvalSymlinks(app); err != nil || real != TrustedBundle || app != TrustedBundle {
			return fmt.Errorf("%w: it is not %s", ErrUntrusted, TrustedBundle)
		}
		req := `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "` + TeamID + `"`
		for _, path := range []string{app, bundled} {
			if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "-R="+req, path).CombinedOutput(); err != nil {
				return fmt.Errorf("%w: %s is not signed by GoVault's Developer ID: %s", ErrUntrusted, path, strings.TrimSpace(string(out)))
			}
		}
	}
	for _, path := range []string{bundled, linkDir} {
		if err := safeAncestors(path, isAdmin); err != nil {
			return err
		}
	}
	return nil
}

func isGoVaultTarget(target string) bool { return strings.HasSuffix(target, bundleSuffix) }

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// Inspect reports the state of the gv command.
func (t *Tool) Inspect() Report {
	if !exists(t.Bundled) {
		return Report{State: Unavailable}
	}
	r := t.inspectLink()
	if t.Trust != nil {
		r.Untrusted = t.Trust(t.Bundled, filepath.Dir(t.Link))
	}
	if r.State == NotInstalled {
		for _, dir := range t.HomebrewBins {
			p := filepath.Join(dir, "gv")
			if p == t.Link {
				continue
			}
			if target, err := os.Readlink(p); err == nil && isGoVaultTarget(target) && exists(p) {
				r = Report{State: Homebrew, Path: p}
				break
			}
		}
	}
	r.Shadow, r.Later = t.others()
	return r
}

func (t *Tool) inspectLink() Report {
	fi, err := os.Lstat(t.Link)
	if errors.Is(err, os.ErrNotExist) {
		return Report{State: NotInstalled}
	}
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return Report{State: Foreign, Path: t.Link}
	}
	target, err := os.Readlink(t.Link)
	switch {
	case err != nil || !isGoVaultTarget(target):
		return Report{State: Foreign, Path: t.Link}
	case !exists(t.Link):
		return Report{State: Broken, Path: t.Link}
	case samePath(t.Link, t.Bundled):
		return Report{State: Installed, Path: t.Link}
	}
	return Report{State: OtherCopy, Path: t.Link}
}

// others finds the first gv that is not GoVault's in the default PATH
// before the link's directory, and the first after it.
func (t *Tool) others() (before, after string) {
	linkDir := filepath.Dir(t.Link)
	passed := false
	for _, dir := range t.SearchDirs {
		if filepath.Clean(dir) == linkDir {
			passed = true
			continue
		}
		p := filepath.Join(dir, "gv")
		// Only what a shell would run counts: an executable regular file,
		// directly or through links.
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if target, err := os.Readlink(p); err == nil && isGoVaultTarget(target) {
			continue
		}
		if samePath(p, t.Bundled) {
			continue
		}
		switch {
		case !passed && before == "":
			before = p
		case passed && after == "":
			after = p
		}
	}
	return before, after
}

// exitChanged is the status the scripts exit with when the link is no
// longer what Inspect saw.
const exitChanged = 17

// Script is the shell script that applies action. As the administrator,
// it enters the link's directory, checks that directory is owned by root
// or an administrator and writable by no one else, and then works on the
// link by its name inside it, checking first that the link is still in the
// state that allows the action.
func (t *Tool) Script(action Action) string {
	dir, name, target := shellQuote(filepath.Dir(t.Link)), shellQuote(filepath.Base(t.Link)), shellQuote(t.Bundled)
	owner := t.TrustedOwner
	if owner == "" {
		owner = `[ "$1" = 0 ]`
	}
	enter := fmt.Sprintf(`cd -P -- %[1]s || exit %[2]d; set -- $(/usr/bin/stat -f '%%u %%g %%Lp' .); m=0$3; `+
		`[ $((m & 2)) = 0 ] || exit %[2]d; if [ $((m & 16)) != 0 ]; then [ "$2" = 0 ] || [ "$2" = 80 ] || exit %[2]d; fi; `+
		`trusted() { %[3]s; }; trusted "$1" || exit %[2]d; `+
		`/bin/ls -lde . | /usr/bin/sed 1d | /usr/bin/grep -Ev '^ *[0-9]+: (user:root|group:admin|group:wheel) ' | `+
		`/usr/bin/grep -Eq ' allow [^ ]*(write|append|delete|add_file|add_subdirectory|writeattr|writeextattr|writesecurity|chown)' && exit %[2]d`,
		dir, exitChanged, owner)
	ours := fmt.Sprintf(`[ -L %[1]s ] || exit %[2]d; case "$(/usr/bin/readlink %[1]s)" in *%[3]s) ;; *) exit %[2]d;; esac`, name, exitChanged, bundleSuffix)
	switch action {
	case Install:
		return fmt.Sprintf(`/bin/mkdir -p %[1]s || exit 1; %[2]s; if [ -e %[3]s ] || [ -L %[3]s ]; then exit %[4]d; fi; /bin/ln -s %[5]s %[3]s`,
			dir, enter, name, exitChanged, target)
	case Repair:
		return enter + "; " + ours + fmt.Sprintf(`; /bin/ln -sfn %s %s`, target, name)
	}
	return enter + "; " + ours + fmt.Sprintf(`; /bin/rm -- %s`, name)
}

// Apply makes the change, prompting once for administrator rights.
func (t *Tool) Apply(action Action, prompt string) error {
	if action != Uninstall && t.Trust != nil {
		if err := t.Trust(t.Bundled, filepath.Dir(t.Link)); err != nil {
			return err
		}
	}
	// Removing the link still needs a protected directory to work in.
	if action == Uninstall && t.Trust != nil {
		if err := safeAncestors(filepath.Dir(t.Link), isAdmin); err != nil {
			return err
		}
	}
	return t.RunPrivileged(t.Script(action), prompt)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func appleScriptString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// osascript runs script with administrator privileges through macOS's
// authorization dialog.
func osascript(script, prompt string) error {
	as := "do shell script " + appleScriptString(script) + " with administrator privileges with prompt " + appleScriptString(prompt)
	out, err := exec.Command("/usr/bin/osascript", "-e", as).CombinedOutput()
	if err == nil {
		return nil
	}
	text := string(out)
	switch {
	case strings.Contains(text, "(-128)"):
		return ErrCancelled
	case strings.Contains(text, fmt.Sprintf("(%d)", exitChanged)):
		return ErrChanged
	}
	return fmt.Errorf("clitool: %s", strings.TrimSpace(text))
}
