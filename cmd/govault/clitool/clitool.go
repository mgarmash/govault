// Package clitool installs, repairs and removes the link that puts the gv
// command inside GoVault's app bundle on the macOS PATH. It changes only
// links that point into a GoVault bundle and never replaces another gv.
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

// Report is the state with the path it concerns. Shadow names another gv
// on the PATH that is not GoVault's, even when the link is fine.
type Report struct {
	State  State
	Path   string
	Shadow string
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
	// SearchDirs are the PATH directories checked for another gv.
	SearchDirs []string
	// RunPrivileged runs a shell script as an administrator.
	RunPrivileged func(script, prompt string) error
}

// New returns the Tool for the gv beside this executable.
func New() (*Tool, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	dirs := []string{"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	if raw, err := os.ReadFile("/etc/paths"); err == nil {
		dirs = append(dirs, strings.Fields(string(raw))...)
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, "bin"), filepath.Join(home, ".local", "bin"), filepath.Join(home, "go", "bin"))
	}
	return &Tool{
		Bundled:       filepath.Join(filepath.Dir(exe), "gv"),
		Link:          LinkPath,
		HomebrewBins:  []string{"/opt/homebrew/bin", "/usr/local/bin"},
		SearchDirs:    dirs,
		RunPrivileged: osascript,
	}, nil
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
	r.Shadow = t.shadow()
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

// shadow finds a gv on the PATH that is not GoVault's.
func (t *Tool) shadow() string {
	for _, dir := range t.SearchDirs {
		p := filepath.Join(dir, "gv")
		if p == t.Link {
			continue
		}
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if target, err := os.Readlink(p); err == nil && isGoVaultTarget(target) {
			continue
		}
		if !samePath(p, t.Bundled) {
			return p
		}
	}
	return ""
}

// exitChanged is the status the scripts exit with when the link is no
// longer what Inspect saw.
const exitChanged = 17

// Script is the shell script that applies action, checking first, as the
// administrator, that the link is still in the state that allows it.
func (t *Tool) Script(action Action) string {
	link, target := shellQuote(t.Link), shellQuote(t.Bundled)
	ours := fmt.Sprintf(`[ -L %[1]s ] || exit %[2]d; case "$(/usr/bin/readlink %[1]s)" in *%[3]s) ;; *) exit %[2]d;; esac`, link, exitChanged, bundleSuffix)
	switch action {
	case Install:
		return fmt.Sprintf(`if [ -e %[1]s ] || [ -L %[1]s ]; then exit %[2]d; fi; /bin/mkdir -p %[3]s && /bin/ln -s %[4]s %[1]s`,
			link, exitChanged, shellQuote(filepath.Dir(t.Link)), target)
	case Repair:
		return ours + fmt.Sprintf(`; /bin/ln -sfn %s %s`, target, link)
	}
	return ours + fmt.Sprintf(`; /bin/rm %s`, link)
}

// Apply makes the change, prompting once for administrator rights.
func (t *Tool) Apply(action Action, prompt string) error {
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
