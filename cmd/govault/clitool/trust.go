//go:build darwin

package clitool

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// adminGID and wheelGID are macOS's admin and wheel groups.
const (
	adminGID = 80
	wheelGID = 0
)

// safeAncestors checks path and each directory above it that exists: none
// may be writable by others, a group-writable one only by wheel or admin,
// and each must be owned by root or an administrator (trustedUID).
func safeAncestors(path string, trustedUID func(uint32) bool) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		switch {
		case os.IsNotExist(err):
		case err != nil:
			return fmt.Errorf("%w: %v", ErrUntrusted, err)
		default:
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("%w: cannot read the owner of %s", ErrUntrusted, p)
			}
			mode := fi.Mode().Perm()
			switch {
			case mode&0o002 != 0:
				return fmt.Errorf("%w: anyone can change %s", ErrUntrusted, p)
			case mode&0o020 != 0 && st.Gid != adminGID && st.Gid != wheelGID:
				return fmt.Errorf("%w: a group other than admin can change %s", ErrUntrusted, p)
			case !trustedUID(st.Uid):
				return fmt.Errorf("%w: %s belongs to a user who is not an administrator", ErrUntrusted, p)
			}
			if err := checkACL(p); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrUntrusted, p, err)
			}
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// aclTrusted are the principals an allow entry may name.
var aclTrusted = []string{"user:root", "group:admin", "group:wheel"}

// checkACL reads path's access list and returns an error unless every
// entry is positively safe.
func checkACL(path string) error {
	out, err := exec.Command("/bin/ls", "-lde", path).Output()
	if err != nil {
		return fmt.Errorf("cannot read the access list: %v", err)
	}
	return parseACL(string(out))
}

// parseACL reads ls -le's entries, " 0: <principal> [inherited] allow|deny
// <rights>", from the right, as a principal's name can hold spaces. Only
// deny entries and allow entries to root, admin or wheel are safe. Every
// entry is checked; each one that is not safe, or that it cannot read,
// including a blank line among them, is in the error.
func parseACL(listing string) error {
	lines := strings.Split(strings.TrimRight(listing, "\n"), "\n")
	var errs []error
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			errs = append(errs, fmt.Errorf("malformed access-list entry %q", line))
			continue
		}
		kind, principal := f[len(f)-2], f[1:len(f)-2]
		if n := len(principal); n > 1 && principal[n-1] == "inherited" {
			principal = principal[:n-1]
		}
		who := strings.Join(principal, " ")
		switch {
		case kind == "deny" && who != "":
		case kind == "allow" && slices.Contains(aclTrusted, who):
		default:
			errs = append(errs, fmt.Errorf("access-list entry %q lets %s change it", strings.TrimSpace(line), who))
		}
	}
	return errors.Join(errs...)
}

// isAdmin reports root or a member of the admin group.
func isAdmin(uid uint32) bool {
	if uid == 0 {
		return true
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	groups, err := u.GroupIds()
	return err == nil && slices.Contains(groups, strconv.Itoa(adminGID))
}
