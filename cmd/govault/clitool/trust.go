//go:build darwin

package clitool

import (
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
			if who, err := aclMutators(p); err != nil {
				return fmt.Errorf("%w: cannot read the access list of %s: %v", ErrUntrusted, p, err)
			} else if who != "" {
				return fmt.Errorf("%w: its access list lets %s change %s", ErrUntrusted, who, p)
			}
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// aclTrusted are the principals an allow entry may name.
var aclTrusted = []string{"user:root", "group:admin", "group:wheel"}

// aclMutators names the first access-list entry of path that is not
// positively safe, or "".
func aclMutators(path string) (string, error) {
	out, err := exec.Command("/bin/ls", "-lde", path).Output()
	if err != nil {
		return "", err
	}
	return parseACL(string(out)), nil
}

// parseACL reads ls -le's entries, " 0: <principal> [inherited] allow|deny
// <rights>", from the right, as a principal's name can hold spaces. Only
// deny entries and allow entries to root, admin or wheel are safe; any
// other entry, or one it cannot read, is returned.
func parseACL(listing string) string {
	lines := strings.Split(strings.TrimRight(listing, "\n"), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			return strings.TrimSpace(line)
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
			return strings.TrimSpace(line)
		}
	}
	return ""
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
