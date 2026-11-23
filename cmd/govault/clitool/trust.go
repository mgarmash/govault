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

// aclMutations are the ACL rights that change an entry or what a
// directory holds.
var aclMutations = []string{"write", "append", "delete", "delete_child", "add_file", "add_subdirectory", "writeattr", "writeextattr", "writesecurity", "chown"}

// aclTrusted are the principals that may hold mutation rights.
var aclTrusted = []string{"user:root", "group:admin", "group:wheel"}

// aclMutators names the first principal other than root, admin or wheel
// that path's access list allows to change it, or "".
func aclMutators(path string) (string, error) {
	out, err := exec.Command("/bin/ls", "-lde", path).Output()
	if err != nil {
		return "", err
	}
	return parseACL(string(out)), nil
}

// parseACL reads ls -le's entries: " 0: user:bob [inherited] allow add_file,...".
func parseACL(listing string) string {
	lines := strings.Split(strings.TrimRight(listing, "\n"), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		who, rest := f[1], f[2:]
		if rest[0] == "inherited" {
			rest = rest[1:]
		}
		if len(rest) < 2 || rest[0] != "allow" || slices.Contains(aclTrusted, who) {
			continue
		}
		for _, right := range strings.Split(rest[1], ",") {
			if slices.Contains(aclMutations, right) {
				return who
			}
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
