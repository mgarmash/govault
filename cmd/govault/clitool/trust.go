//go:build unix

package clitool

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
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
