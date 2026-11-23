//go:build !darwin

package clitool

// The command-line tool link exists only on macOS.
func safeAncestors(string, func(uint32) bool) error { return ErrUntrusted }

func isAdmin(uint32) bool { return false }
