// Package privatefile writes files only the current user can access: mode
// 0600 on Unix, a protected user-only DACL on Windows.
package privatefile

import (
	"os"
	"path/filepath"
)

// WriteFile replaces path with data atomically: it writes a private
// temporary file in the same directory, syncs it and renames it over path,
// so readers see the old or the new file, never a partial one.
func WriteFile(path string, data []byte) error {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// MkdirAll creates dir and its parents, with dir itself accessible only to
// the current user.
func MkdirAll(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return restrictDir(dir)
}
