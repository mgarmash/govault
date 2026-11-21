//go:build !darwin || ios

package main

// chooseSavePath is unavailable here; the UI falls back to a folder picker
// and a file name that does not exist yet.
var chooseSavePath func(name string, done func(path string, ok bool, err error))
