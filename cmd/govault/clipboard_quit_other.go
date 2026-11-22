//go:build !windows

package main

// clearClipboardIfOwned has nothing to do here: macOS clears through the
// concealed clipboard, and on Linux the clipboard is served by the app
// itself, so its contents leave with the process. A clipboard manager that
// copied the secret keeps its own copy, which GoVault cannot reach.
var clearClipboardIfOwned = func(string) {}
