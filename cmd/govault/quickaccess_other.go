//go:build !darwin || ios

package main

func startQuickAccess(*DesktopShell) func() { return nil }
