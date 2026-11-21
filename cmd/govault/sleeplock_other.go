//go:build !darwin || ios

package main

const sleepLockSupported = false

func startSleepLockListener(func()) (func(), error) { return func() {}, nil }
