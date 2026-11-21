//go:build !darwin || ios

package main

func startMouseNavigation(onBack, onForward func()) (stop func(), err error) {
	return func() {}, nil
}
