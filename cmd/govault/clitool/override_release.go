//go:build !govaultdev

package clitool

// Release builds have no developer override.
func developerOverride() bool { return false }
