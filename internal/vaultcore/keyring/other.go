//go:build !darwin && !windows && (!linux || android)

package keyring

func system() (Store, error) { return nil, ErrUnavailable }
