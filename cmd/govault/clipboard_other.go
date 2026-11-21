//go:build !darwin || ios

package main

import (
	"errors"
	"time"
)

type ConcealedClipboard struct{}

func NewConcealedClipboard() *ConcealedClipboard {
	return &ConcealedClipboard{}
}

func (c *ConcealedClipboard) Copy(string, time.Duration) (int, error) {
	return 0, errors.New("clipboard: concealed pasteboard helper is only supported on macOS")
}

func (c *ConcealedClipboard) ClearIfUnchanged(int) bool {
	return false
}

func (c *ConcealedClipboard) Cancel() {}
