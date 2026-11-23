//go:build govaultdev

package clitool

import "os"

func developerOverride() bool { return os.Getenv(DeveloperOverride) == "1" }
