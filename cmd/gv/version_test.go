package main

import (
	"os"
	"regexp"
	"testing"
)

func TestVersionMatchesTheApp(t *testing.T) {
	data, err := os.ReadFile("../govault/nsgo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^version:\s*(\S+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("nsgo.yaml has no version")
	}
	if string(m[1]) != appRelease {
		t.Fatalf("cmd/gv/version.go says %s, nsgo.yaml %s: change both", appRelease, m[1])
	}
}
