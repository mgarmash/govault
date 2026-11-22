package main

import (
	"encoding/xml"
	"os"
	"regexp"
	"strings"
	"testing"
)

const appID = "dev.txchen.govault"

// TestLinuxDesktopEntryCopyMatchesNSGo keeps linux/<id>.desktop, the copy
// Linux packages carry under usr/share/applications, what NSGo writes at
// the AppDir root from nsgo.yaml: its keys, and the categories of
// linux.categories.
func TestLinuxDesktopEntryCopyMatchesNSGo(t *testing.T) {
	cfg, err := os.ReadFile("nsgo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^linux:\n(?:\s*#.*\n)*\s+categories:\s*\[([^\]]*)\]`).FindSubmatch(cfg)
	if m == nil {
		t.Fatal("nsgo.yaml has no linux.categories")
	}
	var categories string
	for _, c := range strings.Split(string(m[1]), ",") {
		categories += strings.TrimSpace(c) + ";"
	}
	want := "[Desktop Entry]\nType=Application\nName=GoVault\nExec=\"GoVault\"\nIcon=" + appID +
		"\nTerminal=false\nStartupWMClass=" + appID + "\nCategories=" + categories + "\n"
	got, err := os.ReadFile("linux/" + appID + ".desktop")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("linux/%s.desktop =\n%s\nwant what NSGo writes:\n%s", appID, got, want)
	}
}

// TestLinuxAppStreamMetadata checks what the AppImage catalog and software
// centers read: the ID and desktop entry, the license and the newest
// release, which is the version nsgo.yaml builds once it is released.
func TestLinuxAppStreamMetadata(t *testing.T) {
	data, err := os.ReadFile("linux/" + appID + ".appdata.xml")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		ID         string `xml:"id"`
		License    string `xml:"project_license"`
		Launchable string `xml:"launchable"`
		Releases   []struct {
			Version string `xml:"version,attr"`
			Date    string `xml:"date,attr"`
		} `xml:"releases>release"`
		Screenshots []string `xml:"screenshots>screenshot>image"`
	}
	if err := xml.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.ID != appID || c.Launchable != appID+".desktop" || c.License != "MIT" || len(c.Screenshots) == 0 || len(c.Releases) == 0 {
		t.Fatalf("metadata = %+v", c)
	}
	for _, r := range c.Releases {
		if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(r.Date) {
			t.Errorf("release %s has date %q", r.Version, r.Date)
		}
	}
}
