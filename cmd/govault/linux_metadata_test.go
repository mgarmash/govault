package main

import (
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

const appID = "dev.txchen.govault"

// TestLinuxAppStreamMetadata checks what the AppImage catalog and software
// centers read: the ID and desktop entry, the license and the newest
// release, which is the version nsgo.yaml builds once it is released.
func TestLinuxAppStreamMetadata(t *testing.T) {
	data, err := os.ReadFile("linux/share/metainfo/" + appID + ".metainfo.xml")
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

// The metainfo is the one linux.share installs, which replaces NSGo's.
func TestLinuxShareHoldsOnlyTheMetainfo(t *testing.T) {
	cfg, err := os.ReadFile("nsgo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^  share: linux/share$`).Match(cfg) {
		t.Fatal("nsgo.yaml does not set linux.share to linux/share")
	}
	var files []string
	_ = filepath.WalkDir("linux/share", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, filepath.ToSlash(p))
		}
		return err
	})
	if len(files) != 1 || files[0] != "linux/share/metainfo/"+appID+".metainfo.xml" {
		t.Fatalf("linux/share holds %v", files)
	}
}
