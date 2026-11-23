package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// On a server that stores attachments in Azure, as Bitwarden's cloud
// does, the file goes to the signed blob URL in one block blob, with no
// bearer token, and downloads again.
func TestAttachmentUploadToAzureStorage(t *testing.T) {
	for _, expired := range []bool{false, true} {
		g := newGV(t)
		g.srv.Configure(func(c *fakeserver.Config) {
			c.Premium, c.AzureUploads, c.AzureURLExpired = true, true, expired
		})
		g.login()
		file := filepath.Join(t.TempDir(), "notes.txt")
		_ = os.WriteFile(file, []byte("azure attachment"), 0o600)
		out := g.mustRun("create", "attachment", "--file", file, "--itemid", fakeserver.ItemGitHubEnt)
		var it struct{ Attachments []struct{ ID string } }
		_ = json.Unmarshal([]byte(out), &it)
		if len(it.Attachments) != 1 {
			t.Fatalf("attachments = %s", out)
		}
		puts := g.srv.BlobPuts()
		if len(puts) != 1 {
			t.Fatalf("blob storage got %d requests", len(puts))
		}
		if puts[0].Get("Authorization") != "" || puts[0].Get("x-ms-blob-type") != "BlockBlob" || puts[0].Get("x-ms-version") != "2024-08-04" {
			t.Fatalf("blob request headers = %v", puts[0])
		}
		if renewed := g.srv.Renewals(); renewed != map[bool]int{false: 0, true: 1}[expired] {
			t.Fatalf("expired=%v: %d renewals", expired, renewed)
		}
		g.mustRun("sync", "-f")
		if got := g.mustRun("get", "attachment", "notes.txt", "--itemid", fakeserver.ItemGitHubEnt, "--raw"); got != "azure attachment" {
			t.Fatalf("downloaded %q", got)
		}
	}
}

// A failed upload removes the attachment the server allocated, and says
// so when that removal fails too.
func TestFailedUploadCleansUpOrSaysItCouldNot(t *testing.T) {
	for _, deleteFails := range []bool{false, true} {
		g := newGV(t)
		g.srv.Configure(func(c *fakeserver.Config) {
			c.Premium, c.AzureUploads, c.BlobFails, c.AttachmentDeleteFails = true, true, true, deleteFails
		})
		g.login()
		file := filepath.Join(t.TempDir(), "notes.txt")
		_ = os.WriteFile(file, []byte("x"), 0o600)
		r := g.run("create", "attachment", "--file", file, "--itemid", fakeserver.ItemGitHubEnt)
		if r.code != 1 {
			t.Fatalf("upload to failing storage = %+v", r)
		}
		var item struct{ Attachments []json.RawMessage }
		raw, _ := json.Marshal(g.srv.Item(fakeserver.ItemGitHubEnt))
		_ = json.Unmarshal(raw, &item)
		atts := item.Attachments
		switch {
		case !deleteFails && len(atts) != 0:
			t.Fatalf("the allocated attachment was left: %v", atts)
		case deleteFails && (len(atts) != 1 || !strings.Contains(r.err, "could not be removed")):
			t.Fatalf("a failed removal = %+v with %d attachments listed", r, len(atts))
		}
	}
}

// A direct upload the server refuses still warns about the attachment its
// failed cleanup left, after the server's message.
func TestRefusedDirectUploadWarnsAboutWhatItLeft(t *testing.T) {
	g := newGV(t)
	g.srv.Configure(func(c *fakeserver.Config) {
		c.Premium, c.DirectUploadFails, c.AttachmentDeleteFails = true, true, true
	})
	g.login()
	file := filepath.Join(t.TempDir(), "notes.txt")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	r := g.run("create", "attachment", "--file", file, "--itemid", fakeserver.ItemGitHubEnt)
	if r.code != 1 || !strings.Contains(r.err, "Upload refused") || !strings.Contains(r.err, "is still on the server") {
		t.Fatalf("refused upload = %+v", r)
	}
}
