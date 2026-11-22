package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
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
