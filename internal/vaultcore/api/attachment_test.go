package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDownloadAttachmentBytes_AuthOnlySameOrigin(t *testing.T) {
	var gotAuth []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if r.URL.Path == "/big" {
			_, _ = w.Write(make([]byte, MaxAttachmentSize+1))
			return
		}
		_, _ = w.Write([]byte("blob"))
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	cdn := httptest.NewServer(handler)
	defer cdn.Close()

	c, err := NewClient(ClientConfig{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, u := range []string{"/attachments/a", server.URL + "/attachments/a", cdn.URL + "/attachments/a"} {
		if data, err := c.DownloadAttachmentBytes(ctx, "tok", u); err != nil || string(data) != "blob" {
			t.Fatalf("download %s = (%q, %v)", u, data, err)
		}
	}
	if len(gotAuth) != 3 || gotAuth[0] != "Bearer tok" || gotAuth[1] != "Bearer tok" || gotAuth[2] != "" {
		t.Fatalf("Authorization headers = %q", gotAuth)
	}
	if _, err := c.DownloadAttachmentBytes(ctx, "tok", "/big"); !errors.Is(err, ErrAttachmentTooLarge) {
		t.Fatalf("oversized download = %v", err)
	}
	if _, err := c.DownloadAttachmentBytes(ctx, "tok", "file:///etc/passwd"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("file URL = %v", err)
	}
}
