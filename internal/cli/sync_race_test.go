package cli

import (
	"strings"
	"sync"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// A sync whose response was read before an edit committed, and arrives
// after it, does not replace the edit with the older copy.
func TestStaleSyncDoesNotUndoACommittedEdit(t *testing.T) {
	g := newGV(t)
	g.login()
	inSync, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	// The fake builds the response before the hook: it holds the vault as
	// it was when the sync asked.
	g.srv.Configure(func(c *fakeserver.Config) {
		c.OnSync = func() {
			once.Do(func() {
				close(inSync)
				<-release
			})
		}
	})
	other := &gvTest{t: t, srv: g.srv, env: g.env, ring: g.ring, goos: g.goos}
	var wg sync.WaitGroup
	var syncErr string
	wg.Add(1)
	go func() {
		defer wg.Done()
		if r := other.run("sync", "-f"); r.code != 0 {
			syncErr = r.err
		}
	}()
	<-inSync
	item := g.mustRun("get", "item", fakeserver.ItemGitHubEnt)
	edited := strings.Replace(item, `"name":"GitHub Enterprise",`, `"name":"GitHub Enterprise","notes":"edited during a sync",`, 1)
	g.mustRun("edit", "item", fakeserver.ItemGitHubEnt, b64(edited))
	close(release)
	wg.Wait()
	if syncErr != "" {
		t.Fatalf("sync: %q", syncErr)
	}
	if got := g.mustRun("get", "notes", fakeserver.ItemGitHubEnt); got != "edited during a sync" {
		t.Fatalf("after the stale sync the local copy says %q", got)
	}
}
