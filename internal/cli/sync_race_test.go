package cli

import (
	"strings"
	"sync"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// syncRace runs a sync whose first fetch the server holds until release,
// and an edit of the GitHub Enterprise notes, in the order order picks.
func syncRace(t *testing.T, writeAnswersFirst bool) {
	g := newGV(t)
	g.login()
	inSync, releaseSync := make(chan struct{}), make(chan struct{})
	inWrite, releaseWrite := make(chan struct{}), make(chan struct{})
	var syncOnce, writeOnce sync.Once
	g.srv.Configure(func(c *fakeserver.Config) {
		c.OnSync = func() {
			syncOnce.Do(func() {
				close(inSync)
				<-releaseSync
			})
		}
		c.OnWrite = func() {
			writeOnce.Do(func() {
				close(inWrite)
				<-releaseWrite
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
	edited := strings.Replace(item, `"notes":null`, `"notes":"edited during a sync"`, 1)
	if !strings.Contains(edited, "edited during a sync") {
		edited = strings.Replace(item, `"name":"GitHub Enterprise",`, `"name":"GitHub Enterprise","notes":"edited during a sync",`, 1)
	}
	var editErr string
	wg.Add(1)
	go func() {
		defer wg.Done()
		if r := g.run("edit", "item", fakeserver.ItemGitHubEnt, b64(edited)); r.code != 0 {
			editErr = r.err
		}
	}()
	<-inWrite
	if writeAnswersFirst {
		close(releaseWrite)
		close(releaseSync)
	} else {
		close(releaseSync)
		close(releaseWrite)
	}
	wg.Wait()
	if syncErr != "" || editErr != "" {
		t.Fatalf("sync: %q, edit: %q", syncErr, editErr)
	}
	if got := g.mustRun("get", "notes", fakeserver.ItemGitHubEnt); got != "edited during a sync" {
		t.Fatalf("after the race the local copy says %q: an older sync replaced the edit", got)
	}
}

func TestSyncFinishingAfterAWriteKeepsTheWrite(t *testing.T)  { syncRace(t, true) }
func TestSyncFinishingBeforeAWriteKeepsTheWrite(t *testing.T) { syncRace(t, false) }
