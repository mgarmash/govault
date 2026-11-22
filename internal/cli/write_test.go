package cli

import (
	"strings"
	"sync"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
)

// An edit based on an older copy of the item is refused by the server and
// changes nothing.
func TestEditOfAnItemChangedElsewhereIsRefused(t *testing.T) {
	g := newGV(t)
	g.login()
	g.srv.Touch(fakeserver.ItemGitHubEnt)
	r := g.run("edit", "item", fakeserver.ItemGitHubEnt, b64(`{"type":1,"name":"Clobbered","login":{}}`))
	if r.code != 1 || !strings.Contains(r.err, "out of date") {
		t.Fatalf("stale edit = %+v", r)
	}
	if g.srv.Item(fakeserver.ItemGitHubEnt)["name"] == nil {
		t.Fatal("the item vanished")
	}
}

// A permanent delete rechecks the item on the server first and keeps an
// item someone else changed since the last sync.
func TestPermanentDeleteKeepsAnItemChangedElsewhere(t *testing.T) {
	g := newGV(t)
	g.login()
	g.srv.Touch(fakeserver.ItemCard)
	r := g.run("delete", "item", fakeserver.ItemCard, "--permanent")
	if r.code != 1 || !strings.Contains(r.err, "changed on the server") {
		t.Fatalf("stale permanent delete = %+v", r)
	}
	if g.srv.Item(fakeserver.ItemCard) == nil {
		t.Fatal("the changed item was deleted")
	}
	g.mustRun("sync", "-f")
	g.mustRun("delete", "item", fakeserver.ItemCard, "--permanent")
	if g.srv.Item(fakeserver.ItemCard) != nil {
		t.Fatal("the item survived a confirmed delete")
	}
}

// Writes need valid credentials and a valid session: none of these reach
// the server.
func TestWritesNeedASessionAndCredentials(t *testing.T) {
	g := newGV(t)
	g.ring = nil
	g.env["BW_CLIENTID"], g.env["BW_CLIENTSECRET"] = fakeserver.ClientID, fakeserver.ClientSecret
	g.mustRun("login", "--apikey", "--nointeraction")
	if r := g.run("create", "folder", b64(`{"name":"x"}`), "--nointeraction"); r.err != "Vault is locked." {
		t.Fatalf("locked write = %+v", r)
	}
	g.env["PW"] = fakeserver.Password
	delete(g.env, "BW_CLIENTID")
	delete(g.env, "BW_CLIENTSECRET")
	g.env["BW_SESSION"] = g.mustRun("unlock", "--passwordenv", "PW", "--raw")
	// Keyring-free, the API key was never kept: there is no local-only write.
	if r := g.run("create", "folder", b64(`{"name":"x"}`)); r.code != 1 || !strings.Contains(r.err, "No sign-in credentials") {
		t.Fatalf("write without credentials = %+v", r)
	}
	for _, req := range g.srv.Requests() {
		if req.Method != "GET" && !strings.HasPrefix(req.Path, "/identity/") {
			t.Fatalf("%s %s reached the server", req.Method, req.Path)
		}
	}
}

// A lock waits for a write in progress, so the write commits whole and the
// lock still ends the session.
func TestLockWaitsForAWrite(t *testing.T) {
	g := newGV(t)
	key := g.login()
	writeReturned := make(chan struct{})
	var wg sync.WaitGroup
	var lockWaited bool
	once := sync.Once{}
	g.srv.Configure(func(c *fakeserver.Config) {
		c.OnWrite = func() {
			once.Do(func() {
				wg.Add(1)
				go func() {
					defer wg.Done()
					lockEnv := &gvTest{t: t, srv: g.srv, env: g.env, ring: g.ring, goos: g.goos}
					lockEnv.mustRun("lock")
					select {
					case <-writeReturned:
						lockWaited = true
					default:
					}
				}()
			})
		}
	})
	g.mustRun("create", "folder", b64(`{"name":"During a lock"}`))
	close(writeReturned)
	wg.Wait()
	if !lockWaited {
		t.Fatal("the lock landed while the write was in progress")
	}
	if r := g.run("unlock", "--check", "--session", key); r.code != 1 {
		t.Fatal("the session survived the lock")
	}
	g.env["PW"] = fakeserver.Password
	g.env["BW_SESSION"] = g.mustRun("unlock", "--passwordenv", "PW", "--raw")
	if out := g.mustRun("list", "folders", "--search", "during"); !strings.Contains(out, "During a lock") {
		t.Fatalf("the committed folder is missing locally: %q", out)
	}
}

// Editing keeps what the JSON leaves out: custom fields and history when
// absent, and the local copy matches the server afterwards.
func TestEditKeepsFieldsTheJSONOmits(t *testing.T) {
	g := newGV(t)
	g.login()
	out := g.mustRun("edit", "item", fakeserver.ItemGitHub, b64(`{"type":1,"name":"GitHub","login":{"username":"alice","password":"gh-secret"}}`))
	if !strings.Contains(out, `"name":"pin","value":"4321"`) || !strings.Contains(out, `"password":"old-gh-secret"`) {
		t.Fatalf("edit dropped fields or history: %s", out)
	}
	if r := g.run("edit", "item", fakeserver.ItemGitHub, b64(`{"type":2,"name":"Now a note"}`)); r.code != 1 || !strings.Contains(r.err, "type") {
		t.Fatalf("type change = %+v", r)
	}
	if r := g.run("create", "item", b64(`{"type":9,"name":"Unknown"}`)); r.code != 1 || r.err != "Item type 9 is not available." {
		t.Fatalf("unknown type = %+v", r)
	}
}
