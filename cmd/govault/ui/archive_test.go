package ui

import (
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func TestArchiveAndUnarchiveFromTheDetailView(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{Username: "b", Password: "p"}}
	svc.order = append(svc.order, "c-mine")
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})

	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("id:detail-archive", 2*time.Second)
	app.Press("id:detail-archive")
	app.WaitUntil(2*time.Second, func() bool { return m.AllCounts.Get().Archive == 1 })
	for _, it := range m.Core.Search("", state.SearchFilter{Category: state.FilterAll}) {
		if it.ID == "c-mine" {
			t.Fatal("an archived item stays in All Items")
		}
	}
	app.Find("id:sidebar-archive >> text:1")

	app.Press("id:sidebar-archive")
	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("id:detail-unarchive", 2*time.Second)
	app.Find("id:detail-view >> text:Archived")
	app.Press("id:detail-unarchive")
	app.WaitUntil(2*time.Second, func() bool { return m.AllCounts.Get().Archive == 0 })
	if c, _ := svc.GetCipher("c-mine"); c.ArchivedDate != nil {
		t.Fatal("unarchive did not apply")
	}
}

func TestArchiveIsPremiumButUnarchiveIsNot(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.noPremium = true
	when := time.Now()
	svc.ciphers["c-old"] = &state.Cipher{ID: "c-old", Type: api.CipherTypeLogin, Name: "Old", ArchivedDate: &when, Login: &state.Login{}}
	svc.ciphers["c-mine"] = &state.Cipher{ID: "c-mine", Type: api.CipherTypeLogin, Name: "Mine", Login: &state.Login{}}
	svc.order = append(svc.order, "c-old", "c-mine")
	app, m, root := startSecurityApp(t, svc, PlatformHooks{})
	app.Post(func() { m.SelectCipher(root, "c-mine") })
	app.WaitFor("id:detail-archive", 2*time.Second)
	if app.Enabled("id:detail-archive") {
		t.Fatal("Archive is offered without premium")
	}
	app.Post(func() { m.SelectCipher(root, "c-old") })
	app.WaitFor("id:detail-unarchive", 2*time.Second)
	if !app.Enabled("id:detail-unarchive") || app.Enabled("id:detail-favorite") {
		t.Fatalf("without premium: unarchive enabled %v, favorite enabled %v", app.Enabled("id:detail-unarchive"), app.Enabled("id:detail-favorite"))
	}
}
