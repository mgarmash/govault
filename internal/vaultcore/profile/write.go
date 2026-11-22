package profile

import (
	"context"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

// Writer is the unlocked vault open for changes: the desktop's
// state.Service over this profile's snapshot.
type Writer struct {
	*state.Service
	AccountID string
	// View is the vault as it was when the write began, for lookups the
	// Service has no form of, such as the premium flag and policies.
	View *state.VaultView
}

// Write unlocks the vault with sessionKey and runs fn with a Service that
// changes it through the server. The profile stays locked exclusively
// until fn returns, so no lock, logout, unlock or other change lands
// meanwhile. Writes need valid credentials: there is no local-only write.
func (p *Profile) Write(ctx context.Context, sessionKey string, envKey *APIKey, fn func(*Writer) error) error {
	return p.exclusive(func() error {
		acct, err := p.activeAccount()
		if err != nil {
			return err
		}
		ps, err := p.loadProfile()
		if err != nil {
			return err
		}
		userKey, err := p.openSession(ps, acct, sessionKey)
		if err != nil {
			return err
		}
		defer userKey.Zero()
		snap, err := p.store.LoadSnapshot(acct.AccountID)
		if err != nil {
			return err
		}
		o, err := p.connect(ps, acct, userKey, envKey)
		if err != nil {
			return err
		}
		if _, err := o.token(ctx, ""); err != nil {
			return err
		}
		view, err := state.OpenVault(snap.RawSyncJSON, userKey)
		if err != nil {
			return err
		}
		defer view.Close()
		svc, err := state.NewService(state.ServiceConfig{
			Store:      p.store,
			AccountID:  acct.AccountID,
			DeviceID:   ps.DeviceID,
			DeviceName: p.opts.DeviceName,
			DeviceType: p.opts.DeviceType,
			HTTPClient: p.opts.HTTPClient,
			Tokens:     serviceTokens{o},
			NewClient:  func(string) (*api.Client, error) { return o.client, nil },
		})
		if err != nil {
			return err
		}
		if err := svc.UnlockWithUserKey(ctx, userKey); err != nil {
			return err
		}
		defer svc.Lock()
		return fn(&Writer{Service: svc, AccountID: acct.AccountID, View: view})
	})
}

// serviceTokens renews a Service's tokens through the profile's
// credentials.
type serviceTokens struct{ o *online }

func (t serviceTokens) AccessToken(ctx context.Context, stale string) (string, error) {
	return t.o.token(ctx, stale)
}
