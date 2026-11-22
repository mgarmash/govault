package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/keyring"
	"github.com/txchen/govault/internal/vaultcore/privatefile"
)

const credentialsInfo = "govault-cli credentials v1"

// renewMargin renews an access token this long before it expires.
const renewMargin = time.Minute

// APIKey is a personal API key.
type APIKey struct {
	ClientID     string
	ClientSecret string
}

// credentials is the sign-in a profile keeps: the grant's long-lived
// secret, the current access token, and the server they are bound to.
type credentials struct {
	Version      int           `json:"version"`
	AccountID    string        `json:"accountId"`
	LoginID      string        `json:"loginId"`
	Endpoints    api.Endpoints `json:"endpoints"`
	Grant        string        `json:"grant"`
	ClientID     string        `json:"clientId,omitempty"`
	ClientSecret string        `json:"clientSecret,omitempty"`
	RefreshToken string        `json:"refreshToken,omitempty"`
	AccessToken  string        `json:"accessToken,omitempty"`
	AccessExpiry time.Time     `json:"accessExpiry"`
}

// valid reports whether c belongs to acct.
func (c *credentials) valid(acct *accountState) bool {
	return c.Version == formatVersion && c.AccountID == acct.AccountID && c.LoginID == acct.LoginID &&
		c.Endpoints == acct.Endpoints && c.Grant == acct.Grant
}

func (c *credentials) fresh(now time.Time) bool {
	return c.AccessToken != "" && now.Add(renewMargin).Before(c.AccessExpiry)
}

func (p *Profile) credentialsAD(ps *profileState, acct *accountState) []byte {
	ad, _ := json.Marshal(struct {
		ProfileID, AccountID, LoginID string
	}{ps.ProfileID, acct.AccountID, acct.LoginID})
	return ad
}

// loadCredentials reads the account's credentials. A file backend needs
// userKey to open them; without it they are absent (nil, nil).
func (p *Profile) loadCredentials(ps *profileState, acct *accountState, userKey *crypto.SymmetricKey) (*credentials, error) {
	var raw []byte
	switch acct.Credentials {
	case backendKeyring:
		if p.opts.Keyring == nil {
			return nil, errors.New("profile: this account's credentials are in a credential store that is not available now")
		}
		v, err := p.opts.Keyring.Get(keyringService, ps.ProfileID)
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		raw = v
	case backendFile:
		if userKey == nil {
			return nil, nil
		}
		sealed, err := os.ReadFile(p.path(credentialsFile))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		key, err := p.credentialsKey(userKey)
		if err != nil {
			return nil, err
		}
		defer crypto.ZeroBytes(key[:])
		if raw, err = crypto.Open(key, sealed, p.credentialsAD(ps, acct)); err != nil {
			return nil, fmt.Errorf("profile: %s: %w", credentialsFile, err)
		}
	default:
		return nil, nil
	}
	defer crypto.ZeroBytes(raw)
	var c credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("profile: invalid credentials: %w", err)
	}
	if !c.valid(acct) {
		return nil, ErrServerChanged
	}
	return &c, nil
}

func (p *Profile) credentialsKey(userKey *crypto.SymmetricKey) ([32]byte, error) {
	raw := userKey.Bytes()
	defer crypto.ZeroBytes(raw[:])
	return crypto.SealKey(raw[:], credentialsInfo)
}

// saveCredentials writes c to the account's backend. The file backend
// needs userKey; without one the credentials stay in memory only.
func (p *Profile) saveCredentials(ps *profileState, acct *accountState, c *credentials, userKey *crypto.SymmetricKey) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(raw)
	switch acct.Credentials {
	case backendKeyring:
		if p.opts.Keyring == nil {
			return errors.New("profile: the credential store is not available")
		}
		return p.opts.Keyring.Set(keyringService, ps.ProfileID, raw)
	case backendFile:
		if userKey == nil {
			return nil
		}
		key, err := p.credentialsKey(userKey)
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(key[:])
		sealed, err := crypto.Seal(key, raw, p.credentialsAD(ps, acct))
		if err != nil {
			return err
		}
		return privatefile.WriteFile(p.path(credentialsFile), sealed)
	}
	return nil
}

// online is one authenticated client of the account.
type online struct {
	p       *Profile
	ps      *profileState
	acct    *accountState
	client  *api.Client
	userKey *crypto.SymmetricKey
	envKey  *APIKey
	creds   *credentials
}

// connect prepares authenticated requests for acct. userKey (from a valid
// session) opens file-backed credentials; envKey stands in for missing
// API-key credentials.
func (p *Profile) connect(ps *profileState, acct *accountState, userKey *crypto.SymmetricKey, envKey *APIKey) (*online, error) {
	if err := p.checkEndpoints(ps, acct); err != nil {
		return nil, err
	}
	client, err := p.newClient(acct.Endpoints, ps.DeviceID)
	if err != nil {
		return nil, err
	}
	return &online{p: p, ps: ps, acct: acct, client: client, userKey: userKey, envKey: envKey}, nil
}

// token returns an access token that is not stale, renewing it when it
// expires or was rejected. Renewal runs under credentials.lock: a process
// that waited finds the token another one renewed and uses it.
func (o *online) token(ctx context.Context, stale string) (string, error) {
	if o.creds != nil && o.creds.AccessToken != stale && o.creds.fresh(o.p.opts.Now()) {
		return o.creds.AccessToken, nil
	}
	var tok string
	err := o.p.withLock(credsLockFile, true, func() error {
		acct, err := o.p.loadAccount()
		if err != nil || acct.LoginID != o.acct.LoginID || acct.LoggingOut {
			return ErrStale
		}
		creds, err := o.p.loadCredentials(o.ps, o.acct, o.userKey)
		if err != nil {
			return err
		}
		if creds != nil && creds.AccessToken != stale && creds.fresh(o.p.opts.Now()) {
			o.creds, tok = creds, creds.AccessToken
			return nil
		}
		if creds == nil {
			if o.acct.Grant != GrantAPIKey || o.envKey == nil {
				return ErrNoCredentials
			}
			creds = &credentials{
				Version: formatVersion, AccountID: o.acct.AccountID, LoginID: o.acct.LoginID,
				Endpoints: o.acct.Endpoints, Grant: GrantAPIKey,
				ClientID: o.envKey.ClientID, ClientSecret: o.envKey.ClientSecret,
			}
		}
		if err := o.renew(ctx, creds); err != nil {
			return err
		}
		if err := o.p.saveCredentials(o.ps, o.acct, creds, o.userKey); err != nil {
			return err
		}
		o.creds, tok = creds, creds.AccessToken
		return nil
	})
	return tok, err
}

// renew exchanges the grant's secret for a new access token and checks it
// was issued for this account.
func (o *online) renew(ctx context.Context, c *credentials) error {
	var resp *api.TokenResponse
	var err error
	switch c.Grant {
	case GrantPassword:
		if c.RefreshToken == "" {
			return ErrSignInRequired
		}
		resp, err = o.client.RefreshToken(ctx, c.RefreshToken)
	case GrantAPIKey:
		resp, err = o.client.LoginAPIKey(ctx, c.ClientID, c.ClientSecret)
	default:
		return ErrSignInRequired
	}
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 400 {
			return fmt.Errorf("%w: %s", ErrSignInRequired, apiErr.Message)
		}
		return err
	}
	sub, err := api.TokenSubject(resp.AccessToken)
	if err != nil {
		return err
	}
	if sub != c.AccountID {
		return ErrDifferentAccount
	}
	c.AccessToken = resp.AccessToken
	c.AccessExpiry = o.p.opts.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	if resp.RefreshToken != "" {
		c.RefreshToken = resp.RefreshToken
	}
	return nil
}

// call runs fn with a valid access token; when the server rejects the
// token, it renews it and retries once.
func call[T any](ctx context.Context, o *online, fn func(token string) (T, error)) (T, error) {
	var zero T
	tok, err := o.token(ctx, "")
	if err != nil {
		return zero, err
	}
	res, err := fn(tok)
	if !errors.Is(err, api.ErrUnauthorized) {
		return res, err
	}
	if tok, err = o.token(ctx, tok); err != nil {
		return zero, err
	}
	return fn(tok)
}
