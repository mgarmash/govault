// Package fakeserver is a Bitwarden-compatible test server shaped after
// Vaultwarden 1.37.5. It serves one fixture account to gv tests and, for
// contract fixtures, to the official bw client.
package fakeserver

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

// Request is one request the server received.
type Request struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Form   map[string]string
}

// Config is what tests may change while the server runs.
type Config struct {
	// Premium sends premium: true in the profile.
	Premium bool
	// TwoFactor lists the providers (by number) a password login must pass,
	// with the code each accepts.
	TwoFactor map[int]string
	// TokenLifetime is the expires_in the server answers.
	TokenLifetime time.Duration
	// Policies is the sync policies list.
	Policies []map[string]any
	// OnSync runs inside each /api/sync request before it is answered.
	OnSync func()
	// Subject, when set, is the user ID new access tokens claim.
	Subject string
	// OmitPermissions leaves edit and viewPassword out of every item.
	OmitPermissions bool
	// OnWrite runs inside each request that changes the vault, before it
	// is applied.
	OnWrite func()
	// EngHidesPasswords makes the Engineering collection hide passwords.
	EngHidesPasswords bool
	// ClaimPadding adds a claim of this many bytes to access tokens, as
	// claim-heavy servers issue them.
	ClaimPadding int
}

// Server is a running fake server.
type Server struct {
	prefix string
	cfg    Config

	mu            sync.Mutex
	http          *httptest.Server
	email         string
	keys          *keys
	attachment    []byte
	requests      []Request
	tokens        map[string]string // access token -> grant type
	refresh       map[string]bool
	rejectNext    bool
	tokenSeq      int
	emailSends    int
	revision      time.Time
	syncCount     int
	userKeyID     string
	items         []obj
	folders       []obj
	blobs         map[string][]byte
	idSeq         int
	kdfIterations int
}

// Option configures a server before it starts.
type Option func(*Server)

// WithKDFIterations sets the account's PBKDF2 iterations. Official clients
// migrate accounts below 600000, which this server does not implement.
func WithKDFIterations(n int) Option { return func(s *Server) { s.kdfIterations = n } }

// WithPrefix mounts the server under a path, like a self-hosted server
// whose base URL has one.
func WithPrefix(prefix string) Option { return func(s *Server) { s.prefix = prefix } }

// New starts a fake server with the fixture vault, over plain HTTP.
func New(opts ...Option) *Server { return start(false, opts) }

// NewTLS starts it over HTTPS with a self-signed certificate, which
// CertPEM returns.
func NewTLS(opts ...Option) *Server { return start(true, opts) }

func start(useTLS bool, opts []Option) *Server {
	s := &Server{
		cfg:           Config{Premium: true, TokenLifetime: time.Hour},
		email:         Email,
		kdfIterations: DefaultKDFIterations,
		tokens:        map[string]string{},
		refresh:       map[string]bool{},
		revision:      revised,
	}
	for _, o := range opts {
		o(s)
	}
	s.keys = newKeys(Email, Password, s.kdfIterations)
	s.attachment = s.keys.attachmentData()
	s.blobs = map[string][]byte{AttachmentID: s.attachment}
	// The vault is seeded under the lock once the address is known, before
	// any client can have it.
	s.mu.Lock()
	defer s.mu.Unlock()
	if useTLS {
		s.http = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	} else {
		s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	}
	s.items = s.seedCiphers()
	s.folders = s.seedFolders()
	return s
}

// CertPEM is the server certificate of a NewTLS server.
func (s *Server) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.http.Certificate().Raw})
}

// Client is an HTTP client that trusts the server.
func (s *Server) Client() *http.Client { return s.http.Client() }

// Close stops the server.
func (s *Server) Close() { s.http.Close() }

// URL is the base URL a client configures, including the prefix.
func (s *Server) URL() string { return s.http.URL + s.prefix }

// Configure changes the configuration under the server's lock.
func (s *Server) Configure(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
}

func (s *Server) config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Requests returns the requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count returns how many received requests satisfy match.
func (s *Server) Count(match func(Request) bool) int {
	n := 0
	for _, r := range s.Requests() {
		if match(r) {
			n++
		}
	}
	return n
}

// RejectNextToken makes the next authenticated request fail with 401 and
// forget every access token issued so far, as an expired token would.
func (s *Server) RejectNextToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectNext = true
}

// EmailCodesSent counts email two-factor codes requested.
func (s *Server) EmailCodesSent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.emailSends
}

// SyncCount counts /api/sync requests.
func (s *Server) SyncCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncCount
}

// UserPublicKey is the fixture account's public key (SPKI, base64).
func UserPublicKey() string { return publicKeyB64(parsePriv(userPrivateKeyB64)) }

// PeerPublicKey is the public key of PeerUserID.
func PeerPublicKey() string { return publicKeyB64(parsePriv(peerPrivateKeyB64)) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if s.prefix != "" {
		if !strings.HasPrefix(path, s.prefix+"/") {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, s.prefix)
	}
	_ = r.ParseForm()
	form := map[string]string{}
	for k, v := range r.PostForm {
		form[k] = strings.Join(v, ",")
	}
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Form: form})
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && (path == "/identity/accounts/prelogin" || path == "/identity/accounts/prelogin/password"):
		writeJSON(w, 200, obj{
			"kdf": 0, "kdfIterations": s.kdfIterations, "kdfMemory": nil, "kdfParallelism": nil,
			"kdfSettings": obj{"iterations": s.kdfIterations, "kdfType": 0, "memory": nil, "parallelism": nil},
			"salt":        nil,
		})
	case r.Method == http.MethodPost && path == "/identity/connect/token":
		s.token(w, r)
	case r.Method == http.MethodPost && path == "/api/two-factor/send-email-login":
		s.mu.Lock()
		s.emailSends++
		s.mu.Unlock()
		w.WriteHeader(200)
	case r.Method == http.MethodGet && path == "/api/config":
		writeJSON(w, 200, obj{"version": "2026.1.0", "gitHash": "fake", "server": obj{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}, "environment": obj{"vault": s.URL(), "api": s.URL() + "/api", "identity": s.URL() + "/identity", "notifications": s.URL() + "/notifications", "sso": ""}, "featureStates": obj{}, "object": "config"})
	case r.Method == http.MethodGet && path == "/api/devices/knowndevice":
		writeJSON(w, 200, true)
	case strings.HasPrefix(path, "/attachments/"):
		s.attachmentData(w, path)
	case strings.HasPrefix(path, "/api/"):
		if !s.authorized(w, r) {
			return
		}
		s.api(w, r, path)
	default:
		writeJSON(w, 404, obj{"message": "Not found"})
	}
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectNext {
		s.rejectNext = false
		s.tokens = map[string]string{}
	}
	if _, ok := s.tokens[tok]; !ok {
		w.WriteHeader(401)
		return false
	}
	return true
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && path == "/api/sync":
		s.mu.Lock()
		s.syncCount++
		hook := s.cfg.OnSync
		body := s.syncBody()
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case r.Method == http.MethodPost && path == "/api/accounts/key-management/user-key-id":
		var body struct {
			UserKeyID string `json:"userKeyId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.userKeyID = body.UserKeyID
		s.mu.Unlock()
		w.WriteHeader(200)
	case r.Method == http.MethodGet && path == "/api/accounts/revision-date":
		s.mu.Lock()
		rev := s.revision
		s.mu.Unlock()
		writeJSON(w, 200, rev.UnixMilli())
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "users" && parts[3] == "public-key":
		switch parts[2] {
		case UserID:
			writeJSON(w, 200, obj{"userId": UserID, "publicKey": UserPublicKey(), "object": "userKey"})
		case PeerUserID:
			writeJSON(w, 200, obj{"userId": PeerUserID, "publicKey": PeerPublicKey(), "object": "userKey"})
		default:
			writeJSON(w, 404, obj{"message": "User doesn't exist"})
		}
	case r.Method == http.MethodGet && path == "/api/collections":
		writeJSON(w, 200, obj{"data": s.orgCollections(), "object": "list", "continuationToken": nil})
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "organizations" && parts[3] == "collections":
		if parts[2] != OrgID {
			writeJSON(w, 404, obj{"message": "Organization not found"})
			return
		}
		writeJSON(w, 200, obj{"data": s.orgCollections(), "object": "list", "continuationToken": nil})
	case r.Method == http.MethodGet && len(parts) == 5 && parts[1] == "ciphers" && parts[3] == "attachment":
		s.attachmentMeta(w, parts[2], parts[4])
	default:
		if !s.write(w, r, parts) {
			writeJSON(w, 404, obj{"message": "Not found"})
		}
	}
}

func (s *Server) orgCollections() []obj {
	return []obj{
		{"id": CollectionEng, "organizationId": OrgID, "name": enc("Engineering", s.keys.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": false, "hidePasswords": s.config().EngHidesPasswords, "manage": false},
		{"id": CollectionSec, "organizationId": OrgID, "name": enc("Secrets", s.keys.orgKey), "externalId": nil, "object": "collectionDetails", "readOnly": true, "hidePasswords": true, "manage": false},
	}
}

func (s *Server) attachmentData(w http.ResponseWriter, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	s.mu.Lock()
	var data []byte
	ok := false
	if len(parts) == 3 {
		data, ok = s.blobs[parts[2]]
	}
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	switch f.Get("grant_type") {
	case "password":
		if !strings.EqualFold(f.Get("username"), s.email) || f.Get("password") != crypto.HashMasterPasswordForServer(s.keys.masterKey, []byte(Password)) {
			writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "invalid_username_or_password", "ErrorModel": obj{"Message": "Username or password is incorrect. Try again", "Object": "error"}})
			return
		}
		if tf := s.config().TwoFactor; len(tf) > 0 {
			provider, _ := strconv.Atoi(f.Get("twoFactorProvider"))
			code, ok := tf[provider]
			if f.Get("twoFactorToken") == "" || !ok || code != f.Get("twoFactorToken") {
				s.twoFactorChallenge(w, f.Get("twoFactorToken") != "")
				return
			}
		}
		writeJSON(w, 200, s.issue("password", true))
	case "refresh_token":
		s.mu.Lock()
		ok := s.refresh[f.Get("refresh_token")]
		s.mu.Unlock()
		if !ok {
			writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "Invalid refresh token"})
			return
		}
		writeJSON(w, 200, s.issue("refresh_token", true))
	case "client_credentials":
		if f.Get("scope") != "api" || f.Get("client_id") != ClientID || f.Get("client_secret") != ClientSecret {
			writeJSON(w, 400, obj{"error": "invalid_client", "error_description": "invalid_client"})
			return
		}
		if f.Get("deviceIdentifier") == "" || f.Get("deviceName") == "" || f.Get("deviceType") == "" {
			writeJSON(w, 400, obj{"error": "invalid_request", "error_description": "device_identifier cannot be blank"})
			return
		}
		writeJSON(w, 200, s.issue("client_credentials", false))
	default:
		writeJSON(w, 400, obj{"error": "unsupported_grant_type"})
	}
}

// GrantCount counts token grants of grantType issued so far.
func (s *Server) GrantCount(grantType string) int {
	return s.Count(func(r Request) bool { return r.Path == "/identity/connect/token" && r.Form["grant_type"] == grantType })
}

func (s *Server) twoFactorChallenge(w http.ResponseWriter, wrongCode bool) {
	if wrongCode {
		writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "Two factor required.", "ErrorModel": obj{"Message": "Invalid TOTP code", "Object": "error"}, "TwoFactorProviders": s.providerList(), "TwoFactorProviders2": s.providerData()})
		return
	}
	writeJSON(w, 400, obj{"error": "invalid_grant", "error_description": "Two factor required.", "TwoFactorProviders": s.providerList(), "TwoFactorProviders2": s.providerData(), "MasterPasswordPolicy": obj{"Object": "masterPasswordPolicy"}})
}

func (s *Server) providerList() []string {
	var out []string
	tf := s.config().TwoFactor
	for p := range 8 {
		if _, ok := tf[p]; ok {
			out = append(out, strconv.Itoa(p))
		}
	}
	return out
}

func (s *Server) providerData() obj {
	out := obj{}
	for p := range s.config().TwoFactor {
		switch p {
		case 1:
			out["1"] = obj{"Email": "a***e@example.com"}
		case 3:
			out["3"] = obj{"Nfc": true}
		default:
			out[strconv.Itoa(p)] = nil
		}
	}
	return out
}

func (s *Server) issue(grant string, withRefresh bool) obj {
	s.mu.Lock()
	s.tokenSeq++
	seq := s.tokenSeq
	cfg := s.cfg
	s.mu.Unlock()
	lifetime := cfg.TokenLifetime

	clientID := "cli"
	if grant == "client_credentials" {
		clientID = ClientID
	}
	sub := UserID
	if cfg.Subject != "" {
		sub = cfg.Subject
	}
	now := time.Now()
	claims := obj{
		"nbf": now.Unix(), "exp": now.Add(lifetime).Unix(), "iss": s.URL() + "|login",
		"sub": sub, "premium": cfg.Premium, "name": "Alice", "email": s.email, "email_verified": true,
		"sstamp": "stamp", "device": "dev", "devicetype": "MacOsCLI", "client_id": clientID, "scope": []string{"api", "offline_access"}, "amr": []string{"Application"},
	}
	if cfg.ClaimPadding > 0 {
		claims["padding"] = strings.Repeat("p", cfg.ClaimPadding)
	}
	payload, _ := json.Marshal(claims)
	access := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig" + strconv.Itoa(seq)

	s.mu.Lock()
	s.tokens[access] = grant
	s.mu.Unlock()
	k := s.keys
	resp := obj{
		"access_token": access, "expires_in": int(lifetime.Seconds()), "token_type": "Bearer",
		"Key": k.protectedUserKey(), "PrivateKey": k.encPrivateKey(),
		"Kdf": 0, "KdfIterations": s.kdfIterations, "KdfMemory": nil, "KdfParallelism": nil,
		"ForcePasswordReset": false, "ResetMasterPassword": false, "scope": "api offline_access", "unofficialServer": true,
		"AccountKeys": obj{
			"publicKeyEncryptionKeyPair": obj{"wrappedPrivateKey": k.encPrivateKey(), "publicKey": publicKeyB64(k.userPriv), "Object": "publicKeyEncryptionKeyPair"},
			"Object":                     "privateKeys",
		},
		"UserDecryptionOptions": obj{
			"HasMasterPassword": true,
			"MasterPasswordUnlock": obj{
				"Kdf":                       obj{"KdfType": 0, "Iterations": s.kdfIterations, "Memory": nil, "Parallelism": nil},
				"MasterKeyEncryptedUserKey": k.protectedUserKey(),
				"MasterKeyWrappedUserKey":   k.protectedUserKey(),
				"Salt":                      s.email,
			},
			"Object": "userDecryptionOptions",
		},
	}
	if withRefresh {
		rt := "refresh-" + strconv.Itoa(seq)
		s.mu.Lock()
		s.refresh[rt] = true
		s.mu.Unlock()
		resp["refresh_token"] = rt
	} else {
		resp["scope"] = "api"
	}
	return resp
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// PeerPrivateKey exists so fingerprint tests can check a peer lookup.
func PeerPrivateKey() *rsa.PrivateKey { return parsePriv(peerPrivateKeyB64) }
