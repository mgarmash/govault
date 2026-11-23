package cli

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

var guidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

func isGUID(s string) bool { return guidPattern.MatchString(s) }

// normalizeSearch removes combining diacritics, as bw's
// normalizeSearchQuery does.
func normalizeSearch(s string) string {
	decomposed := norm.NFD.String(s)
	return strings.Map(func(r rune) rune {
		if r >= 0x300 && r <= 0x36f {
			return -1
		}
		return r
	}, decomposed)
}

// lowerJS lowercases like String.prototype.toLowerCase for the cases that
// matter here.
func lowerJS(s string) string { return strings.ToLower(s) }

// subtitle is the item's list subtitle, which search also matches.
func subtitle(c *state.Cipher) string {
	switch c.Type {
	case api.CipherTypeLogin:
		if c.Login == nil {
			return ""
		}
		if c.Login.Username == "" && len(c.Login.Fido2Credentials) > 0 {
			return c.Login.Fido2Credentials[0].UserName
		}
		return c.Login.Username
	case api.CipherTypeCard:
		if c.Card == nil {
			return ""
		}
		sub := c.Card.Brand
		if n := c.Card.Number; len(n) >= 4 {
			if sub != "" {
				sub += ", "
			}
			count := 4
			if len(n) >= 5 && (strings.HasPrefix(n, "34") || strings.HasPrefix(n, "37")) {
				count = 5
			}
			sub += "*" + n[len(n)-count:]
		}
		return sub
	case api.CipherTypeIdentity:
		if c.Identity == nil {
			return ""
		}
		return strings.TrimSpace(c.Identity.FirstName + " " + c.Identity.LastName)
	case api.CipherTypeSSHKey:
		if c.SSHKey != nil {
			return c.SSHKey.KeyFingerprint
		}
	}
	return ""
}

const matchRegex = 4

// searchBasic keeps the items in which every word of query occurs in the
// name, subtitle, a login host name or the notes; words of eight or more
// characters also match the start of the ID. This is bw's
// searchCiphersBasic.
func searchBasic(items []*state.Cipher, query string) []*state.Cipher {
	terms := strings.Fields(normalizeSearch(lowerJS(strings.TrimSpace(query))))
	var out []*state.Cipher
	for _, c := range items {
		if matchesAll(c, terms) {
			out = append(out, c)
		}
	}
	return out
}

func matchesAll(c *state.Cipher, terms []string) bool {
	contains := func(s, term string) bool {
		return s != "" && strings.Contains(normalizeSearch(lowerJS(s)), term)
	}
	for _, term := range terms {
		switch {
		case contains(c.Name, term):
		case len(term) >= 8 && strings.HasPrefix(c.ID, term):
		case contains(subtitle(c), term):
		case c.Login != nil && slices.ContainsFunc(c.Login.URIs, func(u state.LoginURI) bool {
			if u.URI == "" || (u.Match != nil && *u.Match == matchRegex) {
				return false
			}
			return contains(hostname(u.URI), term)
		}):
		case contains(c.Notes, term):
		default:
			return false
		}
	}
	return true
}

// parseURI parses s as a URL, assuming http:// when it has no scheme, the
// way Bitwarden's URL helpers do.
func parseURI(s string) *url.URL {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		if !strings.Contains(s, ".") {
			return nil
		}
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// hostname is a URI's host name in lowercase, or "".
func hostname(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"data:", "about:", "file:"} {
		if strings.HasPrefix(s, p) {
			return ""
		}
	}
	u := parseURI(s)
	if u == nil {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if a, err := idna.ToASCII(h); err == nil {
		h = a
	}
	return h
}

// host is a URL's host and non-default port, as URL.host gives.
func host(s string) string {
	u := parseURI(s)
	if u == nil {
		return ""
	}
	h := hostname(s)
	if h == "" {
		return ""
	}
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		h += ":" + port
	}
	return h
}

// domain is the registrable domain of a URI (its public suffix plus one
// label), the host itself for localhost and IP addresses, or "".
func domain(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "about:") {
		return ""
	}
	h := hostname(s)
	if h == "" {
		return ""
	}
	if h == "localhost" || net.ParseIP(strings.Trim(h, "[]")) != nil {
		return h
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return d
}

// domainMatchExclusions are hosts that never match their domain.
var domainMatchExclusions = map[string][]string{"google.com": {"script.google.com"}}

// matchesURL reports whether a login URI matches target under its match
// rule, or defaultMatch when it has none. bw's CLI requests the vault
// without equivalent domains, so none apply here either.
func matchesURL(u state.LoginURI, target string, defaultMatch int) bool {
	if u.URI == "" || target == "" {
		return false
	}
	mode := defaultMatch
	if u.Match != nil {
		mode = *u.Match
	}
	switch mode {
	case 0:
		d := domain(u.URI)
		if d == "" || d != domain(target) {
			return false
		}
		if excluded, ok := domainMatchExclusions[d]; ok {
			return !slices.Contains(excluded, host(target))
		}
		return true
	case 1:
		h := host(target)
		return h != "" && h == host(u.URI)
	case 2:
		return strings.HasPrefix(target, u.URI)
	case 3:
		return target == u.URI
	case matchRegex:
		re, err := regexp.Compile("(?i)" + u.URI)
		return err == nil && re.MatchString(target)
	}
	return false
}

func matchesAnyURL(c *state.Cipher, target string, defaultMatch int) bool {
	if c.Type != api.CipherTypeLogin || c.Login == nil {
		return false
	}
	for _, u := range c.Login.URIs {
		if matchesURL(u, target, defaultMatch) {
			return true
		}
	}
	return false
}

// collator is not safe for concurrent use: in-process callers, such as
// tests running several commands, take it under collatorMu.
var (
	collatorMu sync.Mutex
	collator   = collate.New(language.English, collate.IgnoreCase, collate.IgnoreDiacritics, collate.Numeric)
)

func compareNames(a, b string) int {
	collatorMu.Lock()
	defer collatorMu.Unlock()
	return collator.CompareString(a, b)
}

// sortItems orders items by name, then login items by name and username,
// as bw's locale sorting function does.
func sortItems(items []*state.Cipher) {
	slices.SortStableFunc(items, func(a, b *state.Cipher) int {
		if r := compareNames(a.Name, b.Name); r != 0 || a.Type != api.CipherTypeLogin || b.Type != api.CipherTypeLogin {
			return r
		}
		an, bn := a.Name, b.Name
		if a.Login != nil {
			an += a.Login.Username
		}
		if b.Login != nil {
			bn += b.Login.Username
		}
		return compareNames(an, bn)
	})
}

// Policy types from the server's enum.
const (
	policyRestrictedItemTypes = 15
	policyURIMatchDefaults    = 16
)

// policyApplies is the subset of an organization's policies that binds
// this user: the policy is on and the membership is accepted or confirmed.
func policyApplies(p state.Policy, orgs []state.ViewOrganization) bool {
	if !p.Enabled {
		return false
	}
	for _, o := range orgs {
		if o.ID == p.OrganizationID {
			return o.Status == 1 || o.Status == 2
		}
	}
	return false
}

// restrictions maps each item type an organization policy restricts to the
// organizations that still allow it. Owners and admins are not exempt.
func restrictions(v *state.VaultView) map[int][]string {
	var policies []state.Policy
	for _, p := range v.Policies {
		if p.Type == policyRestrictedItemTypes && policyApplies(p, v.Organizations) {
			policies = append(policies, p)
		}
	}
	if len(policies) == 0 {
		return nil
	}
	typesOf := func(p state.Policy) []int {
		var types []int
		if json.Unmarshal(p.Data, &types) != nil || types == nil {
			return []int{int(api.CipherTypeCard)}
		}
		return types
	}
	out := map[int][]string{}
	for _, p := range policies {
		for _, t := range typesOf(p) {
			if _, ok := out[t]; ok {
				continue
			}
			allow := []string{}
			for _, o := range v.Organizations {
				var own *state.Policy
				for i := range policies {
					if policies[i].OrganizationID == o.ID {
						own = &policies[i]
					}
				}
				if own == nil || !slices.Contains(typesOf(*own), t) {
					allow = append(allow, o.ID)
				}
			}
			out[t] = allow
		}
	}
	return out
}

func restricted(c *state.Cipher, r map[int][]string) bool {
	allow, ok := r[int(c.Type)]
	if !ok {
		return false
	}
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		return !slices.Contains(allow, *c.OrganizationID)
	}
	return true
}

// defaultURIMatch is the organization policy's default URI match rule, or
// domain matching.
func defaultURIMatch(v *state.VaultView) int {
	for _, p := range v.Policies {
		if p.Type != policyURIMatchDefaults || !policyApplies(p, v.Organizations) || len(p.Data) == 0 {
			continue
		}
		var data struct {
			URIMatchDetection *int `json:"uriMatchDetection"`
		}
		if json.Unmarshal(p.Data, &data) == nil && data.URIMatchDetection != nil && *data.URIMatchDetection >= 1 && *data.URIMatchDetection <= 5 {
			return *data.URIMatchDetection
		}
	}
	return 0
}

func isBlank(s string) bool { return strings.TrimFunc(s, unicode.IsSpace) == "" }
