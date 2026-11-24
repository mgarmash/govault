package state

import (
	"slices"
	"strings"
)

type scoredSummary struct {
	summary CipherSummary
	score   int
}

// searchCiphers lists the ciphers filter selects that match query. hidden
// reports an item whose passwords the user may not see, which search
// treats as the detail view does: nothing it hides can be found.
func searchCiphers(ciphers map[string]*Cipher, query string, filter SearchFilter, hidden func(*Cipher) bool) []CipherSummary {
	q := strings.ToLower(strings.TrimSpace(query))
	var matches []scoredSummary

	for _, c := range ciphers {
		if !matchesFilter(c, filter) {
			continue
		}
		summary := summarizeCipher(c)
		if q == "" {
			matches = append(matches, scoredSummary{summary: summary, score: 0})
			continue
		}
		if score, ok := scoreCipher(c, summary, q, hidden(c)); ok {
			matches = append(matches, scoredSummary{summary: summary, score: score})
		}
	}

	slices.SortFunc(matches, func(a, b scoredSummary) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return strings.Compare(strings.ToLower(a.summary.Name), strings.ToLower(b.summary.Name))
	})

	out := make([]CipherSummary, len(matches))
	for i, m := range matches {
		out[i] = m.summary
	}
	return out
}

func matchesFilter(c *Cipher, filter SearchFilter) bool {
	isDeleted := c.DeletedDate != nil
	if filter.Category == FilterTrash {
		return isDeleted
	}
	if isDeleted {
		return false
	}
	isArchived := c.ArchivedDate != nil
	if filter.Category == FilterArchive {
		return isArchived
	}
	if isArchived {
		return false
	}

	if filter.Type != nil && c.Type != *filter.Type {
		return false
	}
	if filter.OrganizationID != "" && (c.OrganizationID == nil || *c.OrganizationID != filter.OrganizationID) {
		return false
	}
	if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
		return false
	}
	if filter.FolderID != "" {
		return c.FolderID != nil && *c.FolderID == filter.FolderID
	}

	switch filter.Category {
	case FilterFavorites:
		return c.Favorite
	case FilterNoFolder:
		return c.FolderID == nil || *c.FolderID == ""
	default:
		return true
	}
}

// Custom field types search may read: text and boolean. Hidden fields are
// secrets, and linked fields hold no value.
const (
	fieldText    = 0
	fieldBoolean = 2
)

// scoreCipher matches q against what an item shows without revealing a
// secret: its name, subtitle, websites and notes; the names and values of
// its text and boolean fields unless it hides passwords; a card's brand and
// the last four digits of its number, those also only when it does not
// hide passwords; an SSH key's fingerprint; an identity's name, company,
// email and username. Passwords, TOTP secrets, hidden fields, card codes,
// private keys and identity numbers are never searched.
func scoreCipher(c *Cipher, summary CipherSummary, q string, hidesPasswords bool) (int, bool) {
	best := 0
	matched := false

	check := func(field string, weight int) {
		if field == "" {
			return
		}
		s := matchScore(strings.ToLower(field), q)
		if s > 0 {
			total := s * weight
			if !matched || total > best {
				best = total
				matched = true
			}
		}
	}

	check(summary.Name, 10)
	check(summary.Subtitle, 6)
	if c.Login != nil {
		for _, u := range c.Login.URIs {
			check(u.URI, 5)
		}
	}
	check(c.Notes, 2)
	if !hidesPasswords {
		for _, f := range c.Fields {
			if f.Type == fieldText || f.Type == fieldBoolean {
				check(f.Name, 3)
				check(f.Value, 3)
			}
		}
	}
	if k := c.Card; k != nil {
		check(k.Brand, 4)
		if digits := strings.TrimSpace(k.Number); !hidesPasswords && len(digits) >= 4 {
			// Only the last four: the whole number is a secret.
			check(digits[len(digits)-4:], 4)
		}
	}
	if k := c.SSHKey; k != nil {
		check(k.KeyFingerprint, 4)
	}
	if i := c.Identity; i != nil {
		check(strings.Join(strings.Fields(i.FirstName+" "+i.MiddleName+" "+i.LastName), " "), 5)
		check(i.Company, 4)
		check(i.Email, 4)
		check(i.Username, 4)
	}

	return best, matched
}

func matchScore(haystack, needle string) int {
	if haystack == needle {
		return 100
	}
	if strings.HasPrefix(haystack, needle) {
		return 80
	}
	if strings.Contains(haystack, needle) {
		return 60
	}
	if isSubsequence(haystack, needle) {
		return 30
	}
	return 0
}

func isSubsequence(haystack, needle string) bool {
	hi := 0
	for ni := 0; ni < len(needle); ni++ {
		idx := strings.IndexByte(haystack[hi:], needle[ni])
		if idx < 0 {
			return false
		}
		hi += idx + 1
	}
	return true
}
