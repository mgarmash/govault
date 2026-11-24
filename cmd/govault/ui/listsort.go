package ui

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/state"
)

// ListSort is how the vault list is ordered.
type ListSort string

const (
	// SortDefault is the order search gives: by name, best matches first
	// while searching.
	SortDefault        ListSort = ""
	SortNameDesc       ListSort = "nameDesc"
	SortModifiedNewest ListSort = "modifiedNewest"
	SortModifiedOldest ListSort = "modifiedOldest"
)

// SortItems orders items, already in the default order, as s asks. Ties
// keep the name order.
func SortItems(items []state.CipherSummary, s ListSort) []state.CipherSummary {
	byName := func(a, b state.CipherSummary) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.ID, b.ID))
	}
	modified := func(c state.CipherSummary) time.Time {
		if c.RevisionDate == nil {
			return time.Time{}
		}
		return *c.RevisionDate
	}
	switch s {
	case SortNameDesc:
		slices.SortStableFunc(items, func(a, b state.CipherSummary) int { return byName(b, a) })
	case SortModifiedNewest:
		slices.SortStableFunc(items, func(a, b state.CipherSummary) int {
			return cmp.Or(modified(b).Compare(modified(a)), byName(a, b))
		})
	case SortModifiedOldest:
		slices.SortStableFunc(items, func(a, b state.CipherSummary) int {
			return cmp.Or(modified(a).Compare(modified(b)), byName(a, b))
		})
	}
	return items
}

// SetListSort orders the list as s asks and remembers it.
func (m *AppModel) SetListSort(s ListSort) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.ListSort = s
		return p
	})
	m.RefreshFilteredList()
}
