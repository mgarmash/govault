package profile

import (
	"errors"

	"github.com/txchen/govault/internal/vaultcore/store"
)

// sequencedStore numbers every snapshot it saves one past the saved one,
// so Sync can tell a commit landed while it fetched. Callers hold the
// profile exclusively.
type sequencedStore struct{ *store.FileStore }

func (s sequencedStore) SaveSnapshot(snap *store.Snapshot) error {
	seq, err := s.sequence(snap.AccountID)
	if err != nil {
		return err
	}
	snap.Sequence = seq + 1
	return s.FileStore.SaveSnapshot(snap)
}

// sequence is the saved snapshot's number, 0 when there is none.
func (s sequencedStore) sequence(accountID string) (uint64, error) {
	cur, err := s.LoadSnapshot(accountID)
	if errors.Is(err, store.ErrSnapshotNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return cur.Sequence, nil
}
