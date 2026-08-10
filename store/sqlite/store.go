package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// Store composes the durable local storage capabilities.
type Store struct {
	db                         *database
	activationHistoryRetention int
	cursorKey                  [32]byte
	closeOnce                  sync.Once
	closeErr                   error
	revisions                  revisionReservationSet
	generations                generationWaitSet

	snapshotMu          sync.Mutex
	snapshotClosing     bool
	snapshotShutdown    chan struct{}
	snapshotOpeners     int
	snapshotOpenersDone chan struct{}
	snapshots           map[*snapshot]struct{}
}

var _ store.Store = (*Store)(nil)

// Open opens one existing, fully migrated durable policy store. It never
// creates a database, applies migrations, or repairs durable state.
func Open(config Config) (*Store, error) {
	ctx := context.Background()
	config, lock, err := acquireRuntimeSharedLock(ctx, config, false)
	if err != nil {
		return nil, err
	}
	// The retained runtime shared lock prevents an exclusive migration from
	// changing the durable schema between this read-only validation and the
	// eventual pool lifetime. No writable connector exists until it passes.
	if err := validateSchemaUnderSharedLock(ctx, config); err != nil {
		_ = lock.Close()
		return nil, err
	}
	database, err := openExistingDatabaseWithLock(ctx, config, lock)
	if err != nil {
		// The database constructor owns and closes the transferred lock on every
		// partial-pool failure path.
		return nil, err
	}
	result, err := newStoreFromDatabase(ctx, database)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return result, nil
}

func openMigratedStore(ctx context.Context, config Config) (*Store, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	database, err := openExistingDatabase(ctx, config)
	if err != nil {
		return nil, err
	}
	result, err := newStoreFromDatabase(ctx, database)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return result, nil
}

func newStoreFromDatabase(ctx context.Context, database *database) (*Store, error) {
	if err := validateRuntimeState(ctx, database); err != nil {
		return nil, err
	}
	key, err := loadCursorKey(ctx, database)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:                         database,
		activationHistoryRetention: database.config.ActivationHistoryRetention,
		cursorKey:                  key,
		snapshotShutdown:           make(chan struct{}),
	}, nil
}

func loadCursorKey(ctx context.Context, database *database) ([32]byte, error) {
	var result [32]byte
	if database == nil {
		return result, sqliteError(policyengine.ErrorIntegrity)
	}
	release, err := database.acquireReader(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	return readCursorKey(ctx, database.readers)
}

// Close releases SQLite resources. Concurrent calls observe the same result.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	s.closeOnce.Do(func() {
		snapshotErr := s.closeOwnedSnapshots()
		databaseErr := s.db.Close()
		if snapshotErr != nil {
			s.closeErr = snapshotErr
			return
		}
		s.closeErr = databaseErr
	})
	return s.closeErr
}

// beginSnapshotOpen admits one in-flight OpenSnapshot operation. Store.Close
// closes snapshotShutdown before draining existing views, so waiters and
// racing openers can leave without allowing a new pinned connection to escape
// the instance lifetime.
func (s *Store) beginSnapshotOpen() bool {
	if s == nil {
		return false
	}
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	if s.snapshotClosing {
		return false
	}
	s.snapshotOpeners++
	if s.snapshotOpeners == 1 {
		s.snapshotOpenersDone = make(chan struct{})
	}
	return true
}

func (s *Store) endSnapshotOpen() {
	if s == nil {
		return
	}
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	if s.snapshotOpeners == 0 {
		return
	}
	s.snapshotOpeners--
	if s.snapshotOpeners == 0 && s.snapshotOpenersDone != nil {
		close(s.snapshotOpenersDone)
	}
}

func (s *Store) registerSnapshot(view *snapshot) bool {
	if s == nil || view == nil {
		return false
	}
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	if s.snapshotClosing {
		return false
	}
	if s.snapshots == nil {
		s.snapshots = make(map[*snapshot]struct{})
	}
	view.owner = s
	s.snapshots[view] = struct{}{}
	return true
}

func (s *Store) unregisterSnapshot(view *snapshot) {
	if s == nil || view == nil {
		return
	}
	s.snapshotMu.Lock()
	delete(s.snapshots, view)
	s.snapshotMu.Unlock()
}

func (s *Store) closeOwnedSnapshots() error {
	if s == nil {
		return nil
	}
	s.snapshotMu.Lock()
	if !s.snapshotClosing {
		s.snapshotClosing = true
		if s.snapshotShutdown != nil {
			close(s.snapshotShutdown)
		}
	}
	views := make([]*snapshot, 0, len(s.snapshots))
	for view := range s.snapshots {
		views = append(views, view)
	}
	done := s.snapshotOpenersDone
	opening := s.snapshotOpeners
	s.snapshotMu.Unlock()

	var first error
	for _, view := range views {
		if err := view.Close(); err != nil && first == nil {
			first = err
		}
	}
	if opening > 0 && done != nil {
		<-done
	}
	return first
}

func (s *Store) read(ctx context.Context, fn func(*sql.DB) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if s == nil || s.db == nil || fn == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	release, err := s.db.acquireReader(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := fn(s.db.readers); err != nil {
		return mapError(ctx, err)
	}
	return contextError(ctx)
}

// String returns only static privacy-safe store metadata.
func (*Store) String() string { return "Store{[REDACTED]}" }

// GoString returns only static privacy-safe store metadata.
func (*Store) GoString() string { return "Store{[REDACTED]}" }

// Format redacts all store configuration and durable values.
func (*Store) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("Store{[REDACTED]}"))
}

// LogValue returns static privacy-safe structured logging metadata.
func (*Store) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", "Store"), slog.String("value", "[REDACTED]"))
}
