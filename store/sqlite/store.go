package sqlite

import (
	"context"
	"database/sql"
	"errors"
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
}

var _ store.Store = (*Store)(nil)

// Open opens one existing, fully migrated durable policy store. It never
// creates a database, applies migrations, or repairs durable state.
func Open(config Config) (*Store, error) {
	ctx := context.Background()
	database, err := openExistingDatabase(ctx, config)
	if err != nil {
		return nil, err
	}
	// Retain the runtime shared lock while validating. That prevents an
	// exclusive migration from changing the durable schema between validation
	// and the lifetime that will serve public requests.
	if err := ValidateSchema(ctx, config); err != nil {
		_ = database.Close()
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
	key, err := loadCursorKey(ctx, database)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:                         database,
		activationHistoryRetention: database.config.ActivationHistoryRetention,
		cursorKey:                  key,
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

	var value []byte
	err = database.readers.QueryRowContext(ctx, "SELECT value FROM cadrena_meta WHERE key = ?", cursorKeyMetaKey).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return result, sqliteError(policyengine.ErrorIntegrity)
	}
	if err != nil {
		return result, mapError(ctx, err)
	}
	if len(value) != len(result) {
		return result, sqliteError(policyengine.ErrorIntegrity)
	}
	copy(result[:], value)
	if err := contextError(ctx); err != nil {
		return [32]byte{}, err
	}
	return result, nil
}

// Close releases SQLite resources. Concurrent calls observe the same result.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
	})
	return s.closeErr
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
