package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "modernc.org/sqlite"
)

// database is the private durable SQLite foundation. It is intentionally not
// exposed until every public store capability is available.
type database struct {
	config Config

	writer  *sql.DB
	readers *sql.DB
	lock    advisoryLock

	readerAdmission chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
	closeErr        error

	writeRequests chan writeRequest
	writerDone    chan struct{}
}

type connectorFactory func(string) (driver.Connector, error)

func openDatabase(ctx context.Context, config Config) (*database, error) {
	return openDatabaseWithConnectorFactory(ctx, config, moderncsqlite.NewConnector)
}

func openDatabaseWithConnectorFactory(ctx context.Context, config Config, newConnector connectorFactory) (_ *database, err error) {
	return openDatabaseWithConnectorFactoryMode(ctx, config, newConnector, true)
}

// openExistingDatabase opens a pre-existing database without allowing SQLite
// to create a replacement file if it disappears after schema validation.
func openExistingDatabase(ctx context.Context, config Config) (*database, error) {
	return openDatabaseWithConnectorFactoryMode(ctx, config, moderncsqlite.NewConnector, false)
}

// openExistingDatabaseWithLock transfers an already-held runtime shared lock
// into the writer/reader pool lifetime. It is used by public Open only after
// read-only schema validation has completed under that same lock.
func openExistingDatabaseWithLock(ctx context.Context, config Config, lock advisoryLock) (*database, error) {
	return openDatabaseWithConnectorFactoryModeAndLock(ctx, config, moderncsqlite.NewConnector, false, lock)
}

func openDatabaseWithConnectorFactoryMode(ctx context.Context, config Config, newConnector connectorFactory, create bool) (_ *database, err error) {
	lock, err := acquireRuntimeSharedLock(ctx, config, create)
	if err != nil {
		return nil, err
	}
	database, err := openDatabaseWithConnectorFactoryModeAndLock(ctx, config, newConnector, create, lock)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return database, nil
}

// acquireRuntimeSharedLock owns the existing-only checks that must happen
// before any lock sidecar or SQLite runtime connection is created. Its caller
// transfers the held lock to a database lifetime or closes it on failure.
func acquireRuntimeSharedLock(ctx context.Context, config Config, create bool) (advisoryLock, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	// A public existing-only open must not leave even an advisory-lock sidecar
	// behind for a path that does not name a durable database.
	if !create {
		exists, statErr := sqliteDatabaseExists(config.Path)
		if statErr != nil {
			return nil, mapError(ctx, statErr)
		}
		if !exists {
			return nil, sqliteError(policyengine.ErrorFailedPrecondition)
		}
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return nil, mapError(ctx, err)
	}
	if err := lock.LockShared(ctx); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if !create {
		exists, statErr := sqliteDatabaseExists(config.Path)
		if statErr != nil {
			_ = lock.Close()
			return nil, mapError(ctx, statErr)
		}
		if !exists {
			_ = lock.Close()
			return nil, sqliteError(policyengine.ErrorFailedPrecondition)
		}
	}
	return lock, nil
}

// openDatabaseWithConnectorFactoryModeAndLock creates runtime pools only after
// its caller has acquired the shared lock. Public Open uses this after a
// read-only schema validation; direct task-foundation openers retain their
// existing create/verify behavior.
func openDatabaseWithConnectorFactoryModeAndLock(ctx context.Context, config Config, newConnector connectorFactory, create bool, lock advisoryLock) (_ *database, err error) {
	if newConnector == nil || lock == nil {
		return nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	database := &database{
		config:          config,
		lock:            lock,
		readerAdmission: make(chan struct{}, config.MaxReaders),
		closed:          make(chan struct{}),
	}
	defer func() {
		if err != nil {
			_ = database.closeResources()
		}
	}()
	if create {
		if err := ensureOwnerOnlyDatabaseFile(config.Path); err != nil {
			return nil, mapError(ctx, err)
		}
	} else {
		exists, statErr := sqliteDatabaseExists(config.Path)
		if statErr != nil {
			return nil, mapError(ctx, statErr)
		}
		if !exists {
			return nil, sqliteError(policyengine.ErrorFailedPrecondition)
		}
	}

	writerConnector, err := newConnector(databaseDSNMode(config, false, create))
	if err != nil {
		return nil, mapError(ctx, err)
	}
	writer := sql.OpenDB(writerConnector)
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	database.writer = writer

	if err := writer.PingContext(ctx); err != nil {
		return nil, mapError(ctx, err)
	}
	if err := verifyWriterConnection(ctx, writer, config); err != nil {
		return nil, err
	}

	readerConnector, err := newConnector(databaseDSNMode(config, true, create))
	if err != nil {
		return nil, mapError(ctx, err)
	}
	readers := sql.OpenDB(readerConnector)
	readers.SetMaxOpenConns(config.MaxReaders)
	readers.SetMaxIdleConns(config.MaxReaders)
	database.readers = readers
	if err := verifyReaderConnections(ctx, readers, config); err != nil {
		return nil, err
	}
	if err := database.startWriter(ctx); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *database) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		if d.writerDone != nil {
			<-d.writerDone
		}
		d.closeErr = d.closeResources()
	})
	return d.closeErr
}

func (d *database) closeResources() error {
	var failed bool
	if d.readers != nil {
		if err := d.readers.Close(); err != nil {
			failed = true
		}
		d.readers = nil
	}
	if d.writer != nil {
		if err := d.writer.Close(); err != nil {
			failed = true
		}
		d.writer = nil
	}
	if d.lock != nil {
		if err := d.lock.Unlock(); err != nil {
			failed = true
		}
		if err := d.lock.Close(); err != nil {
			failed = true
		}
		d.lock = nil
	}
	if failed {
		return sqliteError(policyengine.ErrorInternal)
	}
	return nil
}

func ensureOwnerOnlyDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func databaseDSN(config Config, reader bool) string {
	return databaseDSNMode(config, reader, true)
}

func databaseDSNMode(config Config, reader, create bool) string {
	uri := &url.URL{Scheme: "file", Path: config.Path}
	query := url.Values{}
	query.Set("_busy_timeout", strconv.FormatInt(config.BusyTimeout.Milliseconds(), 10))
	query.Set("_foreign_keys", "on")
	query.Set("_synchronous", string(config.Synchronous))
	if reader {
		query.Set("_query_only", "1")
		if !create {
			query.Set("mode", "ro")
		}
	} else {
		query.Set("_journal_mode", "WAL")
		if !create {
			query.Set("mode", "rw")
		}
	}
	uri.RawQuery = query.Encode()
	return uri.String()
}

func verifyWriterConnection(ctx context.Context, database *sql.DB, config Config) error {
	conn, err := database.Conn(ctx)
	if err != nil {
		return mapError(ctx, err)
	}
	defer conn.Close()
	return verifyConnectionPragmas(ctx, conn, config, false)
}

func verifyReaderConnections(ctx context.Context, database *sql.DB, config Config) error {
	connections := make([]*sql.Conn, 0, config.MaxReaders)
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()

	for range config.MaxReaders {
		conn, err := database.Conn(ctx)
		if err != nil {
			return mapError(ctx, err)
		}
		connections = append(connections, conn)
		if err := verifyConnectionPragmas(ctx, conn, config, true); err != nil {
			return err
		}
	}
	return nil
}

func verifyConnectionPragmas(ctx context.Context, conn *sql.Conn, config Config, reader bool) error {
	for _, expected := range []struct {
		name  string
		value int64
	}{
		{name: "foreign_keys", value: 1},
		{name: "synchronous", value: 2},
		{name: "busy_timeout", value: config.BusyTimeout.Milliseconds()},
		{name: "query_only", value: boolToInt64(reader)},
	} {
		var got int64
		if err := conn.QueryRowContext(ctx, "PRAGMA "+expected.name).Scan(&got); err != nil {
			return mapError(ctx, err)
		}
		if got != expected.value {
			return sqliteError(policyengine.ErrorInternal)
		}
	}

	var journalMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return mapError(ctx, err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return sqliteError(policyengine.ErrorInternal)
	}
	return nil
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
