package sqlite

import (
	"context"
	"database/sql"
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

func openDatabase(ctx context.Context, config Config) (_ *database, err error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return nil, mapError(ctx, err)
	}
	if err := lock.LockShared(ctx); err != nil {
		_ = lock.Close()
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
	if err := ensureOwnerOnlyDatabaseFile(config.Path); err != nil {
		return nil, mapError(ctx, err)
	}

	writerConnector, err := moderncsqlite.NewConnector(databaseDSN(config, false))
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

	readerConnector, err := moderncsqlite.NewConnector(databaseDSN(config, true))
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
	uri := &url.URL{Scheme: "file", Path: config.Path}
	query := url.Values{}
	query.Set("_busy_timeout", strconv.FormatInt(config.BusyTimeout.Milliseconds(), 10))
	query.Set("_foreign_keys", "on")
	query.Set("_synchronous", string(config.Synchronous))
	if reader {
		query.Set("_query_only", "1")
	} else {
		query.Set("_journal_mode", "WAL")
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
