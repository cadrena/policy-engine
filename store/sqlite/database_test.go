package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestConnectionPoolsApplyRequiredPragmasToEveryPhysicalConnection(t *testing.T) {
	// This catches a connection setup that configures only the first connection,
	// shares a writer/read pool, or lets readers change WAL/query-only state.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.BusyTimeout = 123 * time.Millisecond
	config.MaxReaders = 3
	database, err := openDatabase(context.Background(), config)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	defer database.Close()
	info, err := os.Stat(config.Path)
	if err != nil {
		t.Fatalf("Stat(database file) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database file permissions = %#o, want %#o", got, os.FileMode(0o600))
	}

	if got := database.writer.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("writer MaxOpenConnections = %d, want 1", got)
	}
	if got := database.readers.Stats().MaxOpenConnections; got != config.MaxReaders {
		t.Fatalf("reader MaxOpenConnections = %d, want %d", got, config.MaxReaders)
	}

	var writerPragmaErr error
	err = database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		writerPragmaErr = connectionPragmaError(ctx, conn, config.BusyTimeout.Milliseconds(), 0)
		return writerPragmaErr
	})
	if writerPragmaErr != nil {
		t.Fatal(writerPragmaErr)
	}
	if err != nil {
		t.Fatalf("writer pragma check error = %v", err)
	}

	readers := make([]*sql.Conn, 0, config.MaxReaders)
	for range config.MaxReaders {
		reader, err := database.readers.Conn(context.Background())
		if err != nil {
			t.Fatalf("reader.Conn() error = %v", err)
		}
		readers = append(readers, reader)
	}
	for _, reader := range readers {
		defer reader.Close()
		assertConnectionPragmas(t, reader, config.BusyTimeout.Milliseconds(), 1)
	}
}

func TestConnectionReaderAdmissionStaysBoundedAndCloseUnblocksWaiters(t *testing.T) {
	// This catches an admission semaphore that over-releases, admits a caller
	// above MaxReaders, or leaves an already-blocked caller stranded on Close.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.MaxReaders = 1
	database, err := openDatabase(context.Background(), config)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}

	release, err := database.acquireReader(context.Background())
	if err != nil {
		t.Fatalf("first acquireReader() error = %v", err)
	}
	release()
	release()

	secondRelease, err := database.acquireReader(context.Background())
	if err != nil {
		t.Fatalf("second acquireReader() error = %v", err)
	}
	defer secondRelease()

	waiting := make(chan error, 1)
	go func() {
		release, err := database.acquireReader(context.Background())
		if release != nil {
			release()
		}
		waiting <- err
	}()
	select {
	case err := <-waiting:
		t.Fatalf("acquireReader() completed while MaxReaders held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-waiting; categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("blocked acquireReader() category = %v, want %v", categoryOf(err), policyengine.ErrorUnavailable)
	}
}

func TestConnectionPartialFailureReleasesSidecarLock(t *testing.T) {
	// This catches partial-open cleanup that leaves the shared runtime lock held
	// after SQLite rejects a corrupt database before reader setup completes.
	path := filepath.Join(t.TempDir(), "policy.db")
	if err := os.WriteFile(path, []byte("not a SQLite database"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := openDatabase(context.Background(), validConfig(path))
	if categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("openDatabase() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
	if output, err := runLockHelper(path, "exclusive"); err != nil {
		t.Fatalf("exclusive lock after failed open error = %v, output = %q", err, output)
	}
}

func assertConnectionPragmas(t *testing.T, conn *sql.Conn, busyTimeoutMS int64, queryOnly int) {
	t.Helper()
	if err := connectionPragmaError(context.Background(), conn, busyTimeoutMS, queryOnly); err != nil {
		t.Fatal(err)
	}
}

func connectionPragmaError(ctx context.Context, conn *sql.Conn, busyTimeoutMS int64, queryOnly int) error {
	for _, check := range []struct {
		pragma string
		want   int64
	}{
		{pragma: "foreign_keys", want: 1},
		{pragma: "synchronous", want: 2},
		{pragma: "busy_timeout", want: busyTimeoutMS},
		{pragma: "query_only", want: int64(queryOnly)},
	} {
		var got int64
		if err := conn.QueryRowContext(ctx, "PRAGMA "+check.pragma).Scan(&got); err != nil {
			return fmt.Errorf("PRAGMA %s query error: %w", check.pragma, err)
		}
		if got != check.want {
			return fmt.Errorf("PRAGMA %s = %d, want %d", check.pragma, got, check.want)
		}
	}

	var journalMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("PRAGMA journal_mode query error: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("PRAGMA journal_mode = %q, want %q", journalMode, "wal")
	}
	return nil
}
