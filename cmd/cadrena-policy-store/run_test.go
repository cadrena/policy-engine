package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
	"github.com/cadrena/policy-engine/store/sqlite"
)

func TestRunMigrateThenValidate(t *testing.T) {
	// This catches a CLI that cannot drive the public maintenance lifecycle
	// through its stable argument surface and exit statuses.
	db := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", db, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate exit = %d", code)
	}
	if code := run(context.Background(), []string{"--db", db, "validate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("validate exit = %d", code)
	}
}

func TestRunPlanOnMissingDatabaseCreatesNoArtifacts(t *testing.T) {
	// This catches the plan command routing through a writer/open path that
	// changes persistent state when an operator only requested inspection.
	db := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", db, "plan"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("plan exit = %d", code)
	}
	for _, artifact := range []string{db, db + "-wal", db + "-shm", db + ".lock"} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("plan created artifact %q: stat error = %v", artifact, err)
		}
	}
}

func TestRunAcceptsEqualsFormOfTheSingleDatabaseFlag(t *testing.T) {
	// This catches a flag parser that rejects the standard --db=/absolute/path
	// spelling even though it represents the same one database value.
	db := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db=" + db, "plan"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("equals-form plan exit = %d, want 0", code)
	}
}

func TestRunRejectsInvalidCommandLineAsUsage(t *testing.T) {
	// This catches permissive parsing that accepts a missing, relative, repeated,
	// or unknown command instead of preserving the documented grammar and exit 2.
	absoluteDB := filepath.Join(t.TempDir(), "policy.db")
	for _, args := range [][]string{
		nil,
		{"plan"},
		{"--db", "policy.db", "plan"},
		{"--db", absoluteDB, "unknown"},
		{"--db", absoluteDB, "plan", "extra"},
		{"--db", absoluteDB, "--db", absoluteDB, "plan"},
	} {
		if code := run(context.Background(), args, io.Discard, io.Discard); code != 2 {
			t.Fatalf("run(%q) exit = %d, want 2", args, code)
		}
	}
}

func TestRunReportsMigrationLockConflictAsOperationalFailure(t *testing.T) {
	// This catches a maintenance command that hangs forever or claims success
	// when SQLite cannot obtain the exclusive migration transaction.
	path := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("initial migrate exit = %d", code)
	}
	db := openCLIPlainSQLite(t, path)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("open competing connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatalf("begin competing exclusive transaction: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if code := run(ctx, []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("contended migrate exit = %d, want 1", code)
	}
}

func TestRunReportsChecksumCorruptionAsOperationalFailure(t *testing.T) {
	// This catches a CLI that translates durable checksum corruption into a
	// success or usage error instead of the stable operational failure class.
	path := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate exit = %d", code)
	}
	db := openCLIPlainSQLite(t, path)
	if _, err := db.ExecContext(context.Background(), "UPDATE schema_migrations SET checksum = '0000000000000000000000000000000000000000000000000000000000000000'"); err != nil {
		t.Fatalf("corrupt checksum: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close corrupt database: %v", err)
	}
	if code := run(context.Background(), []string{"--db", path, "validate"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("validate after checksum corruption exit = %d, want 1", code)
	}
}

func TestRunNeverLeaksPathOrSensitiveCanaries(t *testing.T) {
	// This catches direct propagation of filesystem/driver errors into CLI
	// output, which could disclose database locations, values, or SQL details.
	path := filepath.Join(t.TempDir(), "CANARY_POLICY", "CANARY_TUPLE", "CANARY_ATTRIBUTE", "policy.db")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--db", path, "migrate"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid-config migrate exit = %d, want 2", code)
	}
	output := stdout.String() + stderr.String()
	for _, canary := range []string{path, "CANARY_POLICY", "CANARY_TUPLE", "CANARY_ATTRIBUTE", "SELECT sensitive_value FROM tuples"} {
		if strings.Contains(output, canary) {
			t.Fatalf("CLI output leaked %q: %q", canary, output)
		}
	}
}

func TestRunIntegrityAcceptsOnlyClosedMigratedStore(t *testing.T) {
	// This catches an integrity CLI that routes through migration/repair or
	// reports a valid store without running the exclusive offline checker.
	path := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate exit = %d", code)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--db", path, "integrity"}, &stdout, &stderr); code != 0 {
		t.Fatalf("integrity exit = %d, stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); got != "VALID\n" {
		t.Fatalf("integrity stdout = %q, want one safe VALID line", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("integrity stderr = %q, want empty", got)
	}
}

func TestRunBackupExportsFreshRestorableImage(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.db")
	if code := run(context.Background(), []string{"--db", source, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate exit = %d", code)
	}
	destination := filepath.Join(t.TempDir(), "backup.db")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--db", source, "--out", destination, "backup"}, &stdout, &stderr); code != 0 {
		t.Fatalf("backup exit = %d, stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); got != "EXPORTED\n" {
		t.Errorf("backup stdout = %q, want EXPORTED", got)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("backup stderr = %q, want empty", got)
	}
	if code := run(context.Background(), []string{"--db", destination, "integrity"}, io.Discard, io.Discard); code != 0 {
		t.Errorf("restored backup integrity exit = %d, want 0", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--db", source, "--out", destination, "backup"}, &stdout, &stderr); code != 1 {
		t.Errorf("backup overwrite exit = %d, want 1", code)
	}
	if got := stderr.String(); got != "FAILED_PRECONDITION\n" {
		t.Errorf("backup overwrite stderr = %q, want FAILED_PRECONDITION", got)
	}
}

func TestRunPruneEventsUsesOfflineMaintenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.db")
	if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate exit = %d", code)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--db", path, "prune-events"}, &stdout, &stderr); code != 0 {
		t.Fatalf("prune-events exit = %d, stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); got != "PRUNED\n" {
		t.Errorf("prune-events stdout = %q, want PRUNED", got)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("prune-events stderr = %q, want empty", got)
	}
	if code := run(context.Background(), []string{"--db", path, "integrity"}, io.Discard, io.Discard); code != 0 {
		t.Errorf("integrity after prune-events exit = %d, want 0", code)
	}
	config := sqlite.Config{
		Path: path, BusyTimeout: cliBusyTimeout, MaxReaders: 1, Synchronous: sqlite.SynchronousFull,
		ActivationHistoryRetention: cliActivationHistoryRetention, Clock: wallClock{},
	}
	opened, err := sqlite.Open(config)
	if err != nil {
		t.Fatalf("Open(source) error = %v", err)
	}
	defer func() { _ = opened.Close() }()
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--db", path, "prune-events"}, &stdout, &stderr); code != 1 {
		t.Errorf("prune-events with running source exit = %d, want 1", code)
	}
	if got := stdout.String(); got != "" {
		t.Errorf("prune-events with running source stdout = %q, want empty", got)
	}
	if got := stderr.String(); got != "UNAVAILABLE\n" {
		t.Errorf("prune-events with running source stderr = %q, want UNAVAILABLE", got)
	}
}

func TestRunIntegrityUsesSanitizedExitCategoriesAndExclusiveMaintenance(t *testing.T) {
	// This catches category drift, leaked durable data/paths, or an integrity
	// command that can run alongside a runtime or another SQLite maintainer.
	t.Run("invalid configuration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "CANARY_POLICY", "CANARY_TUPLE", "policy.db")
		assertRunIntegrityFailure(context.Background(), t, path, 2, "INVALID_ARGUMENT")
	})

	t.Run("canceled", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.db")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertRunIntegrityFailure(ctx, t, path, 1, "CANCELED")
	})

	t.Run("ledger corruption", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.db")
		if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
			t.Fatalf("migrate exit = %d", code)
		}
		database := openCLIPlainSQLite(t, path)
		if _, err := database.ExecContext(context.Background(), "UPDATE schema_migrations SET checksum = 'CANARY_POLICY'"); err != nil {
			t.Fatalf("corrupt ledger: %v", err)
		}
		if err := database.Close(); err != nil {
			t.Fatalf("close corrupt database: %v", err)
		}
		assertRunIntegrityFailure(context.Background(), t, path, 1, "INTEGRITY_ERROR")
	})

	t.Run("busy SQLite transaction", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.db")
		if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
			t.Fatalf("migrate exit = %d", code)
		}
		database := openCLIPlainSQLite(t, path)
		conn, err := database.Conn(context.Background())
		if err != nil {
			t.Fatalf("database.Conn() error = %v", err)
		}
		defer func() { _ = conn.Close() }()
		defer func() { _ = database.Close() }()
		if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
			t.Fatalf("BEGIN EXCLUSIVE error = %v", err)
		}
		defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
		assertRunIntegrityFailure(context.Background(), t, path, 1, "UNAVAILABLE")
	})

	t.Run("live runtime shared lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.db")
		if code := run(context.Background(), []string{"--db", path, "migrate"}, io.Discard, io.Discard); code != 0 {
			t.Fatalf("migrate exit = %d", code)
		}
		runtime, err := sqlite.Open(sqlite.Config{
			Path: path, BusyTimeout: cliBusyTimeout, MaxReaders: 1, Synchronous: sqlite.SynchronousFull,
			ActivationHistoryRetention: cliActivationHistoryRetention, Clock: wallClock{},
		})
		if err != nil {
			t.Fatalf("sqlite.Open() error = %v", err)
		}
		defer func() { _ = runtime.Close() }()
		assertRunIntegrityFailure(context.Background(), t, path, 1, "UNAVAILABLE")
	})
}

func assertRunIntegrityFailure(ctx context.Context, t *testing.T, path string, wantCode int, wantCategory string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"--db", path, "integrity"}, &stdout, &stderr)
	if code != wantCode {
		t.Fatalf("integrity exit = %d, want %d; stdout=%q stderr=%q", code, wantCode, stdout.String(), stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("integrity failure stdout = %q, want empty", got)
	}
	if got := stderr.String(); got != wantCategory+"\n" {
		t.Fatalf("integrity stderr = %q, want %q", got, wantCategory+"\n")
	}
	for _, canary := range []string{path, "CANARY_POLICY", "CANARY_TUPLE", "CANARY_ATTRIBUTE", "SELECT", "sqlite", "modernc"} {
		if strings.Contains(stdout.String()+stderr.String(), canary) {
			t.Fatalf("integrity output leaked %q: %q", canary, stdout.String()+stderr.String())
		}
	}
}

func openCLIPlainSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatalf("canonicalize raw SQLite parent: %v", err)
	}
	canonicalPath := filepath.Join(canonicalParent, filepath.Base(path))
	db, err := sql.Open(moderncsqlite.DriverName, canonicalPath)
	if err != nil {
		t.Fatalf("open raw SQLite database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
