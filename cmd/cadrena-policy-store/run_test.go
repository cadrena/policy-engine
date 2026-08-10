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

	_ "modernc.org/sqlite"
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
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatalf("begin competing exclusive transaction: %v", err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")

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

func openCLIPlainSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw SQLite database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
