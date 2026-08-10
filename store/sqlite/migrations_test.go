package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	policyengine "github.com/cadrena/policy-engine"
	_ "modernc.org/sqlite"
)

func TestEmbeddedMigrationsAreOrderedAndChecksumExactBytes(t *testing.T) {
	// This catches a manifest loader that reorders migrations or normalizes SQL
	// before hashing, either of which would break the durable ledger contract.
	migrations := embeddedMigrationsForTest(t)
	if len(migrations) != 1 || migrations[0].Version != 1 || migrations[0].Name != "initial" {
		t.Fatalf("migrations = %#v", migrations)
	}
	want := sha256.Sum256(migrations[0].SQL)
	if migrations[0].SHA256 != want {
		t.Fatalf("checksum = %x, want %x", migrations[0].SHA256, want)
	}
}

func TestMigrationManifestRejectsUnsafeOrIncompleteFiles(t *testing.T) {
	// This catches a parser that accepts an ambiguous order, duplicate version,
	// hole, empty migration, or filename outside the fixed migration grammar.
	for _, tc := range []struct {
		name string
		fs   fstest.MapFS
	}{
		{
			name: "non-zero-padded version",
			fs: fstest.MapFS{
				"migrations/1_initial.sql": {Data: []byte("SELECT 1;")},
			},
		},
		{
			name: "duplicate version",
			fs: fstest.MapFS{
				"migrations/0001_first.sql":  {Data: []byte("SELECT 1;")},
				"migrations/0001_second.sql": {Data: []byte("SELECT 2;")},
			},
		},
		{
			name: "version gap",
			fs: fstest.MapFS{
				"migrations/0001_first.sql": {Data: []byte("SELECT 1;")},
				"migrations/0003_third.sql": {Data: []byte("SELECT 3;")},
			},
		},
		{
			name: "empty SQL",
			fs: fstest.MapFS{
				"migrations/0001_initial.sql": {Data: nil},
			},
		},
		{
			name: "nonmatching filename",
			fs: fstest.MapFS{
				"migrations/0001-Initial.sql": {Data: []byte("SELECT 1;")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMigrationFS(tc.fs); categoryOf(err) != policyengine.ErrorIntegrity {
				t.Fatalf("parseMigrationFS() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestPlanMigrationsMissingDatabaseReportsInitialPendingWithoutArtifacts(t *testing.T) {
	// This catches planning through the runtime database opener, which would
	// create a database, WAL, SHM, or advisory lock while merely inspecting.
	path := filepath.Join(t.TempDir(), "policy.db")
	plan, err := PlanMigrations(context.Background(), validConfig(path))
	if err != nil {
		t.Fatalf("PlanMigrations() error = %v", err)
	}
	if plan.Current != 0 {
		t.Fatalf("plan current = %d, want 0", plan.Current)
	}
	if len(plan.Pending) != 1 || plan.Pending[0].Version != 1 || plan.Pending[0].Name != "initial" {
		t.Fatalf("plan pending = %#v", plan.Pending)
	}
	assertNoMigrationArtifacts(t, path)
}

func TestApplyMigrationsCreatesSchemaAndExactLedgerRecord(t *testing.T) {
	// This catches migration application that skips the bootstrap ledger,
	// records a normalized/wrong digest, or uses a non-UTC application time.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	result, err := ApplyMigrations(context.Background(), config)
	if err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if result.Previous != 0 || result.Current != 1 || len(result.Applied) != 1 || result.Applied[0].Version != 1 {
		t.Fatalf("migration result = %#v", result)
	}

	db := openRawSQLite(t, path)
	var checksum, appliedAt string
	if err := db.QueryRowContext(context.Background(), "SELECT checksum, applied_at FROM schema_migrations WHERE version = 1").Scan(&checksum, &appliedAt); err != nil {
		t.Fatalf("read ledger record: %v", err)
	}
	migrations := embeddedMigrationsForTest(t)
	wantChecksum := hex.EncodeToString(migrations[0].SHA256[:])
	if checksum != wantChecksum {
		t.Fatalf("ledger checksum = %q, want %q", checksum, wantChecksum)
	}
	if appliedAt != "1970-01-01T00:00:00Z" {
		t.Fatalf("ledger applied_at = %q, want UTC RFC3339Nano fixed-clock value", appliedAt)
	}
}

func TestInitialMigrationCreatesExactlyOnePersistentCursorKey(t *testing.T) {
	// This catches migration code that defers key generation to runtime opening,
	// creates an invalid key, or rotates the key on an idempotent migration run.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("first ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)
	var first []byte
	if err := db.QueryRowContext(context.Background(), "SELECT value FROM cadrena_meta WHERE key = 'cursor_hmac_key'").Scan(&first); err != nil {
		t.Fatalf("read initial cursor key: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("cursor key length = %d, want 32", len(first))
	}
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("second ApplyMigrations() error = %v", err)
	}
	var second []byte
	if err := db.QueryRowContext(context.Background(), "SELECT value FROM cadrena_meta WHERE key = 'cursor_hmac_key'").Scan(&second); err != nil {
		t.Fatalf("read persisted cursor key: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("idempotent migration rotated persistent cursor key")
	}
}

func TestApplyMigrationsSecondRunIsNoOpAtCurrentVersion(t *testing.T) {
	// This catches a migration runner that reapplies an already ledgered
	// version instead of using the verified prefix as its durable cursor.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("first ApplyMigrations() error = %v", err)
	}
	result, err := ApplyMigrations(context.Background(), config)
	if err != nil {
		t.Fatalf("second ApplyMigrations() error = %v", err)
	}
	if result.Previous != 1 || result.Current != 1 || len(result.Applied) != 0 {
		t.Fatalf("second migration result = %#v", result)
	}
}

func TestValidateSchemaRejectsAnEmptyUnmigratedDatabase(t *testing.T) {
	// This catches runtime validation that treats a syntactically valid empty
	// SQLite file as a usable policy store or migrates it implicitly.
	path := filepath.Join(t.TempDir(), "policy.db")
	db := openRawSQLite(t, path)
	if err := db.Close(); err != nil {
		t.Fatalf("close empty database: %v", err)
	}

	err := ValidateSchema(context.Background(), validConfig(path))
	if categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorFailedPrecondition)
	}
}

func TestMigrationAPIsRejectChangedChecksum(t *testing.T) {
	// This catches accepting a ledger row whose version/name look valid but
	// whose exact SQL digest no longer proves it was the embedded migration.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)
	mustExecMigrationTest(t, db, "UPDATE schema_migrations SET checksum = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version = 1")
	if err := db.Close(); err != nil {
		t.Fatalf("close corrupt ledger database: %v", err)
	}

	if _, err := PlanMigrations(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("PlanMigrations() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
	if _, err := ApplyMigrations(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("ApplyMigrations() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
	if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
}

func TestMigrationAPIsRejectUnknownNewerVersion(t *testing.T) {
	// This catches tolerance of a database that advertises a migration newer
	// than this binary, which could otherwise run against an unknown schema.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	db := openRawSQLite(t, path)
	mustExecMigrationTest(t, db, "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (2, 'future', '0000000000000000000000000000000000000000000000000000000000000000', '1970-01-01T00:00:00Z')")
	if err := db.Close(); err != nil {
		t.Fatalf("close future ledger database: %v", err)
	}

	if _, err := PlanMigrations(context.Background(), config); categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("PlanMigrations() category = %v, want %v", categoryOf(err), policyengine.ErrorFailedPrecondition)
	}
	if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorFailedPrecondition)
	}
}

func TestMigrationAPIsRejectLedgerGapDuplicateAndMalformedRows(t *testing.T) {
	// This catches a ledger reader that merely takes MAX(version), permitting
	// holes, duplicate records, or malformed durable migration evidence.
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, db *sql.DB)
	}{
		{
			name: "gap",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "DELETE FROM schema_migrations WHERE version = 1")
				mustExecMigrationTest(t, db, "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (2, 'initial', '0000000000000000000000000000000000000000000000000000000000000000', '1970-01-01T00:00:00Z')")
			},
		},
		{
			name: "duplicate",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "DROP TABLE schema_migrations")
				mustExecMigrationTest(t, db, "CREATE TABLE schema_migrations (version INTEGER, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)")
				mustExecMigrationTest(t, db, "INSERT INTO schema_migrations VALUES (1, 'initial', '0000000000000000000000000000000000000000000000000000000000000000', '1970-01-01T00:00:00Z')")
				mustExecMigrationTest(t, db, "INSERT INTO schema_migrations VALUES (1, 'initial', '0000000000000000000000000000000000000000000000000000000000000000', '1970-01-01T00:00:00Z')")
			},
		},
		{
			name: "malformed row",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE schema_migrations SET applied_at = 'not-a-timestamp' WHERE version = 1")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.db")
			config := validConfig(path)
			if _, err := ApplyMigrations(context.Background(), config); err != nil {
				t.Fatalf("ApplyMigrations() error = %v", err)
			}
			db := openRawSQLite(t, path)
			tc.mutate(t, db)
			if err := db.Close(); err != nil {
				t.Fatalf("close corrupt ledger database: %v", err)
			}

			if err := ValidateSchema(context.Background(), config); categoryOf(err) != policyengine.ErrorIntegrity {
				t.Fatalf("ValidateSchema() category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestApplyMigrationsRollsBackSchemaAndLedgerAfterMigrationSQLFailure(t *testing.T) {
	// This catches per-statement commits: a failed migration must leave neither
	// its application table nor its bootstrap/version ledger durable.
	path := filepath.Join(t.TempDir(), "policy.db")
	config := validConfig(path)
	sqlBytes := []byte("CREATE TABLE rollback_probe (value TEXT NOT NULL); INSERT INTO rollback_probe(value) VALUES ('x'); THIS IS INVALID SQL;")
	manifest := []migration{migrationForTest(1, "rollback_probe", sqlBytes)}
	if _, err := applyMigrationsWith(context.Background(), config, manifest); categoryOf(err) != policyengine.ErrorInternal {
		t.Fatalf("applyMigrationsWith() category = %v, want %v", categoryOf(err), policyengine.ErrorInternal)
	}

	db := openRawSQLite(t, path)
	for _, name := range []string{"rollback_probe", "schema_migrations"} {
		var count int
		if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&count); err != nil {
			t.Fatalf("check rolled back %s table: %v", name, err)
		}
		if count != 0 {
			t.Fatalf("table %q persisted after failed migration", name)
		}
	}
}

func embeddedMigrationsForTest(t *testing.T) []migration {
	t.Helper()
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations() error = %v", err)
	}
	return migrations
}

func migrationForTest(version uint64, name string, sqlBytes []byte) migration {
	return migration{
		MigrationInfo: MigrationInfo{
			Version: version,
			Name:    name,
			SHA256:  sha256.Sum256(sqlBytes),
		},
		SQL: sqlBytes,
	}
}

func assertNoMigrationArtifacts(t *testing.T, path string) {
	t.Helper()
	for _, artifact := range []string{path, path + "-wal", path + "-shm", path + ".lock"} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("planning created artifact %q: stat error = %v", artifact, err)
		}
	}
}

func openRawSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw SQLite database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustExecMigrationTest(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), statement); err != nil {
		t.Fatalf("execute %q: %v", statement, err)
	}
}
