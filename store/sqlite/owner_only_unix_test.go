//go:build darwin || linux

package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"golang.org/x/sys/unix"
)

func TestOwnerOnlySetupRejectsSymlinkAndNonRegularTargets(t *testing.T) {
	// This catches owner-only setup that follows a symlink or opens a
	// non-regular object. Every target is a disposable fixture, but it must
	// remain untouched by the rejected database or lock setup.
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, path string) error
		make func(t *testing.T, path string) func(t *testing.T)
	}{
		{
			name: "lock symlink",
			run: func(t *testing.T, path string) error {
				lock, err := newAdvisoryLock(path)
				if lock != nil {
					_ = lock.Close()
				}
				return err
			},
			make: makeOwnerOnlyLockSymlinkFixture,
		},
		{
			name: "database symlink",
			run: func(t *testing.T, path string) error {
				_, err := ApplyMigrations(context.Background(), validConfig(path))
				return err
			},
			make: makeOwnerOnlyDatabaseSymlinkFixture,
		},
		{
			name: "lock directory",
			run: func(t *testing.T, path string) error {
				lock, err := newAdvisoryLock(path)
				if lock != nil {
					_ = lock.Close()
				}
				return err
			},
			make: makeOwnerOnlyLockDirectoryFixture,
		},
		{
			name: "database directory",
			run: func(t *testing.T, path string) error {
				_, err := ApplyMigrations(context.Background(), validConfig(path))
				return err
			},
			make: makeOwnerOnlyDatabaseDirectoryFixture,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.db")
			assertUntouched := tc.make(t, path)
			err := tc.run(t, path)
			assertUntouched(t)
			if got := categoryOf(err); got != policyengine.ErrorFailedPrecondition {
				t.Fatalf("owner-only setup category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
			}
		})
	}
}

func TestOwnerOnlyFileOpenerRejectsFIFO(t *testing.T) {
	// This catches an opener that merely uses O_NOFOLLOW: FIFOs are not
	// symlinks, so the descriptor itself must be fstat-checked as a regular
	// file before the owner-only setup can continue.
	path := filepath.Join(t.TempDir(), "policy.db")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo() error = %v", err)
	}
	file, err := openOwnerOnlyRegularFile(path)
	if file != nil {
		_ = file.Close()
	}
	if got := categoryOf(err); got != policyengine.ErrorFailedPrecondition {
		t.Fatalf("openOwnerOnlyRegularFile(FIFO) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO target changed: info=%v error=%v", info, err)
	}
}

func makeOwnerOnlyLockSymlinkFixture(t *testing.T, path string) func(t *testing.T) {
	t.Helper()
	target := filepath.Join(filepath.Dir(path), "lock-canary")
	const contents = "LOCK_CANARY"
	if err := os.WriteFile(target, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockFilePath(path)); err != nil {
		t.Fatal(err)
	}
	return func(t *testing.T) {
		t.Helper()
		assertOwnerOnlyCanaryUntouched(t, target, contents, 0o644)
	}
}

func makeOwnerOnlyDatabaseSymlinkFixture(t *testing.T, path string) func(t *testing.T) {
	t.Helper()
	target := filepath.Join(filepath.Dir(path), "database-canary")
	database := openRawSQLite(t, target)
	mustExecMigrationTest(t, database, "CREATE TABLE target_canary(value TEXT NOT NULL)")
	mustExecMigrationTest(t, database, "INSERT INTO target_canary(value) VALUES ('DATABASE_CANARY')")
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	return func(t *testing.T) {
		t.Helper()
		assertOwnerOnlyCanaryUntouched(t, target, "", 0o644)
		if sqliteTableExists(t, target, schemaMigrationsTable) {
			t.Fatalf("symlink target gained %s", schemaMigrationsTable)
		}
	}
}

func makeOwnerOnlyLockDirectoryFixture(t *testing.T, path string) func(t *testing.T) {
	t.Helper()
	if err := os.Mkdir(lockFilePath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	return func(t *testing.T) {
		t.Helper()
		info, err := os.Lstat(lockFilePath(path))
		if err != nil || !info.IsDir() {
			t.Fatalf("lock non-regular target changed: info=%v error=%v", info, err)
		}
	}
}

func makeOwnerOnlyDatabaseDirectoryFixture(t *testing.T, path string) func(t *testing.T) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func(t *testing.T) {
		t.Helper()
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			t.Fatalf("database non-regular target changed: info=%v error=%v", info, err)
		}
	}
}

func assertOwnerOnlyCanaryUntouched(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	if want != "" {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("canary contents changed: got=%q error=%v", got, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("canary mode changed: mode=%v error=%v, want %#o", info.Mode(), err, mode)
	}
}

func sqliteTableExists(t *testing.T, path, table string) bool {
	t.Helper()
	database := openRawSQLite(t, path)
	defer func() { _ = database.Close() }()
	var count int
	err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("inspect canary target: %v", err)
	}
	return count != 0
}
