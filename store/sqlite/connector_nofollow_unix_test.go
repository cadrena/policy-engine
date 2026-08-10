//go:build darwin || linux

package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
)

// These production-path regressions retain a real SQLite read lock on the
// symlink target and close sibling connections so the Unix VFS has target
// descriptors in its pUnused list. That is the case where a final-component
// O_NOFOLLOW alone is insufficient: unixOpen consults pUnused after a
// follow-link stat before it would call open(2). The connector must therefore
// reject the symlink during SQLite pathname resolution itself.
func TestRuntimeConnectorsRejectDatabaseSymlinkSwapAfterValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match func(string) bool
		dsn   func(Config) string
	}{
		{
			name: "writer",
			match: func(dsn string) bool {
				return !strings.Contains(dsn, "_query_only=1")
			},
			dsn: func(config Config) string {
				return databaseDSNMode(config, false, true)
			},
		},
		{
			name: "reader",
			match: func(dsn string) bool {
				return strings.Contains(dsn, "_query_only=1")
			},
			dsn: func(config Config) string {
				return databaseDSNMode(config, true, true)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
			canaryPath := filepath.Join(t.TempDir(), "canary.db")
			makeSQLiteConnectorCanary(t, canaryPath)
			holdReusableSQLiteTargetDescriptors(t, configAtPath(config, canaryPath), tc.dsn)
			canary := snapshotSQLiteConnectorCanary(t, canaryPath)
			swap := newPostValidationPathSwap(config.Path, canaryPath, tc.match)

			database, err := openDatabaseWithConnectorFactory(context.Background(), config, swap.connector)
			if database != nil {
				_ = database.Close()
			}
			swap.assertRejected(t)
			canary.assertUnchanged(t, canaryPath)
			if err == nil {
				t.Fatal("runtime open succeeded after its database path became a symlink")
			}
		})
	}
}

func TestMigrationConnectorsRejectDatabaseSymlinkSwapAfterValidation(t *testing.T) {
	t.Run("writer", func(t *testing.T) {
		config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
		canaryPath := filepath.Join(t.TempDir(), "canary.db")
		makeSQLiteConnectorCanary(t, canaryPath)
		holdReusableSQLiteTargetDescriptors(t, configAtPath(config, canaryPath), func(config Config) string {
			return databaseDSNMode(config, false, true)
		})
		canary := snapshotSQLiteConnectorCanary(t, canaryPath)
		swap := newPostValidationPathSwap(config.Path, canaryPath, func(dsn string) bool {
			return !strings.Contains(dsn, "_query_only=1")
		})

		_, err := applyMigrationsWithConnectorFactory(context.Background(), config, embeddedMigrationsForTest(t), swap.connector)
		swap.assertRejected(t)
		canary.assertUnchanged(t, canaryPath)
		if err == nil {
			t.Fatal("migration writer succeeded after its database path became a symlink")
		}
	})

	t.Run("reader", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		canaryPath := filepath.Join(t.TempDir(), "canary.db")
		makeSQLiteConnectorCanary(t, canaryPath)
		holdReusableSQLiteTargetDescriptors(t, configAtPath(config, canaryPath), func(config Config) string {
			return databaseDSNMode(config, true, false)
		})
		canary := snapshotSQLiteConnectorCanary(t, canaryPath)
		swap := newPostValidationPathSwap(config.Path, canaryPath, func(dsn string) bool {
			return strings.Contains(dsn, "_query_only=1")
		})

		_, err := planMigrationsWithConnectorFactory(context.Background(), config, swap.connector)
		swap.assertRejected(t)
		canary.assertUnchanged(t, canaryPath)
		if err == nil {
			t.Fatal("migration reader succeeded after its database path became a symlink")
		}
	})
}

func TestFullIntegrityConnectorRejectsDatabaseSymlinkSwapAfterValidation(t *testing.T) {
	config := migratedIntegrityConfig(t)
	canaryPath := filepath.Join(t.TempDir(), "canary.db")
	makeSQLiteConnectorCanary(t, canaryPath)
	holdReusableSQLiteTargetDescriptors(t, configAtPath(config, canaryPath), integrityDSN)
	canary := snapshotSQLiteConnectorCanary(t, canaryPath)
	swap := newPostValidationPathSwap(config.Path, canaryPath, func(dsn string) bool {
		return !strings.Contains(dsn, "_query_only=1")
	})

	err := fullIntegrityCheckWithConnectorFactory(context.Background(), config, swap.connector)
	swap.assertRejected(t)
	canary.assertUnchanged(t, canaryPath)
	if err == nil {
		t.Fatal("full integrity check succeeded after its database path became a symlink")
	}
}

type postValidationPathSwap struct {
	path   string
	target string
	match  func(string) bool

	once       sync.Once
	mu         sync.Mutex
	err        error
	did        bool
	connectErr error
	connected  bool
}

func newPostValidationPathSwap(path, target string, match func(string) bool) *postValidationPathSwap {
	return &postValidationPathSwap{path: path, target: target, match: match}
}

func (s *postValidationPathSwap) connector(dsn string) (driver.Connector, error) {
	base, err := moderncsqlite.NewConnector(dsn)
	if err != nil || !s.match(dsn) {
		return base, err
	}
	return swapBeforeConnectConnector{Connector: base, swap: s.swap, record: s.recordConnect}, nil
}

func (s *postValidationPathSwap) swap() error {
	s.once.Do(func() {
		err := os.Remove(s.path)
		if err == nil {
			err = os.Symlink(s.target, s.path)
		}
		s.mu.Lock()
		s.err = err
		s.did = true
		s.mu.Unlock()
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *postValidationPathSwap) recordConnect(err error) {
	s.mu.Lock()
	s.connectErr = err
	s.connected = err == nil
	s.mu.Unlock()
}

func (s *postValidationPathSwap) assertRejected(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	did, swapErr, connected, connectErr := s.did, s.err, s.connected, s.connectErr
	s.mu.Unlock()
	if !did || swapErr != nil {
		t.Fatalf("post-validation path swap: triggered=%t error=%v", did, swapErr)
	}
	if connected || connectErr == nil {
		t.Fatalf("connector accepted a symlink after the post-validation swap: connected=%t error=%v", connected, connectErr)
	}
}

type swapBeforeConnectConnector struct {
	driver.Connector
	swap   func() error
	record func(error)
}

func (c swapBeforeConnectConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := c.swap(); err != nil {
		c.record(err)
		return nil, err
	}
	conn, err := c.Connector.Connect(ctx)
	c.record(err)
	return conn, err
}

// holdReusableSQLiteTargetDescriptors creates the SQLite state that makes
// unixOpen's pUnused fast path observable. Holding a real target read
// transaction keeps its inode lock alive; closing sibling connections then
// leaves their descriptors reusable instead of closing them. The exact DSN is
// used for every connection so the VFS read/write flags match the production
// connector under test.
func holdReusableSQLiteTargetDescriptors(t *testing.T, config Config, makeDSN func(Config) string) {
	t.Helper()
	canonicalConfig, err := canonicalizeDatabaseConfig(config)
	if err != nil {
		t.Fatalf("canonicalize target holder database path: %v", err)
	}
	dsn := makeDSN(canonicalConfig)
	ctx := context.Background()
	connector, err := moderncsqlite.NewConnector(dsn)
	if err != nil {
		t.Fatalf("new target holder connector: %v", err)
	}
	holder := sql.OpenDB(connector)
	holder.SetMaxOpenConns(1)
	holder.SetMaxIdleConns(1)
	conn, err := holder.Conn(ctx)
	if err != nil {
		_ = holder.Close()
		t.Fatalf("open target holder connection: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		_ = conn.Close()
		_ = holder.Close()
	})
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatalf("begin target read transaction: %v", err)
	}
	var marker string
	if err := conn.QueryRowContext(ctx, "SELECT value FROM connector_swap_canary LIMIT 1").Scan(&marker); err != nil {
		t.Fatalf("read target marker while holding transaction: %v", err)
	}
	if marker != "unchanged" {
		t.Fatalf("target marker = %q, want unchanged", marker)
	}
	for range 8 {
		spareConnector, err := moderncsqlite.NewConnector(dsn)
		if err != nil {
			t.Fatalf("new target spare connector: %v", err)
		}
		spare := sql.OpenDB(spareConnector)
		spare.SetMaxOpenConns(1)
		spare.SetMaxIdleConns(1)
		if err := spare.PingContext(ctx); err != nil {
			_ = spare.Close()
			t.Fatalf("open target spare connection: %v", err)
		}
		if err := spare.Close(); err != nil {
			t.Fatalf("close target spare connection: %v", err)
		}
	}
}

func configAtPath(config Config, path string) Config {
	config.Path = path
	return config
}

type sqliteConnectorCanarySnapshot struct {
	primary   []byte
	mode      os.FileMode
	schema    string
	artifacts [3]sqliteConnectorCanaryArtifact
}

type sqliteConnectorCanaryArtifact struct {
	exists bool
	bytes  []byte
	mode   os.FileMode
}

func makeSQLiteConnectorCanary(t *testing.T, path string) {
	t.Helper()
	if _, err := ApplyMigrations(context.Background(), validConfig(path)); err != nil {
		t.Fatalf("create canary migrations: %v", err)
	}
	database := openRawSQLite(t, path)
	if _, err := database.ExecContext(context.Background(), "CREATE TABLE connector_swap_canary(value TEXT NOT NULL)"); err != nil {
		t.Fatalf("create canary marker: %v", err)
	}
	if _, err := database.ExecContext(context.Background(), "INSERT INTO connector_swap_canary(value) VALUES ('unchanged')"); err != nil {
		t.Fatalf("insert canary marker: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close canary database: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod canary: %v", err)
	}
}

func snapshotSQLiteConnectorCanary(t *testing.T, path string) sqliteConnectorCanarySnapshot {
	t.Helper()
	primary, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canary: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat canary: %v", err)
	}
	return sqliteConnectorCanarySnapshot{
		primary: primary,
		mode:    info.Mode().Perm(),
		schema:  sqliteConnectorCanarySchema(t, path),
		artifacts: [3]sqliteConnectorCanaryArtifact{
			snapshotSQLiteConnectorCanaryArtifact(t, path+"-wal"),
			snapshotSQLiteConnectorCanaryArtifact(t, path+"-shm"),
			snapshotSQLiteConnectorCanaryArtifact(t, path+"-journal"),
		},
	}
}

func (s sqliteConnectorCanarySnapshot) assertUnchanged(t *testing.T, path string) {
	t.Helper()
	after := snapshotSQLiteConnectorCanary(t, path)
	if !bytes.Equal(s.primary, after.primary) {
		t.Fatal("canary primary database bytes changed")
	}
	if s.mode != after.mode {
		t.Fatalf("canary mode = %#o, want %#o", after.mode, s.mode)
	}
	if s.schema != after.schema {
		t.Fatalf("canary schema changed: got %q, want %q", after.schema, s.schema)
	}
	for index, before := range s.artifacts {
		got := after.artifacts[index]
		if before.exists != got.exists || before.mode != got.mode || !bytes.Equal(before.bytes, got.bytes) {
			t.Fatalf("canary sidecar %d changed: got=%#v want=%#v", index, got, before)
		}
	}
}

func snapshotSQLiteConnectorCanaryArtifact(t *testing.T, path string) sqliteConnectorCanaryArtifact {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sqliteConnectorCanaryArtifact{}
	}
	if err != nil {
		t.Fatalf("read canary sidecar %q: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat canary sidecar %q: %v", path, err)
	}
	return sqliteConnectorCanaryArtifact{exists: true, bytes: bytes, mode: info.Mode().Perm()}
}

func sqliteConnectorCanarySchema(t *testing.T, path string) string {
	t.Helper()
	config, err := canonicalizeDatabaseConfig(validConfig(path))
	if err != nil {
		t.Fatalf("canonicalize canary schema path: %v", err)
	}
	connector, err := moderncsqlite.NewConnector(databaseDSNMode(config, true, false))
	if err != nil {
		t.Fatalf("open read-only canary connector: %v", err)
	}
	database := sql.OpenDB(connector)
	defer func() { _ = database.Close() }()
	rows, err := database.QueryContext(context.Background(), "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
	if err != nil {
		t.Fatalf("read canary schema: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var entries []string
	for rows.Next() {
		var objectType, name, table, definition string
		if err := rows.Scan(&objectType, &name, &table, &definition); err != nil {
			t.Fatalf("scan canary schema: %v", err)
		}
		entries = append(entries, strings.Join([]string{objectType, name, table, definition}, "\x00"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate canary schema: %v", err)
	}
	return strings.Join(entries, "\n")
}
