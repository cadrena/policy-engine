package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "modernc.org/sqlite"
)

const schemaMigrationsTable = "schema_migrations"

const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

var migrationFilename = regexp.MustCompile(`^([0-9]{4})_([a-z0-9_]+)\.sql$`)

//go:embed migrations/*.sql
var embeddedMigrationFiles embed.FS

// MigrationInfo identifies one immutable, checksum-verified schema migration.
type MigrationInfo struct {
	Version uint64
	Name    string
	SHA256  [sha256.Size]byte
}

// MigrationPlan reports the verified applied prefix and the pending embedded
// migrations. Its Pending slice is independently allocated for each call.
type MigrationPlan struct {
	Current uint64
	Pending []MigrationInfo
}

// MigrationResult reports the verified previous and current versions and the
// migrations durably applied by one invocation. Its Applied slice is
// independently allocated for each call.
type MigrationResult struct {
	Previous uint64
	Current  uint64
	Applied  []MigrationInfo
}

type migration struct {
	MigrationInfo
	SQL []byte
}

type ledgerState struct {
	exists  bool
	current uint64
}

// PlanMigrations verifies the durable migration ledger and reports the
// embedded migrations not yet applied. It does not create a missing database.
func PlanMigrations(ctx context.Context, config Config) (MigrationPlan, error) {
	if err := validateMigrationRequest(ctx, config); err != nil {
		return MigrationPlan{}, err
	}
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return MigrationPlan{}, err
	}

	exists, err := sqliteDatabaseExists(config.Path)
	if err != nil {
		return MigrationPlan{}, mapError(ctx, err)
	}
	if !exists {
		return migrationPlan(0, migrations), nil
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return MigrationPlan{}, err
	}
	defer lock.Close()
	if err := lock.LockShared(ctx); err != nil {
		return MigrationPlan{}, err
	}

	database, conn, err := openMigrationConnection(ctx, config, true)
	if err != nil {
		return MigrationPlan{}, err
	}
	defer closeMigrationConnection(database, conn)

	ledger, err := readMigrationLedger(ctx, conn, migrations)
	if err != nil {
		return MigrationPlan{}, err
	}
	return migrationPlan(ledger.current, migrations), nil
}

// ApplyMigrations verifies the durable ledger and atomically applies every
// pending embedded migration while holding the exclusive maintenance lock.
func ApplyMigrations(ctx context.Context, config Config) (MigrationResult, error) {
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return MigrationResult{}, err
	}
	return applyMigrationsWith(ctx, config, migrations)
}

func applyMigrationsWith(ctx context.Context, config Config, migrations []migration) (result MigrationResult, err error) {
	if err := validateMigrationRequest(ctx, config); err != nil {
		return MigrationResult{}, err
	}
	if err := validateMigrationSet(migrations); err != nil {
		return MigrationResult{}, err
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return MigrationResult{}, err
	}
	defer lock.Close()
	if err := lock.LockExclusive(ctx); err != nil {
		return MigrationResult{}, err
	}

	if err := ensureOwnerOnlyDatabaseFile(config.Path); err != nil {
		return MigrationResult{}, mapError(ctx, err)
	}

	database, conn, err := openMigrationConnection(ctx, config, false)
	if err != nil {
		return MigrationResult{}, err
	}
	defer closeMigrationConnection(database, conn)
	if err := verifyConnectionPragmas(ctx, conn, config, false); err != nil {
		return MigrationResult{}, err
	}

	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return MigrationResult{}, mapError(ctx, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := rollbackMigration(conn); rollbackErr != nil && err == nil {
			err = mapError(ctx, rollbackErr)
		}
	}()

	ledger, err := readMigrationLedger(ctx, conn, migrations)
	if err != nil {
		return MigrationResult{}, err
	}
	if !ledger.exists {
		if _, err := conn.ExecContext(ctx, createSchemaMigrations); err != nil {
			return MigrationResult{}, mapError(ctx, err)
		}
		ledger, err = readMigrationLedger(ctx, conn, migrations)
		if err != nil {
			return MigrationResult{}, err
		}
	}

	result.Previous = ledger.current
	result.Current = ledger.current
	for _, pending := range migrations[ledger.current:] {
		if _, err := conn.ExecContext(ctx, string(pending.SQL)); err != nil {
			return MigrationResult{}, mapError(ctx, err)
		}
		if _, err := conn.ExecContext(
			ctx,
			"INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
			pending.Version,
			pending.Name,
			hex.EncodeToString(pending.SHA256[:]),
			config.Clock.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			return MigrationResult{}, mapError(ctx, err)
		}
		result.Applied = append(result.Applied, pending.MigrationInfo)
		result.Current = pending.Version
	}
	if err := contextError(ctx); err != nil {
		return MigrationResult{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return MigrationResult{}, mapError(ctx, err)
	}
	committed = true
	return result, nil
}

// ValidateSchema verifies that a fully migrated database has the expected
// ledger, schema, indexes, foreign keys, checks, and connection pragmas. It
// never creates a missing database or applies migrations.
func ValidateSchema(ctx context.Context, config Config) error {
	if err := validateMigrationRequest(ctx, config); err != nil {
		return err
	}
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return err
	}

	exists, err := sqliteDatabaseExists(config.Path)
	if err != nil {
		return mapError(ctx, err)
	}
	if !exists {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.LockShared(ctx); err != nil {
		return err
	}

	database, conn, err := openMigrationConnection(ctx, config, true)
	if err != nil {
		return err
	}
	defer closeMigrationConnection(database, conn)

	ledger, err := readMigrationLedger(ctx, conn, migrations)
	if err != nil {
		return err
	}
	if !ledger.exists || ledger.current != uint64(len(migrations)) {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := verifyConnectionPragmas(ctx, conn, config, true); err != nil {
		return migrationValidationError(ctx, err)
	}
	return validateSchemaV1(ctx, conn)
}

func validateMigrationRequest(ctx context.Context, config Config) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return config.validate()
}

func loadEmbeddedMigrations() ([]migration, error) {
	return parseMigrationFS(embeddedMigrationFiles)
}

func parseMigrationFS(filesystem fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(filesystem, "migrations")
	if err != nil || len(entries) == 0 {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}

	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		match := migrationFilename.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		version, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || version == 0 {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		sqlBytes, err := fs.ReadFile(filesystem, "migrations/"+entry.Name())
		if err != nil || len(sqlBytes) == 0 {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		migrations = append(migrations, migration{
			MigrationInfo: MigrationInfo{
				Version: version,
				Name:    match[2],
				SHA256:  sha256.Sum256(sqlBytes),
			},
			SQL: sqlBytes,
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	if err := validateMigrationSet(migrations); err != nil {
		return nil, err
	}
	return migrations, nil
}

func validateMigrationSet(migrations []migration) error {
	if len(migrations) == 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	for index, migration := range migrations {
		if migration.Version != uint64(index+1) || migration.Name == "" || len(migration.SQL) == 0 ||
			migration.SHA256 != sha256.Sum256(migration.SQL) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}

func migrationPlan(current uint64, migrations []migration) MigrationPlan {
	pending := migrations[current:]
	plan := MigrationPlan{Current: current, Pending: make([]MigrationInfo, len(pending))}
	for index, migration := range pending {
		plan.Pending[index] = migration.MigrationInfo
	}
	return plan
}

func sqliteDatabaseExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func openMigrationConnection(ctx context.Context, config Config, reader bool) (*sql.DB, *sql.Conn, error) {
	dsn := databaseDSN(config, reader)
	if reader {
		dsn += "&mode=ro"
	}
	connector, err := moderncsqlite.NewConnector(dsn)
	if err != nil {
		return nil, nil, mapError(ctx, err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	conn, err := database.Conn(ctx)
	if err != nil {
		_ = database.Close()
		return nil, nil, mapError(ctx, err)
	}
	return database, conn, nil
}

func closeMigrationConnection(database *sql.DB, conn *sql.Conn) {
	if conn != nil {
		_ = conn.Close()
	}
	if database != nil {
		_ = database.Close()
	}
}

func rollbackMigration(conn *sql.Conn) error {
	_, err := conn.ExecContext(context.Background(), "ROLLBACK")
	return err
}

func readMigrationLedger(ctx context.Context, conn *sql.Conn, migrations []migration) (ledgerState, error) {
	var objectType string
	err := conn.QueryRowContext(ctx, "SELECT type FROM sqlite_master WHERE name = ?", schemaMigrationsTable).Scan(&objectType)
	if errors.Is(err, sql.ErrNoRows) {
		return ledgerState{}, nil
	}
	if err != nil {
		return ledgerState{}, migrationValidationError(ctx, err)
	}
	if objectType != "table" {
		return ledgerState{}, sqliteError(policyengine.ErrorIntegrity)
	}
	if err := validateMigrationLedgerColumns(ctx, conn); err != nil {
		return ledgerState{}, err
	}

	rows, err := conn.QueryContext(ctx, "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return ledgerState{}, migrationValidationError(ctx, err)
	}
	defer rows.Close()

	state := ledgerState{exists: true}
	for rowIndex := 0; rows.Next(); rowIndex++ {
		var version sql.NullInt64
		var name, checksum, appliedAt sql.NullString
		if err := rows.Scan(&version, &name, &checksum, &appliedAt); err != nil || !version.Valid || !name.Valid || !checksum.Valid || !appliedAt.Valid {
			return ledgerState{}, sqliteError(policyengine.ErrorIntegrity)
		}
		expectedVersion := uint64(rowIndex + 1)
		if version.Int64 <= 0 || uint64(version.Int64) != expectedVersion {
			return ledgerState{}, sqliteError(policyengine.ErrorIntegrity)
		}
		if expectedVersion > uint64(len(migrations)) {
			return ledgerState{}, sqliteError(policyengine.ErrorFailedPrecondition)
		}
		expected := migrations[rowIndex]
		if name.String != expected.Name || checksum.String != hex.EncodeToString(expected.SHA256[:]) || !validAppliedAt(appliedAt.String) {
			return ledgerState{}, sqliteError(policyengine.ErrorIntegrity)
		}
		state.current = expectedVersion
	}
	if err := rows.Err(); err != nil {
		return ledgerState{}, migrationValidationError(ctx, err)
	}
	return state, nil
}

func validateMigrationLedgerColumns(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA table_info(schema_migrations)")
	if err != nil {
		return migrationValidationError(ctx, err)
	}
	defer rows.Close()

	expected := []struct {
		name    string
		typ     string
		notNull int
		primary int
	}{
		{name: "version", typ: "INTEGER", notNull: 0, primary: 1},
		{name: "name", typ: "TEXT", notNull: 1, primary: 0},
		{name: "checksum", typ: "TEXT", notNull: 1, primary: 0},
		{name: "applied_at", typ: "TEXT", notNull: 1, primary: 0},
	}
	for index := 0; rows.Next(); index++ {
		if index >= len(expected) {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		var cid, notNull, primary int
		var name, typ string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		want := expected[index]
		if cid != index || name != want.name || strings.ToUpper(typ) != want.typ || notNull != want.notNull || primary != want.primary || defaultValue.Valid {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if index == len(expected)-1 {
			continue
		}
	}
	if err := rows.Err(); err != nil {
		return migrationValidationError(ctx, err)
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('schema_migrations')").Scan(&count); err != nil || count != len(expected) {
		if err != nil {
			return migrationValidationError(ctx, err)
		}
		return sqliteError(policyengine.ErrorIntegrity)
	}
	return nil
}

func validAppliedAt(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func migrationValidationError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if err == nil {
		return nil
	}
	return sqliteError(policyengine.ErrorIntegrity)
}
