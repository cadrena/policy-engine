package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
)

const (
	backupEventRetention = 22 * 24 * time.Hour
	backupBacklogLimit   = 30 * 24 * time.Hour
)

// ExportAuditBackup creates an offline SQLite backup with old state events
// removed. It requires a stopped store, keeps the source database unchanged,
// and refuses every existing destination or destination sidecar. It retains
// all non-event records, including their original migration ledger and key.
func ExportAuditBackup(ctx context.Context, config Config, destination string) (resultErr error) {
	config, err := validateMigrationRequest(ctx, config)
	if err != nil {
		return err
	}
	destination, err = validateBackupDestination(ctx, destination)
	if err != nil {
		return err
	}
	if err := ensureCleanBackupDestination(ctx, destination); err != nil {
		return err
	}
	if err := ensureNoStaleBackupStages(ctx, destination); err != nil {
		return err
	}
	if config.Path == destination {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	// The copy below names every V1 table. A schema change must update this
	// export before it can emit an image of the new store version.
	migrations, err := loadEmbeddedMigrations()
	if err != nil {
		return err
	}
	if len(migrations) != 1 || migrations[0].Version != 1 || migrations[0].Name != "initial" {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	_, nowNS, err := canonicalClockNow(config.Clock)
	if err != nil {
		return err
	}
	if nowNS < math.MinInt64+int64(backupBacklogLimit) {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	retentionCutoff := nowNS - int64(backupEventRetention)
	backlogCutoff := nowNS - int64(backupBacklogLimit)

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
	defer func() { _ = lock.Close() }()
	if err := lockIntegrityExclusive(ctx, lock, config.BusyTimeout); err != nil {
		return err
	}
	if err := validateWALFile(ctx, config.Path); err != nil {
		return integrityResultError(ctx, err)
	}
	sourceDB, sourceConn, err := openExistingIntegrityConnectionWithConnectorFactory(ctx, config, moderncsqlite.NewConnector)
	if err != nil {
		return integrityResultError(ctx, err)
	}
	defer closeMigrationConnection(sourceDB, sourceConn)
	if err := persistIntegrityWAL(ctx, sourceConn); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := verifyConnectionPragmas(ctx, sourceConn, config, false); err != nil {
		return integrityResultError(ctx, err)
	}
	if _, err := sourceConn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if err := validateWALFile(ctx, config.Path); err != nil {
		_ = rollbackMigration(sourceConn)
		return integrityResultError(ctx, err)
	}
	if err := fullIntegrityCheck(ctx, sourceConn); err != nil {
		_ = rollbackMigration(sourceConn)
		return integrityResultError(ctx, err)
	}
	if err := rollbackMigration(sourceConn); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if err := ensureNoStaleBackupStages(ctx, destination); err != nil {
		return err
	}

	stagingDir, err := os.MkdirTemp(filepath.Dir(destination), ".audit-backup-")
	if err != nil {
		return mapError(ctx, err)
	}
	stageRemoved := false
	defer func() {
		if stageRemoved {
			return
		}
		if cleanupErr := os.RemoveAll(stagingDir); cleanupErr != nil {
			resultErr = mapError(ctx, cleanupErr)
		}
	}()
	stagingConfig := config
	stagingConfig.Path = filepath.Join(stagingDir, "staging.db")
	if _, err := ApplyMigrations(ctx, stagingConfig); err != nil {
		return err
	}
	if err := copyBackupRows(ctx, sourceConn, stagingConfig.Path, nowNS, retentionCutoff, backlogCutoff); err != nil {
		return err
	}
	finalPath := filepath.Join(stagingDir, "final.db")
	if err := compactBackup(ctx, stagingConfig, finalPath); err != nil {
		return err
	}
	finalConfig := config
	finalConfig.Path = finalPath
	if err := FullIntegrityCheck(ctx, finalConfig); err != nil {
		return err
	}
	if err := validateStandaloneBackupImage(ctx, finalPath); err != nil {
		return err
	}
	if err := ensureCleanBackupDestination(ctx, destination); err != nil {
		return err
	}
	if err := publishBackupImage(ctx, finalPath, destination, (*os.File).Sync); err != nil {
		return err
	}
	if err := finishBackupExport(ctx, stagingDir, destination, os.RemoveAll); err != nil {
		return err
	}
	stageRemoved = true
	return nil
}

func ensureNoStaleBackupStages(ctx context.Context, destination string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil {
		return mapError(ctx, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".audit-backup-") {
			return sqliteError(policyengine.ErrorFailedPrecondition)
		}
	}
	return nil
}

func finishBackupExport(ctx context.Context, stagingDir, destination string, removeStage func(string) error) error {
	if removeStage == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	if err := removeStage(stagingDir); err != nil {
		if discardErr := removePublishedBackup(ctx, destination); discardErr != nil {
			return discardErr
		}
		return mapError(ctx, err)
	}
	if err := syncBackupDirectory(ctx, destination); err != nil {
		if discardErr := removePublishedBackup(ctx, destination); discardErr != nil {
			return discardErr
		}
		return err
	}
	if err := contextError(ctx); err != nil {
		if discardErr := removePublishedBackup(ctx, destination); discardErr != nil {
			return discardErr
		}
		return err
	}
	return nil
}

func removePublishedBackup(ctx context.Context, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return mapError(ctx, err)
	}
	return syncBackupDirectory(ctx, destination)
}

func syncBackupDirectory(ctx context.Context, destination string) error {
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return mapError(ctx, err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return mapError(ctx, syncErr)
	}
	if closeErr != nil {
		return mapError(ctx, closeErr)
	}
	return nil
}

// publishBackupImage syncs the complete image before exposing its name. The
// directory sync makes the new link durable before the caller sees success.
// A failed directory sync removes the link and attempts to sync that removal.
func publishBackupImage(ctx context.Context, imagePath, destination string, syncDirectory func(*os.File) error) error {
	if syncDirectory == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := os.Chmod(imagePath, 0o600); err != nil {
		return mapError(ctx, err)
	}
	image, err := os.Open(imagePath)
	if err != nil {
		return mapError(ctx, err)
	}
	syncErr := image.Sync()
	closeErr := image.Close()
	if syncErr != nil {
		return mapError(ctx, syncErr)
	}
	if closeErr != nil {
		return mapError(ctx, closeErr)
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = directory.Close() }()
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := os.Link(imagePath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return sqliteError(policyengine.ErrorFailedPrecondition)
		}
		return mapError(ctx, err)
	}
	if err := syncDirectory(directory); err != nil {
		return discardBackupLink(ctx, destination, directory, syncDirectory, err)
	}
	if err := contextError(ctx); err != nil {
		return discardBackupLink(ctx, destination, directory, syncDirectory, err)
	}
	return nil
}

func discardBackupLink(ctx context.Context, destination string, directory *os.File, syncDirectory func(*os.File) error, cause error) error {
	if err := os.Remove(destination); err != nil {
		return mapError(ctx, err)
	}
	// The original failure still controls the result. A second sync can also
	// fail on a damaged filesystem, but it cannot make publication successful.
	_ = syncDirectory(directory)
	return mapError(ctx, cause)
}

func validateBackupDestination(ctx context.Context, destination string) (string, error) {
	if !durablePath(destination) {
		return "", sqliteError(policyengine.ErrorInvalidArgument)
	}
	canonical, err := canonicalDatabasePath(destination)
	if err != nil {
		return "", mapError(ctx, err)
	}
	if err := validateSupportedFilesystem(ctx, canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

func ensureCleanBackupDestination(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal", ".lock"} {
		_, err := os.Lstat(path + suffix)
		if err == nil {
			return sqliteError(policyengine.ErrorFailedPrecondition)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return mapError(ctx, err)
		}
	}
	return nil
}

func copyBackupRows(ctx context.Context, source *sql.Conn, destination string, nowNS, retentionCutoff, backlogCutoff int64) error {
	var exists int
	if err := source.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM state_events WHERE created_at_ns < ?)", backlogCutoff).Scan(&exists); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if exists != 0 {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := source.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM state_events WHERE created_at_ns > ?)", nowNS).Scan(&exists); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if exists != 0 {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	const nonPrefix = `WITH old_prefix AS (
		SELECT namespace, MAX(sequence) AS last_sequence
		FROM state_events WHERE created_at_ns < ? GROUP BY namespace
	)
	SELECT EXISTS(
		SELECT 1 FROM state_events AS event JOIN old_prefix AS old
		ON event.namespace = old.namespace
		WHERE event.sequence <= old.last_sequence AND event.created_at_ns >= ?
	)`
	if err := source.QueryRowContext(ctx, nonPrefix, retentionCutoff, retentionCutoff).Scan(&exists); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	if exists != 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}

	uri := &url.URL{Scheme: "file", Path: destination}
	uri.RawQuery = "mode=rw"
	if _, err := source.ExecContext(ctx, "ATTACH DATABASE ? AS backup", uri.String()); err != nil {
		return mapError(ctx, err)
	}
	defer func() { _, _ = source.ExecContext(context.Background(), "DETACH DATABASE backup") }()
	if _, err := source.ExecContext(ctx, "BEGIN"); err != nil {
		return mapError(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = rollbackMigration(source)
		}
	}()
	statements := []struct {
		query string
		args  []any
	}{
		{query: "DELETE FROM backup.cadrena_meta"},
		{query: "DELETE FROM backup.schema_migrations"},
		{query: "INSERT INTO backup.cadrena_meta SELECT * FROM main.cadrena_meta"},
		{query: "INSERT INTO backup.schema_migrations SELECT * FROM main.schema_migrations"},
		{query: `INSERT INTO backup.namespace_heads(namespace, data_generation, event_sequence, expired_through, effective_time_ns)
		 SELECT head.namespace, head.data_generation, head.event_sequence,
		 COALESCE((SELECT MAX(sequence) FROM main.state_events AS event
		           WHERE event.namespace = head.namespace AND event.created_at_ns < ?), head.expired_through),
		 head.effective_time_ns FROM main.namespace_heads AS head`, args: []any{retentionCutoff}},
		{query: "INSERT INTO backup.revisions SELECT * FROM main.revisions"},
		{query: "INSERT INTO backup.slot_heads SELECT * FROM main.slot_heads"},
		{query: "INSERT INTO backup.activation_history SELECT * FROM main.activation_history"},
		{query: "INSERT INTO backup.tuples SELECT * FROM main.tuples"},
		{query: "INSERT INTO backup.attributes SELECT * FROM main.attributes"},
		{query: "INSERT INTO backup.attribute_ancestors SELECT * FROM main.attribute_ancestors"},
		{query: "INSERT INTO backup.state_events SELECT * FROM main.state_events WHERE created_at_ns >= ?", args: []any{retentionCutoff}},
		{query: "INSERT INTO backup.idempotency_records SELECT * FROM main.idempotency_records"},
	}
	for _, statement := range statements {
		if _, err := source.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return integrityResultError(ctx, mapError(ctx, err))
		}
	}
	if _, err := source.ExecContext(ctx, "COMMIT"); err != nil {
		return mapError(ctx, err)
	}
	committed = true
	return nil
}

func compactBackup(ctx context.Context, config Config, destination string) error {
	database, conn, err := openMigrationConnection(ctx, config, false)
	if err != nil {
		return err
	}
	defer closeMigrationConnection(database, conn)
	if _, err := conn.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return mapError(ctx, err)
	}
	finalConfig := config
	finalConfig.Path = destination
	finalDB, finalConn, err := openMigrationConnection(ctx, finalConfig, false)
	if err != nil {
		return err
	}
	defer closeMigrationConnection(finalDB, finalConn)
	if err := verifyConnectionPragmas(ctx, finalConn, finalConfig, false); err != nil {
		return err
	}
	return nil
}

func validateStandaloneBackupImage(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return mapError(ctx, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return sqliteError(policyengine.ErrorIntegrity)
	}
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return mapError(ctx, err)
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return nil
}
