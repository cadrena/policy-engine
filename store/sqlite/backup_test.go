package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestExportAuditBackupPrunesDormantNamespaceAndRestores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now.Add(-23 * 24 * time.Hour))
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	populateIntegrityFixture(t, config)
	putBackupRevision(t, config, "dormant", "dormant.cdr")
	putBackupRevision(t, config, "integrity-fixture", "recent.cdr")
	shiftBackupEventTime(t, config.Path, "integrity-fixture", 5, now.Add(-time.Hour))
	clock.Set(now)
	before := backupCounts(t, config.Path)
	if before.events != 6 {
		t.Fatalf("source event count = %d, want 6", before.events)
	}
	sourceDB := openRawSQLite(t, config.Path)
	var oldPayload []byte
	if err := sourceDB.QueryRowContext(ctx, "SELECT payload FROM state_events WHERE namespace = 'dormant'").Scan(&oldPayload); err != nil {
		t.Fatalf("read old source event: %v", err)
	}
	if err := sourceDB.Close(); err != nil {
		t.Fatalf("close source inspection: %v", err)
	}
	sourceImage, err := os.ReadFile(config.Path)
	if err != nil {
		t.Fatalf("read source image before export: %v", err)
	}
	destination := filepath.Join(t.TempDir(), "backup.db")
	if err := ExportAuditBackup(ctx, config, destination); err != nil {
		t.Fatalf("ExportAuditBackup() error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil {
		t.Fatalf("read backup directory after export: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".audit-backup-") {
			t.Errorf("backup export left temporary copy %q", entry.Name())
		}
	}
	after := backupCounts(t, config.Path)
	if after != before {
		t.Errorf("source records after ExportAuditBackup = %+v, want %+v", after, before)
	}
	if got, err := os.ReadFile(config.Path); err != nil || !bytes.Equal(got, sourceImage) {
		t.Errorf("source image after ExportAuditBackup changed: read error = %v", err)
	}
	backup := backupCounts(t, destination)
	if backup.events != 1 || backup.revisions != before.revisions || backup.idempotency != before.idempotency {
		t.Errorf("backup records = %+v, want one event and unchanged non-event counts %+v", backup, before)
	}
	db := openRawSQLite(t, destination)
	defer func() { _ = db.Close() }()
	var dormantSequence, dormantExpired, recentSequence, recentExpired int64
	if err := db.QueryRowContext(ctx, "SELECT event_sequence, expired_through FROM namespace_heads WHERE namespace = 'dormant'").Scan(&dormantSequence, &dormantExpired); err != nil {
		t.Fatalf("read dormant namespace head: %v", err)
	}
	if dormantSequence != 1 || dormantExpired != 1 {
		t.Errorf("dormant namespace head = (%d, %d), want (1, 1)", dormantSequence, dormantExpired)
	}
	if err := db.QueryRowContext(ctx, "SELECT event_sequence, expired_through FROM namespace_heads WHERE namespace = 'integrity-fixture'").Scan(&recentSequence, &recentExpired); err != nil {
		t.Fatalf("read active namespace head: %v", err)
	}
	if recentSequence != 5 || recentExpired != 4 {
		t.Errorf("active namespace head = (%d, %d), want (5, 4)", recentSequence, recentExpired)
	}
	var oldEvents int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM state_events WHERE created_at_ns < ?", now.Add(-backupEventRetention).UnixNano()).Scan(&oldEvents); err != nil {
		t.Fatalf("count old backup events: %v", err)
	}
	if oldEvents != 0 {
		t.Errorf("old backup events = %d, want 0", oldEvents)
	}
	var freePages int
	if err := db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		t.Fatalf("read backup free pages: %v", err)
	}
	if freePages != 0 {
		t.Errorf("backup free pages = %d, want 0", freePages)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close backup inspection: %v", err)
	}
	image, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read backup image: %v", err)
	}
	if bytes.Contains(image, oldPayload) {
		t.Error("backup image contains the removed event payload")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, image, 0o600); err != nil {
		t.Fatalf("write restored image: %v", err)
	}
	restoreConfig := config
	restoreConfig.Path = restored
	if err := FullIntegrityCheck(ctx, restoreConfig); err != nil {
		t.Fatalf("FullIntegrityCheck(restored backup) error = %v", err)
	}
	store, err := Open(restoreConfig)
	if err != nil {
		t.Fatalf("Open(restored backup) error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(restored backup) error = %v", err)
	}
}

func TestExportAuditBackupRejectsOldBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now.Add(-31 * 24 * time.Hour))
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	putBackupRevision(t, config, "dormant", "old.cdr")
	clock.Set(now)
	destination := filepath.Join(t.TempDir(), "backup.db")
	if err := ExportAuditBackup(ctx, config, destination); categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(old backlog) = %v (category %v), want %v", err, categoryOf(err), policyengine.ErrorFailedPrecondition)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after old backlog rejection: stat error = %v, want not exist", err)
	}
}

func TestExportAuditBackupRejectsNonPrefixOldEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now.Add(-23 * 24 * time.Hour))
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	populateIntegrityFixture(t, config)
	shiftBackupEventTime(t, config.Path, "integrity-fixture", 1, now.Add(-time.Hour))
	clock.Set(now)
	if err := FullIntegrityCheck(ctx, config); err != nil {
		t.Fatalf("FullIntegrityCheck(non-prefix source) error = %v", err)
	}
	destination := filepath.Join(t.TempDir(), "backup.db")
	if got := categoryOf(ExportAuditBackup(ctx, config, destination)); got != policyengine.ErrorIntegrity {
		t.Errorf("ExportAuditBackup(non-prefix old events) category = %v, want %v", got, policyengine.ErrorIntegrity)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after non-prefix rejection: stat error = %v, want not exist", err)
	}
}

func TestExportAuditBackupRejectsFutureEventTimestamp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now)
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	putBackupRevision(t, config, "future", "future.cdr")
	shiftBackupEventTime(t, config.Path, "future", 1, now.Add(time.Hour))
	destination := filepath.Join(t.TempDir(), "backup.db")
	if got := categoryOf(ExportAuditBackup(ctx, config, destination)); got != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(future event) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after future event rejection: stat error = %v, want not exist", err)
	}
}

func TestExportAuditBackupRejectsRunningSource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	config := migratedIntegrityConfig(t)
	opened, err := Open(config)
	if err != nil {
		t.Fatalf("Open(source) error = %v", err)
	}
	defer func() { _ = opened.Close() }()
	destination := filepath.Join(t.TempDir(), "backup.db")
	if got := categoryOf(ExportAuditBackup(ctx, config, destination)); got != policyengine.ErrorUnavailable {
		t.Errorf("ExportAuditBackup(running source) category = %v, want %v", got, policyengine.ErrorUnavailable)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after running source rejection: stat error = %v, want not exist", err)
	}
}

func TestPublishBackupImageRemovesLinkAfterDirectorySyncFailure(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	imagePath := filepath.Join(parent, "staged.db")
	destination := filepath.Join(parent, "backup.db")
	image := []byte("complete staged image")
	if err := os.WriteFile(imagePath, image, 0o600); err != nil {
		t.Fatalf("write staged image: %v", err)
	}
	syncCalls := 0
	syncDirectory := func(*os.File) error {
		syncCalls++
		return errors.New("directory sync failed")
	}
	if got := categoryOf(publishBackupImage(context.Background(), imagePath, destination, syncDirectory)); got != policyengine.ErrorInternal {
		t.Errorf("publishBackupImage(directory sync failure) category = %v, want %v", got, policyengine.ErrorInternal)
	}
	if syncCalls != 2 {
		t.Errorf("directory sync calls = %d, want publication and cleanup attempts", syncCalls)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after directory sync failure: stat error = %v, want not exist", err)
	}
	if got, err := os.ReadFile(imagePath); err != nil || !bytes.Equal(got, image) {
		t.Errorf("staged image after directory sync failure = %q, %v; want unchanged image", got, err)
	}
}

func TestFinishBackupExportRejectsStageCleanupFailure(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	stagingDir := filepath.Join(parent, ".audit-backup-staged")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatalf("create staged directory: %v", err)
	}
	destination := filepath.Join(parent, "backup.db")
	if err := os.WriteFile(destination, []byte("published image"), 0o600); err != nil {
		t.Fatalf("create published image: %v", err)
	}
	removeCalls := 0
	removeStage := func(string) error {
		removeCalls++
		return errors.New("stage removal failed")
	}
	if got := categoryOf(finishBackupExport(context.Background(), stagingDir, destination, removeStage)); got != policyengine.ErrorInternal {
		t.Errorf("finishBackupExport(cleanup failure) category = %v, want %v", got, policyengine.ErrorInternal)
	}
	if removeCalls != 1 {
		t.Errorf("stage removal attempts = %d, want 1", removeCalls)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after cleanup failure: stat error = %v, want not exist", err)
	}
	if _, err := os.Lstat(stagingDir); err != nil {
		t.Errorf("staging directory after injected removal failure: stat error = %v, want retained for inspection", err)
	}
}

func TestExportAuditBackupRejectsCrashLeftoverStage(t *testing.T) {
	t.Parallel()
	config := migratedIntegrityConfig(t)
	parent := t.TempDir()
	stagingDir := filepath.Join(parent, ".audit-backup-leftover")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatalf("create crash leftover: %v", err)
	}
	destination := filepath.Join(parent, "backup.db")
	if got := categoryOf(ExportAuditBackup(context.Background(), config, destination)); got != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(crash leftover) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after crash leftover rejection: stat error = %v, want not exist", err)
	}
}

func TestExportAuditBackupRejectsInvalidSourceAndUncleanDestination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	config := migratedIntegrityConfig(t)
	destination := filepath.Join(t.TempDir(), "backup.db")
	mutateIntegrityDatabase(t, config, func(t *testing.T, db *sql.DB) {
		mustExecIntegrityTest(t, db, "UPDATE cadrena_meta SET value = X'00' WHERE key = 'cursor_hmac_key'")
	})
	if got := categoryOf(ExportAuditBackup(ctx, config, destination)); got != policyengine.ErrorIntegrity {
		t.Errorf("ExportAuditBackup(invalid source) category = %v, want %v", got, policyengine.ErrorIntegrity)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Errorf("backup after invalid source rejection: stat error = %v, want not exist", err)
	}
	clean := migratedIntegrityConfig(t)
	canary := []byte("existing backup")
	if err := os.WriteFile(destination, canary, 0o600); err != nil {
		t.Fatalf("write destination canary: %v", err)
	}
	if got := categoryOf(ExportAuditBackup(ctx, clean, destination)); got != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(existing destination) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, canary) {
		t.Errorf("existing destination = %q, %v; want unchanged canary", got, err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatalf("remove destination canary: %v", err)
	}
	if err := os.Symlink(config.Path, destination); err != nil {
		t.Fatalf("create destination symlink: %v", err)
	}
	if got := categoryOf(ExportAuditBackup(ctx, clean, destination)); got != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(symlink destination) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatalf("remove destination symlink: %v", err)
	}
	if err := os.WriteFile(destination+"-wal", []byte("stale"), 0o600); err != nil {
		t.Fatalf("write unclean sidecar: %v", err)
	}
	if got := categoryOf(ExportAuditBackup(ctx, clean, destination)); got != policyengine.ErrorFailedPrecondition {
		t.Errorf("ExportAuditBackup(unclean sidecar) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
}

func putBackupRevision(t *testing.T, config Config, namespace, name string) {
	t.Helper()
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	source := []byte("entity user {}")
	if name == "recent.cdr" {
		source = []byte("entity document {}")
	}
	revision := newSQLiteRevisionWrite(t, namespace, name, source, time.Unix(10, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		_ = adapter.Close()
		t.Fatalf("PutRevision(%q, %q) error = %v", namespace, name, err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func shiftBackupEventTime(t *testing.T, path, namespace string, sequence int64, when time.Time) {
	t.Helper()
	db := openRawSQLite(t, path)
	defer func() { _ = db.Close() }()
	var payload []byte
	if err := db.QueryRowContext(context.Background(), "SELECT payload FROM state_events WHERE namespace = ? AND sequence = ?", namespace, sequence).Scan(&payload); err != nil {
		t.Fatalf("read event for timestamp shift: %v", err)
	}
	event, err := decodeStateEvent(payload)
	if err != nil {
		t.Fatalf("decode event for timestamp shift: %v", err)
	}
	shifted, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace: namespace, Cursor: event.Cursor(), Kind: event.Kind(), RevisionID: event.RevisionID(),
		Slot: event.Slot(), SlotGeneration: event.SlotGeneration(), DataGeneration: event.DataGeneration(), OccurredAt: when,
	})
	if err != nil {
		t.Fatalf("construct shifted event: %v", err)
	}
	encoded, err := encodeStateEvent(shifted)
	if err != nil {
		t.Fatalf("encode shifted event: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "UPDATE state_events SET payload = ?, created_at_ns = ? WHERE namespace = ? AND sequence = ?", encoded, when.UnixNano(), namespace, sequence); err != nil {
		t.Fatalf("update event timestamp: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "UPDATE namespace_heads SET effective_time_ns = ? WHERE namespace = ?", when.UnixNano(), namespace); err != nil {
		t.Fatalf("update effective timestamp: %v", err)
	}
}

type backupRecordCounts struct {
	events      int
	revisions   int
	idempotency int
}

func backupCounts(t *testing.T, path string) backupRecordCounts {
	t.Helper()
	db := openRawSQLite(t, path)
	defer func() { _ = db.Close() }()
	var counts backupRecordCounts
	for _, query := range []struct {
		statement string
		output    *int
	}{
		{statement: "SELECT COUNT(*) FROM state_events", output: &counts.events},
		{statement: "SELECT COUNT(*) FROM revisions", output: &counts.revisions},
		{statement: "SELECT COUNT(*) FROM idempotency_records", output: &counts.idempotency},
	} {
		if err := db.QueryRowContext(context.Background(), query.statement).Scan(query.output); err != nil {
			t.Fatalf("count backup records using %q: %v", query.statement, err)
		}
	}
	return counts
}
