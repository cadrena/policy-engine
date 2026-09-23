package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestPruneExpiredEventsCoversDormantNamespacesAndRestores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now.Add(-25 * time.Hour))
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	putOfflinePruneRevision(t, config, "dormant-a")
	putOfflinePruneRevision(t, config, "dormant-b")
	clock.Set(now.Add(-time.Hour))
	putOfflinePruneRevision(t, config, "fresh")
	clock.Set(now)
	if err := FullIntegrityCheck(ctx, config); err != nil {
		t.Fatalf("FullIntegrityCheck(source before prune) error = %v", err)
	}
	if err := PruneExpiredEvents(ctx, config); err != nil {
		t.Fatalf("PruneExpiredEvents() error = %v", err)
	}
	if err := FullIntegrityCheck(ctx, config); err != nil {
		t.Fatalf("FullIntegrityCheck(source after prune) error = %v", err)
	}
	db := openRawSQLite(t, config.Path)
	for _, tc := range []struct {
		namespace   string
		wantEvents  int
		wantExpired int64
	}{
		{namespace: "dormant-a", wantEvents: 0, wantExpired: 1},
		{namespace: "dormant-b", wantEvents: 0, wantExpired: 1},
		{namespace: "fresh", wantEvents: 1, wantExpired: 0},
	} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM state_events WHERE namespace = ?", tc.namespace).Scan(&count); err != nil {
			t.Fatalf("count events for %q: %v", tc.namespace, err)
		}
		if count != tc.wantEvents {
			t.Errorf("PruneExpiredEvents(%q) events = %d, want %d", tc.namespace, count, tc.wantEvents)
		}
		var sequence, expired int64
		if err := db.QueryRowContext(ctx, "SELECT event_sequence, expired_through FROM namespace_heads WHERE namespace = ?", tc.namespace).Scan(&sequence, &expired); err != nil {
			t.Fatalf("read namespace head for %q: %v", tc.namespace, err)
		}
		if sequence != 1 || expired != tc.wantExpired {
			t.Errorf("PruneExpiredEvents(%q) head = (%d, %d), want (1, %d)", tc.namespace, sequence, expired, tc.wantExpired)
		}
	}
	var revisions int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM revisions").Scan(&revisions); err != nil {
		t.Fatalf("count revisions after prune: %v", err)
	}
	if revisions != 3 {
		t.Errorf("revision count after prune = %d, want 3", revisions)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close source inspection: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := ExportAuditBackup(ctx, config, backupPath); err != nil {
		t.Fatalf("ExportAuditBackup(pruned source) error = %v", err)
	}
	image, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup image: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, image, 0o600); err != nil {
		t.Fatalf("write restored image: %v", err)
	}
	restoreConfig := config
	restoreConfig.Path = restored
	if err := FullIntegrityCheck(ctx, restoreConfig); err != nil {
		t.Fatalf("FullIntegrityCheck(restored pruned source) error = %v", err)
	}
}

func TestPruneExpiredEventsRejectsRunningStore(t *testing.T) {
	t.Parallel()
	config := migratedIntegrityConfig(t)
	opened, err := Open(config)
	if err != nil {
		t.Fatalf("Open(source) error = %v", err)
	}
	defer func() { _ = opened.Close() }()
	if got := categoryOf(PruneExpiredEvents(context.Background(), config)); got != policyengine.ErrorUnavailable {
		t.Errorf("PruneExpiredEvents(running source) category = %v, want %v", got, policyengine.ErrorUnavailable)
	}
}

func TestPruneExpiredEventsRejectsInvalidSourceWithoutDeletingEvents(t *testing.T) {
	t.Parallel()
	config := migratedIntegrityConfig(t)
	putOfflinePruneRevision(t, config, "unchanged")
	mutateIntegrityDatabase(t, config, func(t *testing.T, db *sql.DB) {
		mustExecIntegrityTest(t, db, "UPDATE cadrena_meta SET value = X'00' WHERE key = 'cursor_hmac_key'")
	})
	if got := categoryOf(PruneExpiredEvents(context.Background(), config)); got != policyengine.ErrorIntegrity {
		t.Errorf("PruneExpiredEvents(invalid source) category = %v, want %v", got, policyengine.ErrorIntegrity)
	}
	db := openRawSQLite(t, config.Path)
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM state_events WHERE namespace = 'unchanged'").Scan(&count); err != nil {
		t.Fatalf("count unchanged events: %v", err)
	}
	if count != 1 {
		t.Errorf("events after failed PruneExpiredEvents = %d, want 1", count)
	}
}

func TestPruneExpiredEventsRejectsNonmonotonicEventTimes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)
	clock := &sqliteMutableClock{}
	clock.Set(now.Add(-25 * time.Hour))
	config := validConfig(filepath.Join(t.TempDir(), "source.db"))
	config.Clock = clock
	if _, err := ApplyMigrations(ctx, config); err != nil {
		t.Fatalf("ApplyMigrations(source) error = %v", err)
	}
	populateIntegrityFixture(t, config)
	shiftBackupEventTime(t, config.Path, "integrity-fixture", 1, now.Add(-time.Hour))
	clock.Set(now)
	if err := FullIntegrityCheck(ctx, config); err != nil {
		t.Fatalf("FullIntegrityCheck(nonmonotonic source) error = %v", err)
	}
	if got := categoryOf(PruneExpiredEvents(ctx, config)); got != policyengine.ErrorIntegrity {
		t.Errorf("PruneExpiredEvents(nonmonotonic source) category = %v, want %v", got, policyengine.ErrorIntegrity)
	}
	db := openRawSQLite(t, config.Path)
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM state_events WHERE namespace = 'integrity-fixture'").Scan(&count); err != nil {
		t.Fatalf("count events after rejected prune: %v", err)
	}
	if count != 4 {
		t.Errorf("events after rejected prune = %d, want 4", count)
	}
}

func putOfflinePruneRevision(t *testing.T, config Config, namespace string) {
	t.Helper()
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", namespace, err)
	}
	revision := newSQLiteRevisionWrite(t, namespace, "prune.cdr", []byte("entity user {}"), time.Unix(10, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		_ = adapter.Close()
		t.Fatalf("PutRevision(%q) error = %v", namespace, err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close(%q) error = %v", namespace, err)
	}
}
