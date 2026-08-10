package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestRecoveryCleanReopenReconstructsCommittedPublicValues(t *testing.T) {
	// This catches process-local state, missing WAL durability, or a replay
	// record that cannot be reconstructed after a normal close and reopen.
	config := migratedIntegrityConfig(t)
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := writeSubprocessRecoveryFixture(adapter); err != nil {
		_ = adapter.Close()
		t.Fatalf("write fixture: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(config)
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	assertSubprocessRecoveryFixture(t, reopened)
}

func TestCrashRecoveryRestoresCommittedWALTransactionBeforeCheckpoint(t *testing.T) {
	// This catches recovery that treats a process exit after COMMIT as lost work
	// or relies on a clean close/checkpoint instead of SQLite's WAL recovery.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	child := startSQLiteRecoverySubprocess(t, "committed", config.Path)
	child.awaitReady(t)
	if info, err := os.Stat(config.Path + "-wal"); err != nil || info.Size() == 0 {
		child.releaseAndWait(t)
		t.Fatalf("committed helper WAL = %v, %v; want non-empty WAL before crash", info, err)
	}
	child.releaseAndWait(t)
	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("FullIntegrityCheck(after committed crash) error = %v", err)
	}

	recovered, err := Open(config)
	if err != nil {
		t.Fatalf("Open(after committed crash) error = %v", err)
	}
	defer func() { _ = recovered.Close() }()
	assertSubprocessRecoveryFixture(t, recovered)
	if err := FullIntegrityCheck(context.Background(), config); categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("FullIntegrityCheck(live runtime) category = %v, want %v", categoryOf(err), policyengine.ErrorUnavailable)
	}
}

func TestCrashRecoveryExposesNoneOfPreCommitTransaction(t *testing.T) {
	// This catches accidental commit-before-acknowledgement or recovery that
	// exposes a process's uncommitted page-cache state after it exits.
	config := migratedIntegrityConfig(t)
	child := startSQLiteRecoverySubprocess(t, "uncommitted", config.Path)
	child.awaitReady(t)
	child.releaseAndWait(t)

	database := openRawSQLite(t, config.Path)
	var count int
	if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM namespace_heads WHERE namespace = 'precommit-crash'").Scan(&count); err != nil {
		t.Fatalf("count staged head after crash: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}
	if count != 0 {
		t.Fatalf("staged namespace heads after pre-commit crash = %d, want 0", count)
	}
	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("FullIntegrityCheck(after pre-commit crash) error = %v", err)
	}
}

func TestRecoveryCorruptionFailsClosedAndNeverTouchesOutsideDatabase(t *testing.T) {
	// This catches recovery that silently accepts truncated main/WAL files or
	// follows a failed recovery path into a database outside its supplied
	// temporary directory.
	t.Run("truncated main database", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		if err := os.Truncate(config.Path, 16); err != nil {
			t.Fatalf("truncate database: %v", err)
		}
		if opened, err := Open(config); opened != nil || categoryOf(err) != policyengine.ErrorIntegrity {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatalf("Open(truncated) = %v, %v; want nil INTEGRITY", opened, err)
		}
		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorIntegrity {
			t.Fatalf("FullIntegrityCheck(truncated) category = %v, want %v", got, policyengine.ErrorIntegrity)
		}
	})

	t.Run("corrupt WAL", func(t *testing.T) {
		config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
		child := startSQLiteRecoverySubprocess(t, "committed", config.Path)
		child.awaitReady(t)
		child.releaseAndWait(t)
		if err := os.WriteFile(config.Path+"-wal", []byte("not a SQLite WAL"), 0o600); err != nil {
			t.Fatalf("corrupt WAL: %v", err)
		}
		if opened, err := Open(config); opened != nil || categoryOf(err) != policyengine.ErrorIntegrity {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatalf("Open(corrupt WAL) = %v, %v; want nil INTEGRITY", opened, err)
		}
		err := FullIntegrityCheck(context.Background(), config)
		if got := categoryOf(err); got != policyengine.ErrorIntegrity {
			t.Fatalf("FullIntegrityCheck(corrupt WAL) error = %T %v, category = %v, want %v", err, err, got, policyengine.ErrorIntegrity)
		}
	})

	t.Run("outside canary unchanged", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		if err := os.Truncate(config.Path, 16); err != nil {
			t.Fatalf("truncate database: %v", err)
		}
		outside := filepath.Join(t.TempDir(), "outside.db")
		const canary = "outside database canary"
		if err := os.WriteFile(outside, []byte(canary), 0o600); err != nil {
			t.Fatalf("write outside canary: %v", err)
		}
		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorIntegrity {
			t.Fatalf("FullIntegrityCheck(truncated) category = %v, want %v", got, policyengine.ErrorIntegrity)
		}
		value, err := os.ReadFile(outside)
		if err != nil {
			t.Fatalf("read outside canary: %v", err)
		}
		if string(value) != canary {
			t.Fatalf("outside canary = %q, want %q", value, canary)
		}
		for _, artifact := range []string{outside + ".lock", outside + "-wal", outside + "-shm"} {
			if _, err := os.Stat(artifact); !os.IsNotExist(err) {
				t.Fatalf("recovery touched outside artifact %q: %v", artifact, err)
			}
		}
	})
}

func TestIntegrityFullCheckReturnsUnavailableForSQLiteBusyAndReleasesStaleRuntimeLock(t *testing.T) {
	// This catches a checker that shares a runtime lock, waits forever for a
	// SQLite writer, or leaves a process-dead advisory lock behind.
	t.Run("busy SQLite transaction", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		database := openRawSQLite(t, config.Path)
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

		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorUnavailable {
			t.Fatalf("FullIntegrityCheck(busy) category = %v, want %v", got, policyengine.ErrorUnavailable)
		}
	})

	t.Run("stale runtime lock", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		child := startSQLiteRecoverySubprocess(t, "hold-runtime", config.Path)
		child.awaitReady(t)
		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorUnavailable {
			child.releaseAndWait(t)
			t.Fatalf("FullIntegrityCheck(live runtime) category = %v, want %v", got, policyengine.ErrorUnavailable)
		}
		child.releaseAndWait(t)
		if err := FullIntegrityCheck(context.Background(), config); err != nil {
			t.Fatalf("FullIntegrityCheck(after dead runtime) error = %v", err)
		}
	})

	t.Run("second maintenance process", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		child := startSQLiteRecoverySubprocess(t, "hold-maintenance", config.Path)
		child.awaitReady(t)
		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorUnavailable {
			child.releaseAndWait(t)
			t.Fatalf("FullIntegrityCheck(second maintenance) category = %v, want %v", got, policyengine.ErrorUnavailable)
		}
		child.releaseAndWait(t)
		if err := FullIntegrityCheck(context.Background(), config); err != nil {
			t.Fatalf("FullIntegrityCheck(after second maintenance) error = %v", err)
		}
	})
}

func assertSubprocessRecoveryFixture(t *testing.T, adapter *Store) {
	t.Helper()
	revision, err := subprocessRecoveryRevision()
	if err != nil {
		t.Fatalf("rebuild expected revision: %v", err)
	}
	stored, err := adapter.GetRevision(context.Background(), mustSubprocessGetRevisionRequest(t, revision.Metadata().ID()))
	if err != nil {
		t.Fatalf("GetRevision() error = %v", err)
	}
	if got, want := stored.Metadata().ID(), revision.Metadata().ID(); got != want {
		t.Fatalf("stored revision ID = %q, want %q", got, want)
	}

	resolved, err := adapter.Resolve(context.Background(), mustSubprocessResolveRequest(t))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if activation := resolved.Activation(); activation.RevisionID() != revision.Metadata().ID() || activation.Generation() != 1 {
		t.Fatalf("resolved activation = %#v, want revision %q generation 1", activation, revision.Metadata().ID())
	}

	request, tupleKey, err := subprocessRecoveryDataRequest(revision.Metadata().ID())
	if err != nil {
		t.Fatalf("rebuild expected data request: %v", err)
	}
	replay, err := adapter.WriteData(context.Background(), request)
	if err != nil {
		t.Fatalf("WriteData(replay) error = %v", err)
	}
	if replay.Generation() != 1 || !replay.Replayed() {
		t.Fatalf("WriteData(replay) = %#v, want generation 1 replay", replay)
	}

	snapshotRequest, err := store.NewSnapshotRequest("crash-recovery", 1, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), snapshotRequest)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	defer func() { _ = snapshot.Close() }()
	query, err := store.NewTupleQuery(tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 1)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	result, err := snapshot.QueryTuples(context.Background(), query)
	if err != nil {
		t.Fatalf("QueryTuples() error = %v", err)
	}
	if subjects := result.Subjects(); len(subjects) != 1 || subjects[0].Type != "user" || subjects[0].ID != "subject" {
		t.Fatalf("recovered tuple subjects = %#v, want user:subject", subjects)
	}

	events := sqliteEventsForTest(t, adapter, "crash-recovery")
	if len(events) != 3 || events[0].Kind() != policyengine.StateEventRevisionPublished || events[1].Kind() != policyengine.StateEventSlotActivated || events[2].Kind() != policyengine.StateEventDataWritten {
		t.Fatalf("recovered events = %#v, want revision/activation/data sequence", events)
	}
}

func mustSubprocessGetRevisionRequest(t *testing.T, revisionID string) policyengine.GetRevisionRequest {
	t.Helper()
	request, err := policyengine.NewGetRevisionRequest("crash-recovery", revisionID)
	if err != nil {
		t.Fatalf("NewGetRevisionRequest() error = %v", err)
	}
	return request
}

func mustSubprocessResolveRequest(t *testing.T) policyengine.ResolveRequest {
	t.Helper()
	request, err := policyengine.NewResolveRequest("crash-recovery", "primary")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	return request
}
