package sqlite

import (
	"bytes"
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
	// This catches an offline checker that becomes the recovery/checkpoint step:
	// a committed hot WAL must stay byte-for-byte intact until the runtime opens
	// it directly and proves SQLite recovery can reconstruct public state.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	child := startSQLiteRecoverySubprocess(t, "committed", config.Path)
	child.awaitReady(t)
	if info, err := os.Stat(config.Path + "-wal"); err != nil || info.Size() == 0 {
		child.releaseAndWait(t)
		t.Fatalf("committed helper WAL = %v, %v; want non-empty WAL before crash", info, err)
	}
	child.releaseAndWait(t)
	before := snapshotHotWALArtifacts(t, config.Path)
	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("FullIntegrityCheck(after committed crash) error = %v", err)
	}
	after := snapshotHotWALArtifacts(t, config.Path)
	assertHotWALDurableStatePreserved(t, before, after)

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

type hotWALArtifact struct {
	exists bool
	bytes  []byte
}

func snapshotHotWALArtifacts(t *testing.T, databasePath string) map[string]hotWALArtifact {
	t.Helper()
	artifacts := make(map[string]hotWALArtifact, 2)
	for _, suffix := range []string{"-wal", "-shm"} {
		contents, err := os.ReadFile(databasePath + suffix)
		if os.IsNotExist(err) {
			artifacts[suffix] = hotWALArtifact{}
			continue
		}
		if err != nil {
			t.Fatalf("read hot WAL artifact %q: %v", suffix, err)
		}
		artifacts[suffix] = hotWALArtifact{exists: true, bytes: contents}
	}
	if artifact := artifacts["-wal"]; !artifact.exists || len(artifact.bytes) == 0 {
		t.Fatalf("hot WAL snapshot = %#v, want a non-empty WAL before integrity check", artifact)
	}
	return artifacts
}

func assertHotWALDurableStatePreserved(t *testing.T, before, after map[string]hotWALArtifact) {
	t.Helper()
	originalWAL, currentWAL := before["-wal"], after["-wal"]
	if !originalWAL.exists || !currentWAL.exists || !bytes.Equal(originalWAL.bytes, currentWAL.bytes) {
		t.Fatalf("hot WAL changed across FullIntegrityCheck: before exists=%t bytes=%d, after exists=%t bytes=%d", originalWAL.exists, len(originalWAL.bytes), currentWAL.exists, len(currentWAL.bytes))
	}
	// SQLite's SHM file includes lock and wal-index bookkeeping. BEGIN EXCLUSIVE
	// is allowed to refresh those transient bytes, so the durable assertion is
	// that an existing sidecar remains present and non-empty; the direct Open
	// below proves SQLite can consume the sidecar and recover the original WAL.
	originalSHM, currentSHM := before["-shm"], after["-shm"]
	if originalSHM.exists && (!currentSHM.exists || len(currentSHM.bytes) == 0) {
		t.Fatalf("hot SHM sidecar was not preserved across FullIntegrityCheck: before exists=%t bytes=%d, after exists=%t bytes=%d", originalSHM.exists, len(originalSHM.bytes), currentSHM.exists, len(currentSHM.bytes))
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

	t.Run("subprocess raw SQLite writer", func(t *testing.T) {
		config := migratedIntegrityConfig(t)
		child := startSQLiteRecoverySubprocess(t, "hold-raw-writer", config.Path)
		child.awaitReady(t)
		if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorUnavailable {
			child.releaseAndWait(t)
			t.Fatalf("FullIntegrityCheck(external raw writer) category = %v, want %v", got, policyengine.ErrorUnavailable)
		}
		child.releaseAndWait(t)
		if err := FullIntegrityCheck(context.Background(), config); err != nil {
			t.Fatalf("FullIntegrityCheck(after external raw writer) error = %v", err)
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
	revision, err := expectedSubprocessRecoveryRevision()
	if err != nil {
		t.Fatalf("rebuild expected revision: %v", err)
	}
	stored, err := adapter.GetRevision(context.Background(), mustSubprocessGetRevisionRequest(t, revision.Metadata().ID()))
	if err != nil {
		t.Fatalf("GetRevision() error = %v", err)
	}
	wantMetadata, gotMetadata := revision.Metadata(), stored.Metadata()
	if gotMetadata.Namespace() != wantMetadata.Namespace() || gotMetadata.ID() != wantMetadata.ID() || !gotMetadata.PublishedAt().Equal(wantMetadata.PublishedAt()) {
		t.Fatalf("stored revision metadata = namespace %q ID %q published %s, want namespace %q ID %q published %s", gotMetadata.Namespace(), gotMetadata.ID(), gotMetadata.PublishedAt(), wantMetadata.Namespace(), wantMetadata.ID(), wantMetadata.PublishedAt())
	}
	if got, want := stored.Artifact(), revision.Artifact(); !bytes.Equal(got, want) {
		t.Fatalf("stored revision artifact = %x, want %x", got, want)
	}
	wantProvenance, gotProvenance := revision.Provenance(), stored.Provenance()
	if gotProvenance.SourceName() != wantProvenance.SourceName() || !bytes.Equal(gotProvenance.OriginalSource(), wantProvenance.OriginalSource()) || gotProvenance.OriginalSourceDigest() != wantProvenance.OriginalSourceDigest() || !gotProvenance.Valid() || !stored.Valid() {
		t.Fatalf("stored revision provenance or validity differs after recovery")
	}

	resolved, err := adapter.Resolve(context.Background(), mustSubprocessResolveRequest(t))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if activation := resolved.Activation(); activation.Namespace() != "crash-recovery" || activation.Slot() != "primary" || activation.RevisionID() != revision.Metadata().ID() || activation.Generation() != 1 || !activation.ActivatedAt().Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("resolved activation differs from the committed public value")
	}

	generationRequest, err := policyengine.NewGetDataGenerationRequest("crash-recovery")
	if err != nil {
		t.Fatalf("NewGetDataGenerationRequest() error = %v", err)
	}
	generation, err := adapter.GetDataGeneration(context.Background(), generationRequest)
	if err != nil {
		t.Fatalf("GetDataGeneration() error = %v", err)
	}
	if generation.Generation() != 1 || !generation.Valid() {
		t.Fatalf("recovered data generation = %#v, want valid generation 1", generation)
	}

	request, tupleKey, err := expectedSubprocessRecoveryDataRequest(revision.Metadata().ID())
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

	readAt := time.Unix(100, 0).UTC()
	snapshotRequest, err := store.NewSnapshotRequest("crash-recovery", 1, readAt)
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), snapshotRequest)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	defer func() { _ = snapshot.Close() }()
	if snapshot.Namespace() != "crash-recovery" || snapshot.Generation() != 1 || snapshot.MinimumGeneration() != 1 || !snapshot.ReadAt().Equal(readAt) {
		t.Fatalf("recovered snapshot provenance differs from requested committed view")
	}
	query, err := store.NewTupleQuery(tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 1)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	result, err := snapshot.QueryTuples(context.Background(), query)
	if err != nil {
		t.Fatalf("QueryTuples() error = %v", err)
	}
	if gotQuery := result.Query(); gotQuery.Resource() != tupleKey.Tuple().Resource || gotQuery.Relation() != tupleKey.Tuple().Relation || gotQuery.Limit() != 1 || !result.Valid() {
		t.Fatalf("recovered tuple result provenance differs from the exact query")
	}
	if subjects := result.Subjects(); len(subjects) != 1 || subjects[0] != tupleKey.Tuple().Subject {
		t.Fatalf("recovered tuple subjects = %#v, want %#v", subjects, tupleKey.Tuple().Subject)
	}

	events := sqliteEventsForTest(t, adapter, "crash-recovery")
	wantEvents := []struct {
		kind           policyengine.StateEventKind
		revisionID     string
		slot           string
		slotGeneration uint64
		dataGeneration uint64
	}{
		{kind: policyengine.StateEventRevisionPublished, revisionID: revision.Metadata().ID()},
		{kind: policyengine.StateEventSlotActivated, revisionID: revision.Metadata().ID(), slot: "primary", slotGeneration: 1},
		{kind: policyengine.StateEventDataWritten, dataGeneration: 1},
	}
	if len(events) != len(wantEvents) {
		t.Fatalf("recovered event count = %d, want %d", len(events), len(wantEvents))
	}
	for index, want := range wantEvents {
		event := events[index]
		if event.Namespace() != "crash-recovery" || event.Kind() != want.kind || event.RevisionID() != want.revisionID || event.Slot() != want.slot || event.SlotGeneration() != want.slotGeneration || event.DataGeneration() != want.dataGeneration || !event.OccurredAt().Equal(time.Unix(0, 0).UTC()) || event.Cursor() == "" {
			t.Fatalf("recovered event %d differs from the committed public value", index)
		}
		cursor, err := adapter.decodeCursor(event.Cursor(), cursorDomainEvent, "crash-recovery", "")
		if err != nil || cursor.position != uint64(index+1) || cursor.boundary != 0 || cursor.revisionID != "" || !cursor.revisionPublishedAt.IsZero() {
			t.Fatalf("recovered event %d cursor = %#v, %v; want exact event cursor position %d", index, cursor, err, index+1)
		}
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
