package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestOpenSnapshotPinsCommittedViewAndWaitsForMinimumGeneration(t *testing.T) {
	// This catches a snapshot that opens a fresh read for each call, loses a
	// generation notification, or treats a reached lower bound as an exact one.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = adapter.Close() }()

	revision := newSQLiteRevisionWrite(t, "snapshot-pin", "snapshot.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	first := newSQLiteDataRequest(t, "snapshot-pin", revision.Metadata().ID(), 0, "first", "one")
	if _, err := adapter.WriteData(context.Background(), first); err != nil {
		t.Fatalf("WriteData(first) error = %v", err)
	}

	readAt := time.Unix(100, 0).UTC()
	snapshotRequest, err := store.NewSnapshotRequest("snapshot-pin", 1, readAt)
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	pinned, err := adapter.OpenSnapshot(context.Background(), snapshotRequest)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	defer func() { _ = pinned.Close() }()
	if pinned.Generation() != 1 || pinned.MinimumGeneration() != 1 || !pinned.ReadAt().Equal(readAt) {
		t.Fatalf("pinned metadata = %d/%d/%v", pinned.Generation(), pinned.MinimumGeneration(), pinned.ReadAt())
	}

	second := newSQLiteDataRequest(t, "snapshot-pin", revision.Metadata().ID(), 1, "second", "two")
	if response, err := adapter.WriteData(context.Background(), second); err != nil || response.Generation() != 2 {
		t.Fatalf("WriteData(second) = %#v, %v", response, err)
	}
	attributeKey, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc"}, "classification", mustSQLiteStringValue(t, "ignored"))
	if err != nil {
		t.Fatalf("NewAttribute() error = %v", err)
	}
	key, err := policyengine.NewAttributeKeyPath(attributeKey.Entity(), attributeKey.Path())
	if err != nil {
		t.Fatalf("NewAttributeKeyPath() error = %v", err)
	}
	firstValue, err := pinned.GetAttribute(context.Background(), key)
	if err != nil {
		t.Fatalf("pinned GetAttribute() error = %v", err)
	}
	text, found := firstValue.Value()
	valueText, isString := text.StringValue()
	if !found || !isString || valueText != "one" {
		t.Fatalf("pinned value = %#v/%t, want one", text, found)
	}

	minimumRequest, err := store.NewSnapshotRequest("snapshot-pin", 3, readAt)
	if err != nil {
		t.Fatalf("NewSnapshotRequest(minimum) error = %v", err)
	}
	waitContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitResult := make(chan struct {
		snapshot store.Snapshot
		err      error
	}, 1)
	go func() {
		snapshot, openErr := adapter.OpenSnapshot(waitContext, minimumRequest)
		waitResult <- struct {
			snapshot store.Snapshot
			err      error
		}{snapshot: snapshot, err: openErr}
	}()
	third := newSQLiteDataRequest(t, "snapshot-pin", revision.Metadata().ID(), 2, "third", "three")
	if _, err := adapter.WriteData(context.Background(), third); err != nil {
		t.Fatalf("WriteData(third) error = %v", err)
	}
	result := <-waitResult
	if result.err != nil {
		t.Fatalf("minimum OpenSnapshot() error = %v", result.err)
	}
	if result.snapshot.Generation() != 3 {
		t.Fatalf("minimum snapshot generation = %d, want 3", result.snapshot.Generation())
	}
	if err := result.snapshot.Close(); err != nil {
		t.Fatalf("minimum snapshot Close() error = %v", err)
	}
}

func TestSnapshotCloseIsIdempotentAndBlocksLateReads(t *testing.T) {
	// This catches a close that releases its transaction before admitted reads,
	// leaks reader permits, or continues to allow new snapshot queries.
	adapter := openMigratedStoreForTest(t)
	revision := newSQLiteRevisionWrite(t, "snapshot-close", "snapshot.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	if _, err := adapter.WriteData(context.Background(), newSQLiteDataRequest(t, "snapshot-close", revision.Metadata().ID(), 0, "one", "value")); err != nil {
		t.Fatalf("WriteData() error = %v", err)
	}
	request, err := store.NewSnapshotRequest("snapshot-close", 1, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	query, err := store.NewTupleQuery(dsl.EntityRef{Type: "document", ID: "doc"}, "viewer", 1)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	if _, err := snapshot.QueryTuples(context.Background(), query); categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("late QueryTuples() category = %v, want FAILED_PRECONDITION", categoryOf(err))
	}
}

func TestTwoPinnedSnapshotsDoNotBlockAWALDataCommit(t *testing.T) {
	// Two retained read transactions consume the entire configured reader pool,
	// yet WAL lets the independent serialized writer commit the next generation.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = adapter.Close() }()
	revision := newSQLiteRevisionWrite(t, "wal-snapshots", "wal.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	first := newSQLiteDataRequest(t, "wal-snapshots", revision.Metadata().ID(), 0, "first", "one")
	if _, err := adapter.WriteData(context.Background(), first); err != nil {
		t.Fatalf("WriteData(first) error = %v", err)
	}
	read, err := store.NewSnapshotRequest("wal-snapshots", 0, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	left, err := adapter.OpenSnapshot(context.Background(), read)
	if err != nil {
		t.Fatalf("left OpenSnapshot() error = %v", err)
	}
	defer func() { _ = left.Close() }()
	right, err := adapter.OpenSnapshot(context.Background(), read)
	if err != nil {
		t.Fatalf("right OpenSnapshot() error = %v", err)
	}
	defer func() { _ = right.Close() }()

	writeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan struct {
		response policyengine.WriteDataResponse
		err      error
	}, 1)
	second := newSQLiteDataRequest(t, "wal-snapshots", revision.Metadata().ID(), 1, "second", "two")
	go func() {
		response, writeErr := adapter.WriteData(writeContext, second)
		result <- struct {
			response policyengine.WriteDataResponse
			err      error
		}{response: response, err: writeErr}
	}()
	committed := <-result
	if committed.err != nil || committed.response.Generation() != 2 || committed.response.Replayed() {
		t.Fatalf("WriteData(second) = %#v, %v", committed.response, committed.err)
	}
}

func TestStoreCloseDrainsPinnedSnapshotsBeforeReleasingMaintenanceLock(t *testing.T) {
	// This catches Store.Close releasing the runtime shared lock and pools while
	// a snapshot still owns a checked-out SQLite read transaction. Maintenance
	// must remain blocked while the runtime is live, then succeed only after
	// Store.Close has made the retained snapshot unusable and drained it.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = adapter.Close() }()
	request, err := store.NewSnapshotRequest("store-close-snapshot", 0, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	defer func() { _ = snapshot.Close() }()

	if output, lockErr := runLockHelper(config.Path, "exclusive"); lockErr == nil {
		t.Fatalf("maintenance lock acquired while runtime snapshot was live: %q", output)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Store.Close() error = %v", err)
	}
	query, err := store.NewTupleQuery(dsl.EntityRef{Type: "document", ID: "doc"}, "viewer", 1)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	if _, err := snapshot.QueryTuples(context.Background(), query); categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("snapshot query after Store.Close category = %v, want FAILED_PRECONDITION", categoryOf(err))
	}

	maintenanceContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ApplyMigrations(maintenanceContext, config); err != nil {
		t.Fatalf("ApplyMigrations() after Store.Close error = %v", err)
	}
}

func TestSnapshotCloseReportsRollbackFailureAndDiscardsReaderConnection(t *testing.T) {
	// This catches close paths that hide a real ROLLBACK failure, return a
	// different result on repeated Close, or put a transaction-uncertain reader
	// connection back into the pool for later snapshots.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.MaxReaders = 1
	adapter, hooks := openMigratedStoreWithHooksForTest(t, config)
	request, err := store.NewSnapshotRequest("rollback-close", 0, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	connectionsBefore := hooks.readerConnectionCount()
	closesBefore := hooks.readerConnectionCloseCount()
	hooks.armNextSnapshotRollbackFailure()
	firstClose := snapshot.Close()
	if categoryOf(firstClose) != policyengine.ErrorUnavailable {
		t.Fatalf("first snapshot Close() category = %v, want UNAVAILABLE", categoryOf(firstClose))
	}
	if repeatedClose := snapshot.Close(); repeatedClose != firstClose {
		t.Fatalf("repeated snapshot Close() = %v, want original %v", repeatedClose, firstClose)
	}
	if got := hooks.readerConnectionCloseCount(); got <= closesBefore {
		t.Fatalf("reader physical closes = %d, want discard after rollback failure (before %d)", got, closesBefore)
	}

	replacement, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatalf("replacement OpenSnapshot() error = %v", err)
	}
	defer func() { _ = replacement.Close() }()
	if got := hooks.readerConnectionCount(); got <= connectionsBefore {
		t.Fatalf("reader physical connections = %d, want fresh connection after discard (before %d)", got, connectionsBefore)
	}
}
