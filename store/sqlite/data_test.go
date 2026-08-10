package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
	"github.com/cadrena/policy-engine/store"
)

func TestOpenRequiresAnExistingMigratedDatabase(t *testing.T) {
	// This catches a public runtime opener that creates, migrates, or repairs a
	// database rather than refusing a missing or unmigrated durable store.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if opened, err := Open(config); opened != nil || categoryOf(err) != policyengine.ErrorFailedPrecondition {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("Open(missing) = %v, %v; want nil FAILED_PRECONDITION", opened, err)
	}
	if _, err := os.Stat(config.Path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("Open(missing) lock sidecar stat error = %v; want no sidecar", err)
	}

	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	opened, err := Open(config)
	if err != nil {
		t.Fatalf("Open(migrated) error = %v", err)
	}
	defer func() { _ = opened.Close() }()
	var _ store.Store = opened
}

func TestOpenValidatesUnmigratedDatabaseBeforeStartingWritableRuntime(t *testing.T) {
	// This catches Open() starting a writer with journal_mode=WAL before it has
	// proved the existing database is migrated. Such a rejected open must leave
	// the file, SQLite sidecars, and journal mode unchanged and release its
	// temporary runtime lock.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	bootstrap := openRawSQLite(t, config.Path)
	if _, err := bootstrap.Exec("CREATE TABLE unmigrated_marker(value TEXT NOT NULL)"); err != nil {
		_ = bootstrap.Close()
		t.Fatalf("CREATE TABLE error = %v", err)
	}
	var initialJournal string
	if err := bootstrap.QueryRow("PRAGMA journal_mode=DELETE").Scan(&initialJournal); err != nil {
		_ = bootstrap.Close()
		t.Fatalf("PRAGMA journal_mode=DELETE error = %v", err)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatalf("bootstrap Close() error = %v", err)
	}
	if initialJournal != "delete" {
		t.Fatalf("initial journal mode = %q, want delete", initialJournal)
	}

	beforeBytes, err := os.ReadFile(config.Path)
	if err != nil {
		t.Fatalf("ReadFile(before) error = %v", err)
	}
	beforeArtifacts := sqliteDatabaseArtifactsForTest(t, config.Path)
	if beforeMode := sqliteJournalModeForTest(t, config.Path); beforeMode != "delete" {
		t.Fatalf("journal mode before Open = %q, want delete", beforeMode)
	}

	opened, err := Open(config)
	if opened != nil {
		_ = opened.Close()
		t.Fatalf("Open(unmigrated) returned a store with error %v", err)
	}
	if categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("Open(unmigrated) category = %v, want FAILED_PRECONDITION", categoryOf(err))
	}

	afterBytes, err := os.ReadFile(config.Path)
	if err != nil {
		t.Fatalf("ReadFile(after) error = %v", err)
	}
	if !bytes.Equal(afterBytes, beforeBytes) {
		t.Fatal("Open(unmigrated) changed database bytes before rejecting it")
	}
	if afterArtifacts := sqliteDatabaseArtifactsForTest(t, config.Path); !reflect.DeepEqual(afterArtifacts, beforeArtifacts) {
		t.Fatalf("Open(unmigrated) SQLite artifacts = %q, want %q", afterArtifacts, beforeArtifacts)
	}
	if afterMode := sqliteJournalModeForTest(t, config.Path); afterMode != "delete" {
		t.Fatalf("journal mode after Open = %q, want delete", afterMode)
	}

	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		t.Fatalf("newAdvisoryLock() error = %v", err)
	}
	defer func() { _ = lock.Close() }()
	lockContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := lock.LockExclusive(lockContext); err != nil {
		t.Fatalf("exclusive lock after rejected Open() error = %v", err)
	}
}

func TestDataCodecsRejectInvalidTagsCountsAndOversizedLengthHeaders(t *testing.T) {
	// This catches a decoder that trusts a tag/count/declared length before
	// validation, allocates a claimed payload, or bypasses public constructors
	// after a structurally valid durable decode.
	const (
		tupleResourceTypeCanary   = "resource-type-canary"
		attributeEntityTypeCanary = "entity-type-canary"
		attributePathCanary       = "path-segment-canary"
	)
	for _, test := range []struct {
		name     string
		decode   func() error
		canaries []string
	}{
		{name: "tuple version", decode: func() error { _, err := decodeTupleKey([]byte{codecVersion + 1}); return err }},
		{name: "tuple resource type rejected by constructor", canaries: []string{tupleResourceTypeCanary}, decode: func() error {
			// Version and every string16 length are hand-written. The resource
			// type is a valid-length UTF-8 string with an unsafe leading NUL;
			// all other tuple fields are valid so NewTupleKey is the rejection.
			_, err := decodeTupleKey([]byte{
				1,
				0, 21, 0, 'r', 'e', 's', 'o', 'u', 'r', 'c', 'e', '-', 't', 'y', 'p', 'e', '-', 'c', 'a', 'n', 'a', 'r', 'y',
				0, 18, 'r', 'e', 's', 'o', 'u', 'r', 'c', 'e', '-', 'i', 'd', '-', 'c', 'a', 'n', 'a', 'r', 'y',
				0, 6, 'v', 'i', 'e', 'w', 'e', 'r',
				0, 5, 'g', 'r', 'o', 'u', 'p',
				0, 17, 's', 'u', 'b', 'j', 'e', 'c', 't', '-', 'i', 'd', '-', 'c', 'a', 'n', 'a', 'r', 'y',
				0, 6, 'm', 'e', 'm', 'b', 'e', 'r',
			})
			return err
		}},
		{name: "attribute value tag", decode: func() error { _, err := decodeAttributeValue([]byte{codecVersion, 0xff}); return err }},
		{name: "attribute boolean payload", decode: func() error {
			_, err := decodeAttributeValue([]byte{codecVersion, attributeValueBoolean, 2})
			return err
		}},
		{name: "attribute string oversized header", decode: func() error {
			_, err := decodeAttributeValue([]byte{codecVersion, attributeValueString, 0x00, 0x01, 0x00, 0x01})
			return err
		}},
		{name: "attribute path zero count", decode: func() error { _, err := decodeAttributePath([]byte{codecVersion, 0, 0, 0, 0}); return err }},
		{name: "attribute path oversized count", decode: func() error { _, err := decodeAttributePath([]byte{codecVersion, 0x00, 0x01, 0x86, 0xa1}); return err }},
		{name: "attribute path segment rejected by constructor", canaries: []string{attributePathCanary}, decode: func() error {
			// A one-segment V1 path with the exact 19-byte segment is structurally
			// complete. Its hyphens violate the public DSL-identifier rule.
			_, err := decodeAttributePath([]byte{
				1, 0, 0, 0, 1, 0, 19,
				'p', 'a', 't', 'h', '-', 's', 'e', 'g', 'm', 'e', 'n', 't', '-', 'c', 'a', 'n', 'a', 'r', 'y',
			})
			return err
		}},
		{name: "attribute key oversized nested payload", decode: func() error {
			_, err := decodeAttributeKey([]byte{codecVersion, 0, 1, 'e', 0, 1, 'i', 0x00, 0x40, 0x00, 0x01})
			return err
		}},
		{name: "attribute entity type rejected by constructor", canaries: []string{attributeEntityTypeCanary}, decode: func() error {
			// The outer key and its 17-byte nested V1 path are fully formed.
			// Only the leading NUL in the entity type is semantically invalid.
			_, err := decodeAttributeKey([]byte{
				1,
				0, 19, 0, 'e', 'n', 't', 'i', 't', 'y', '-', 't', 'y', 'p', 'e', '-', 'c', 'a', 'n', 'a', 'r', 'y',
				0, 16, 'e', 'n', 't', 'i', 't', 'y', '-', 'i', 'd', '-', 'c', 'a', 'n', 'a', 'r', 'y',
				0, 0, 0, 17,
				1, 0, 0, 0, 1, 0, 10, 'v', 'a', 'l', 'i', 'd', '_', 'p', 'a', 't', 'h',
			})
			return err
		}},
		{name: "idempotency response tag", decode: func() error { _, err := decodeIdempotencyResponse([]byte{codecVersion, 0}, false); return err }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := test.decode()
			if err == nil {
				t.Fatal("decoder accepted invalid durable bytes")
			}
			if categoryOf(err) != policyengine.ErrorIntegrity {
				t.Fatalf("decoder category = %v, want INTEGRITY", categoryOf(err))
			}
			if got := err.Error(); got != policyengine.ErrorIntegrity.String() {
				t.Fatalf("decoder error = %q, want sanitized INTEGRITY", got)
			}
			for _, canary := range test.canaries {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("decoder error leaked invalid durable canary %q in %q", canary, err)
				}
			}
		})
	}
}

func TestTupleResourceRelationQueryPlanUsesMigrationIndex(t *testing.T) {
	// This catches a resource/relation lookup that loses the migration's exact
	// prefix index and silently turns bounded snapshot queries into scans. The
	// public API intentionally has no subject-filter query shape to invent here.
	adapter := openMigratedStoreForTest(t)
	revision := newSQLiteRevisionWrite(t, "tuple-plan", "plan.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request, tupleKey := newSQLiteTupleWriteRequest(t, "tuple-plan", revision.Metadata().ID(), "tuple-plan-key")
	if _, err := adapter.WriteData(context.Background(), request); err != nil {
		t.Fatalf("WriteData() error = %v", err)
	}

	conn, release, err := adapter.db.acquireReaderConnection(context.Background())
	if err != nil {
		t.Fatalf("acquireReaderConnection() error = %v", err)
	}
	defer func() { _ = release() }()
	rows, err := conn.QueryContext(context.Background(), `EXPLAIN QUERY PLAN SELECT tuple_key, subject_type, subject_id, subject_relation, relation, resource_type, resource_id, expires_at_ns FROM tuples
WHERE namespace = ? AND resource_type = ? AND resource_id = ? AND relation = ?
AND (expires_at_ns IS NULL OR expires_at_ns > ?)
ORDER BY subject_type, subject_id, subject_relation LIMIT ?`,
		"tuple-plan", tupleKey.Tuple().Resource.Type, tupleKey.Tuple().Resource.ID, tupleKey.Tuple().Relation, time.Unix(100, 0).UTC().UnixNano(), 2,
	)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN error = %v", err)
	}
	defer func() { _ = rows.Close() }()
	usedIndex := false
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("EXPLAIN row scan error = %v", err)
		}
		usedIndex = usedIndex || strings.Contains(detail, "idx_tuples_namespace_resource_relation_subject")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("EXPLAIN rows error = %v", err)
	}
	if !usedIndex {
		t.Fatal("resource/relation tuple query did not use idx_tuples_namespace_resource_relation_subject")
	}
}

func sqliteDatabaseArtifactsForTest(t testing.TB, path string) map[string][]byte {
	t.Helper()
	artifacts := make(map[string][]byte)
	for _, suffix := range []string{"-journal", "-shm", "-wal"} {
		value, err := os.ReadFile(path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", suffix, err)
		}
		artifacts[suffix] = value
	}
	return artifacts
}

func sqliteJournalModeForTest(t testing.TB, path string) string {
	t.Helper()
	canonicalPath, err := canonicalDatabasePath(path)
	if err != nil {
		t.Fatalf("canonicalize read-only SQLite database path: %v", err)
	}
	database, err := sql.Open(moderncsqlite.DriverName, "file:"+canonicalPath+"?mode=ro&_query_only=1")
	if err != nil {
		t.Fatalf("sql.Open(read-only) error = %v", err)
	}
	defer func() { _ = database.Close() }()
	var mode string
	if err := database.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode error = %v", err)
	}
	return mode
}

func TestCanonicalDataCodecsRoundTripAndRejectTrailingData(t *testing.T) {
	// This catches a codec that uses unordered/ambiguous bytes, skips public
	// constructors on decode, aliases input storage, or accepts appended data.
	tuple := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "roadmap"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "group", ID: "engineering", Relation: "member"},
	}
	tupleBytes, err := encodeTupleKey(tuple)
	if err != nil {
		t.Fatalf("encodeTupleKey() error = %v", err)
	}
	if repeated, err := encodeTupleKey(tuple); err != nil || !bytes.Equal(tupleBytes, repeated) {
		t.Fatalf("tuple encoding is not deterministic: %x / %x, %v", tupleBytes, repeated, err)
	}
	decodedTuple, err := decodeTupleKey(tupleBytes)
	if err != nil || decodedTuple != tuple {
		t.Fatalf("decodeTupleKey() = %#v, %v; want %#v", decodedTuple, err, tuple)
	}
	if _, err := decodeTupleKey(append(append([]byte(nil), tupleBytes...), 0)); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("decodeTupleKey(trailing) category = %v, want INTEGRITY", categoryOf(err))
	}

	entity := dsl.EntityRef{Type: "document", ID: "roadmap"}
	key, err := policyengine.NewAttributeKeyPath(entity, []string{"metadata", "classification"})
	if err != nil {
		t.Fatalf("NewAttributeKeyPath() error = %v", err)
	}
	keyBytes, err := encodeAttributeKey(key)
	if err != nil {
		t.Fatalf("encodeAttributeKey() error = %v", err)
	}
	decodedKey, err := decodeAttributeKey(keyBytes)
	if err != nil || decodedKey.Entity() != entity || stringSliceString(decodedKey.Path()) != "metadata/classification" {
		t.Fatalf("decodeAttributeKey() = %#v, %v", decodedKey, err)
	}
	if _, err := decodeAttributeKey(append(append([]byte(nil), keyBytes...), 0)); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("decodeAttributeKey(trailing) category = %v, want INTEGRITY", categoryOf(err))
	}
	pathBytes, err := encodeAttributePath(key.Path())
	if err != nil {
		t.Fatalf("encodeAttributePath() error = %v", err)
	}
	decodedPath, err := decodeAttributePath(pathBytes)
	if err != nil || stringSliceString(decodedPath) != "metadata/classification" {
		t.Fatalf("decodeAttributePath() = %#v, %v", decodedPath, err)
	}
	if _, err := decodeAttributePath(append(append([]byte(nil), pathBytes...), 0)); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("decodeAttributePath(trailing) category = %v, want INTEGRITY", categoryOf(err))
	}

	for _, value := range []policyengine.Value{
		mustSQLiteStringValue(t, "confidential"),
		policyengine.NewIntegerValue(-17),
		policyengine.NewBooleanValue(true),
		policyengine.NewNullValue(),
	} {
		encoded, encodeErr := encodeAttributeValue(value)
		if encodeErr != nil {
			t.Fatalf("encodeAttributeValue(%v) error = %v", value.Kind(), encodeErr)
		}
		decoded, decodeErr := decodeAttributeValue(encoded)
		if decodeErr != nil || decoded != value {
			t.Fatalf("decodeAttributeValue(%v) = %#v, %v", value.Kind(), decoded, decodeErr)
		}
		if _, decodeErr := decodeAttributeValue(append(encoded, 0)); categoryOf(decodeErr) != policyengine.ErrorIntegrity {
			t.Fatalf("decodeAttributeValue(%v, trailing) category = %v, want INTEGRITY", value.Kind(), categoryOf(decodeErr))
		}
	}

	request := newSQLiteDataRequest(t, "codec-data", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, "codec-key", "classified")
	_, fingerprint, err := store.FingerprintWriteData(request)
	if err != nil {
		t.Fatalf("FingerprintWriteData() error = %v", err)
	}
	fingerprintBytes, err := encodeIdempotencyFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("encodeIdempotencyFingerprint() error = %v", err)
	}
	decodedFingerprint, err := decodeIdempotencyFingerprint(fingerprintBytes)
	if err != nil || !bytes.Equal(decodedFingerprint, fingerprint.Bytes()) {
		t.Fatalf("decodeIdempotencyFingerprint() = %x, %v", decodedFingerprint, err)
	}
	fingerprintBeforeMutation := append([]byte(nil), fingerprintBytes...)
	decodedFingerprint[0] ^= 0xff
	if !bytes.Equal(fingerprintBytes, fingerprintBeforeMutation) {
		t.Fatal("decodeIdempotencyFingerprint() aliased its encoded input")
	}
	if _, err := decodeIdempotencyFingerprint(append(append([]byte(nil), fingerprintBytes...), 0)); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("decodeIdempotencyFingerprint(trailing) category = %v, want INTEGRITY", categoryOf(err))
	}
	response, err := policyengine.NewWriteDataResponse(7, false)
	if err != nil {
		t.Fatalf("NewWriteDataResponse() error = %v", err)
	}
	responseBytes, err := encodeIdempotencyResponse(response)
	if err != nil {
		t.Fatalf("encodeIdempotencyResponse() error = %v", err)
	}
	decodedResponse, err := decodeIdempotencyResponse(responseBytes, false)
	if err != nil || decodedResponse.Generation() != 7 || decodedResponse.Replayed() {
		t.Fatalf("decodeIdempotencyResponse() = %#v, %v", decodedResponse, err)
	}
	if _, err := decodeIdempotencyResponse(append(append([]byte(nil), responseBytes...), 0), false); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("decodeIdempotencyResponse(trailing) category = %v, want INTEGRITY", categoryOf(err))
	}
}

func TestWriteDataPersistsActiveFactsAndPinsExpiryToSnapshotReadAt(t *testing.T) {
	// This catches mutation code that does not atomically persist facts or uses
	// wall clock time instead of the snapshot's caller-captured ReadAt value.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = adapter.Close() }()

	revision := newSQLiteRevisionWrite(t, "data-persist", "data.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	resource := dsl.EntityRef{Type: "document", ID: "roadmap"}
	before := time.Unix(99, 0).UTC()
	after := time.Unix(101, 0).UTC()
	activeTuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: resource, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "active"},
	}, &after)
	if err != nil {
		t.Fatalf("NewRelationshipTuple(active) error = %v", err)
	}
	expiredTuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: resource, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "expired"},
	}, &before)
	if err != nil {
		t.Fatalf("NewRelationshipTuple(expired) error = %v", err)
	}
	attribute, err := policyengine.NewAttributePath(resource, []string{"metadata", "classification"}, mustSQLiteStringValue(t, "internal"))
	if err != nil {
		t.Fatalf("NewAttributePath() error = %v", err)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "data-persist", ValidationRevisionID: revision.Metadata().ID(), IdempotencyKey: "first",
		TupleWrites: []policyengine.RelationshipTuple{activeTuple, expiredTuple}, AttributeWrites: []policyengine.Attribute{attribute},
	})
	if err != nil {
		t.Fatalf("NewWriteDataRequest() error = %v", err)
	}
	if response, err := adapter.WriteData(context.Background(), request); err != nil || response.Generation() != 1 || response.Replayed() {
		t.Fatalf("WriteData() = %#v, %v", response, err)
	}

	readAt := time.Unix(100, 0).UTC()
	snapshotRequest, err := store.NewSnapshotRequest("data-persist", 1, readAt)
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	snapshot, err := adapter.OpenSnapshot(context.Background(), snapshotRequest)
	if err != nil {
		t.Fatalf("OpenSnapshot() error = %v", err)
	}
	defer func() { _ = snapshot.Close() }()
	query, err := store.NewTupleQuery(resource, "viewer", 2)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	result, err := snapshot.QueryTuples(context.Background(), query)
	if err != nil || len(result.Subjects()) != 1 || result.Subjects()[0].ID != "active" {
		t.Fatalf("QueryTuples() = %#v, %v; want active only", result, err)
	}
	key, err := policyengine.NewAttributeKeyPath(resource, []string{"metadata", "classification"})
	if err != nil {
		t.Fatalf("NewAttributeKeyPath() error = %v", err)
	}
	gotAttribute, err := snapshot.GetAttribute(context.Background(), key)
	if err != nil || !gotAttribute.Found() {
		t.Fatalf("GetAttribute() = %#v, %v", gotAttribute, err)
	}
	ancestor, err := policyengine.NewAttributeKey(resource, "metadata")
	if err != nil {
		t.Fatalf("NewAttributeKey() error = %v", err)
	}
	if found, err := snapshot.HasAttributeDescendant(context.Background(), ancestor); err != nil || !found {
		t.Fatalf("HasAttributeDescendant() = %t, %v; want true", found, err)
	}
}

func TestWriteDataWithNilLifecycleObserverUsesNormalCommitPath(t *testing.T) {
	// The private observer seam is nil in production. This regression proves
	// adding the data pre-admission milestone does not change an ordinary write.
	adapter := openMigratedStoreForTest(t)
	if adapter.revisions.observer != nil {
		t.Fatal("new Store unexpectedly has a lifecycle observer")
	}
	revision := newSQLiteRevisionWrite(t, "nil-observer", "normal.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request := newSQLiteDataRequest(t, "nil-observer", revision.Metadata().ID(), 0, "normal-key", "normal")
	response, err := adapter.WriteData(context.Background(), request)
	if err != nil || response.Generation() != 1 || response.Replayed() {
		t.Fatalf("WriteData() = %#v, %v", response, err)
	}
	if adapter.revisions.observer != nil {
		t.Fatal("ordinary WriteData left a lifecycle observer installed")
	}
}

func TestSnapshotRejectsCorruptCanonicalTupleStorage(t *testing.T) {
	// A matching index row is not trusted solely because its SQL filters match:
	// the persisted tuple key must also decode to the selected canonical tuple.
	adapter := openMigratedStoreForTest(t)
	revision := newSQLiteRevisionWrite(t, "tuple-integrity", "tuple.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request, tupleKey := newSQLiteTupleWriteRequest(t, "tuple-integrity", revision.Metadata().ID(), "tuple-key")
	if _, err := adapter.WriteData(context.Background(), request); err != nil {
		t.Fatalf("WriteData() error = %v", err)
	}
	if err := adapter.db.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "UPDATE tuples SET tuple_key = ? WHERE namespace = ?", []byte{codecVersion}, "tuple-integrity")
		return mapError(ctx, err)
	}); err != nil {
		t.Fatalf("corrupt tuple row setup error = %v", err)
	}
	snapshotRequest, err := store.NewSnapshotRequest("tuple-integrity", 0, time.Unix(100, 0).UTC())
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
	if _, err := snapshot.QueryTuples(context.Background(), query); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("QueryTuples(corrupt tuple) category = %v, want INTEGRITY", categoryOf(err))
	}
}

func mustSQLiteStringValue(t testing.TB, value string) policyengine.Value {
	t.Helper()
	result, err := policyengine.NewStringValue(value)
	if err != nil {
		t.Fatalf("NewStringValue(%q) error = %v", value, err)
	}
	return result
}

func newSQLiteDataRequest(t testing.TB, namespace, revisionID string, expected uint64, key, value string) policyengine.WriteDataRequest {
	t.Helper()
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc"}, "classification", mustSQLiteStringValue(t, value))
	if err != nil {
		t.Fatalf("NewAttribute() error = %v", err)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: namespace, ValidationRevisionID: revisionID, ExpectedGeneration: expected, IdempotencyKey: key,
		AttributeWrites: []policyengine.Attribute{attribute},
	})
	if err != nil {
		t.Fatalf("NewWriteDataRequest() error = %v", err)
	}
	return request
}

func stringSliceString(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += "/"
		}
		result += value
	}
	return result
}
