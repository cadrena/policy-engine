package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
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
	var complete store.Store = opened
	if complete == nil {
		t.Fatal("Open(migrated) returned a nil complete store")
	}
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
