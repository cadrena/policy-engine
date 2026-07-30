package evaluator

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestAdapterRemainsPinnedAcrossConcurrentWrite(t *testing.T) {
	t.Parallel()
	adapter, err := memory.New()
	requireNoError(t, err)
	writeViewer(t, adapter, 0, "first", "alice")

	request, err := store.NewSnapshotRequest("tenant", 1, time.Unix(100, 0).UTC())
	requireNoError(t, err)
	snapshot, err := adapter.OpenSnapshot(context.Background(), request)
	requireNoError(t, err)
	t.Cleanup(func() { requireNoError(t, snapshot.Close()) })

	reader, err := NewSnapshotReader(snapshot, policyengine.ContextualData{})
	requireNoError(t, err)
	writeViewer(t, adapter, 1, "second", "bob")

	subjects, err := reader.ReadTuples(
		context.Background(),
		dsl.EntityRef{Type: "document", ID: "doc-1"},
		"viewer",
	)
	requireNoError(t, err)
	assertSubjects(t, subjects, "user:alice")
}

func TestSnapshotReaderUnionsContextualAndPersistentSubjectsCanonically(t *testing.T) {
	adapter, err := memory.New()
	requireNoError(t, err)
	writeViewer(t, adapter, 0, "persisted", "bob")
	snapshot := openSnapshot(t, adapter, 1)
	t.Cleanup(func() { requireNoError(t, snapshot.Close()) })

	contextual := mustContextualData(t, []string{"carol", "alice", "bob"}, nil)
	reader, err := NewSnapshotReader(snapshot, contextual)
	requireNoError(t, err)
	var _ dsl.TupleReader = reader

	subjects, err := reader.ReadTuples(context.Background(), dsl.EntityRef{Type: "document", ID: "doc-1"}, "viewer")
	requireNoError(t, err)
	assertSubjects(t, subjects, "user:alice", "user:bob", "user:carol")
}

func TestResolveArgumentsMapsOnlyDSLPrimitiveValues(t *testing.T) {
	text, err := policyengine.NewStringValue("private")
	requireNoError(t, err)
	resolved, err := ResolveArguments(map[string]policyengine.Value{
		"text":    text,
		"integer": policyengine.NewIntegerValue(7),
		"boolean": policyengine.NewBooleanValue(true),
		"null":    policyengine.NewNullValue(),
	})
	requireNoError(t, err)
	want := map[string]any{"text": "private", "integer": int64(7), "boolean": true, "null": nil}
	if !reflect.DeepEqual(resolved, want) {
		t.Fatalf("ResolveArguments() = %#v, want %#v", resolved, want)
	}

	_, err = ResolveArguments(map[string]policyengine.Value{"invalid": {}})
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
}

func TestSnapshotReaderResolveAttributeUsesContextualValueAndRejectsPersistentConflict(t *testing.T) {
	adapter, err := memory.New()
	requireNoError(t, err)
	persisted, err := policyengine.NewStringValue("internal")
	requireNoError(t, err)
	writeAttribute(t, adapter, 0, "persisted", []string{"classification"}, persisted)
	snapshot := openSnapshot(t, adapter, 1)
	t.Cleanup(func() { requireNoError(t, snapshot.Close()) })

	equal := mustContextualData(t, nil, []policyengine.Attribute{mustAttribute(t, []string{"classification"}, persisted)})
	reader, err := NewSnapshotReader(snapshot, equal)
	requireNoError(t, err)
	value, found, err := reader.ResolveAttribute(context.Background(), dsl.EntityRef{Type: "document", ID: "doc-1"}, []string{"classification"})
	requireNoError(t, err)
	if !found || value != "internal" {
		t.Fatalf("ResolveAttribute() = (%#v, %t), want (%q, true)", value, found, "internal")
	}

	different, err := policyengine.NewStringValue("secret")
	requireNoError(t, err)
	conflicting := mustContextualData(t, nil, []policyengine.Attribute{mustAttribute(t, []string{"classification"}, different)})
	conflictReader, err := NewSnapshotReader(snapshot, conflicting)
	requireNoError(t, err)
	_, _, err = conflictReader.ResolveAttribute(context.Background(), dsl.EntityRef{Type: "document", ID: "doc-1"}, []string{"classification"})
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
}

func TestSnapshotReaderRejectsContextualPersistentAttributePathConflicts(t *testing.T) {
	for _, test := range []struct {
		name       string
		contextual []string
		persistent []string
	}{
		{name: "contextual parent has persistent descendant", contextual: []string{"metadata"}, persistent: []string{"metadata", "classification"}},
		{name: "contextual child has persistent ancestor", contextual: []string{"metadata", "classification"}, persistent: []string{"metadata"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := memory.New()
			requireNoError(t, err)
			writeAttribute(t, adapter, 0, "persisted", test.persistent, policyengine.NewBooleanValue(true))
			snapshot := openSnapshot(t, adapter, 1)
			t.Cleanup(func() { requireNoError(t, snapshot.Close()) })
			contextual := mustContextualData(t, nil, []policyengine.Attribute{mustAttribute(t, test.contextual, policyengine.NewBooleanValue(true))})
			reader, err := NewSnapshotReader(snapshot, contextual)
			requireNoError(t, err)

			_, _, err = reader.ResolveAttribute(context.Background(), dsl.EntityRef{Type: "document", ID: "doc-1"}, test.contextual)
			requireCategory(t, err, policyengine.ErrorInvalidArgument)
		})
	}
}

func TestSnapshotReaderRejectsCanceledAndInvalidAttributeResolution(t *testing.T) {
	adapter, err := memory.New()
	requireNoError(t, err)
	snapshot := openSnapshot(t, adapter, 0)
	t.Cleanup(func() { requireNoError(t, snapshot.Close()) })
	reader, err := NewSnapshotReader(snapshot, policyengine.ContextualData{})
	requireNoError(t, err)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = reader.ReadTuples(canceled, dsl.EntityRef{Type: "document", ID: "doc-1"}, "viewer")
	requireCategory(t, err, policyengine.ErrorCanceled)
	_, _, err = reader.ResolveAttribute(context.Background(), dsl.EntityRef{Type: "document", ID: "doc-1"}, []string{"invalid.path"})
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
}

func writeViewer(t *testing.T, adapter *memory.Store, generation uint64, key, subject string) {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: subject},
	}, nil)
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "tenant",
		ValidationRevisionID: ensureTestRevision(t, adapter),
		ExpectedGeneration:   generation,
		IdempotencyKey:       key,
		TupleWrites:          []policyengine.RelationshipTuple{tuple},
	})
	requireNoError(t, err)
	_, err = adapter.WriteData(context.Background(), request)
	requireNoError(t, err)
}

func writeAttribute(t *testing.T, adapter *memory.Store, generation uint64, key string, path []string, value policyengine.Value) {
	t.Helper()
	attribute := mustAttribute(t, path, value)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "tenant",
		ValidationRevisionID: ensureTestRevision(t, adapter),
		ExpectedGeneration:   generation,
		IdempotencyKey:       key,
		AttributeWrites:      []policyengine.Attribute{attribute},
	})
	requireNoError(t, err)
	_, err = adapter.WriteData(context.Background(), request)
	requireNoError(t, err)
}

func ensureTestRevision(t *testing.T, adapter *memory.Store) string {
	t.Helper()
	artifact, err := dsl.CompileArtifact("adapter-test.dsl", []byte(`
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { allow otherwise }
`))
	requireNoError(t, err)
	encoded, err := artifact.MarshalBinary()
	requireNoError(t, err)
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	requireNoError(t, err)
	metadata, err := policyengine.NewRevisionMetadata("tenant", id, time.Unix(100, 0).UTC())
	requireNoError(t, err)
	write, err := store.NewRevisionWrite(metadata, encoded)
	requireNoError(t, err)
	_, err = adapter.PutRevision(context.Background(), write)
	requireNoError(t, err)
	return id.String()
}

func openSnapshot(t *testing.T, adapter *memory.Store, minimum uint64) store.Snapshot {
	t.Helper()
	request, err := store.NewSnapshotRequest("tenant", minimum, time.Unix(100, 0).UTC())
	requireNoError(t, err)
	snapshot, err := adapter.OpenSnapshot(context.Background(), request)
	requireNoError(t, err)
	return snapshot
}

func mustContextualData(t *testing.T, subjects []string, attributes []policyengine.Attribute) policyengine.ContextualData {
	t.Helper()
	tuples := make([]policyengine.RelationshipTuple, 0, len(subjects))
	for _, subject := range subjects {
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
			Relation: "viewer",
			Subject:  dsl.SubjectRef{Type: "user", ID: subject},
		}, nil)
		requireNoError(t, err)
		tuples = append(tuples, tuple)
	}
	data, err := policyengine.NewContextualData(tuples, attributes)
	requireNoError(t, err)
	return data
}

func mustAttribute(t *testing.T, path []string, value policyengine.Value) policyengine.Attribute {
	t.Helper()
	attribute, err := policyengine.NewAttributePath(dsl.EntityRef{Type: "document", ID: "doc-1"}, path, value)
	requireNoError(t, err)
	return attribute
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func assertSubjects(t *testing.T, subjects []dsl.SubjectRef, want ...string) {
	t.Helper()
	if len(subjects) != len(want) {
		t.Fatalf("subject count = %d, want %d", len(subjects), len(want))
	}
	for index, expected := range want {
		actual := subjects[index].Type + ":" + subjects[index].ID
		if actual != expected {
			t.Fatalf("subject %d = %q, want %q", index, actual, expected)
		}
	}
}

func requireCategory(t *testing.T, err error, want policyengine.ErrorCategory) {
	t.Helper()
	var engineErr *policyengine.EngineError
	if !errors.As(err, &engineErr) || engineErr.Category() != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
