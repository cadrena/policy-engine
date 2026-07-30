package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	"github.com/cadrena/policy-engine/internal/domain"
	"github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

const dataPolicySource = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view {
    allow when resource.amount == 5000
    allow otherwise
}
`

func TestWriteDataRejectsStaleGenerationWithoutPartialMutation(t *testing.T) {
	ctx := context.Background()
	service, memoryStore := newDataServiceFixture(t)

	first := writeRequest(t, "tenant-a", 0, "write-1",
		[]policyengine.RelationshipTuple{viewerTuple(t, "alice", "doc-1")},
		[]policyengine.Attribute{amountAttribute(t, "doc-1", 5000)})
	got, err := service.WriteData(ctx, dataWriterCaller(t), first)
	requireNoError(t, err)
	if got.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", got.Generation())
	}

	stale := writeRequest(t, "tenant-a", 0, "write-2",
		[]policyengine.RelationshipTuple{viewerTuple(t, "bob", "doc-2")},
		nil)
	_, err = service.WriteData(ctx, dataWriterCaller(t), stale)
	requireCategory(t, err, policyengine.ErrorConflict)

	snapshot := openSnapshot(t, memoryStore, "tenant-a", 1)
	defer func() { requireNoError(t, snapshot.Close()) }()
	assertTuplePresent(t, snapshot, "alice", "doc-1")
	assertTupleAbsent(t, snapshot, "bob", "doc-2")
}

func TestGetDataGenerationReturnsAuthorizedAuthoritativeHead(t *testing.T) {
	ctx := context.Background()
	service, _ := newDataServiceFixture(t)

	request, err := policyengine.NewGetDataGenerationRequest("tenant-a")
	requireNoError(t, err)
	initial, err := service.GetDataGeneration(ctx, dataWriterCaller(t), request)
	requireNoError(t, err)
	if !initial.Valid() || initial.Generation() != 0 {
		t.Fatalf("initial response = %#v, want valid generation 0", initial)
	}

	write := writeRequest(t, "tenant-a", 0, "head-1",
		[]policyengine.RelationshipTuple{viewerTuple(t, "alice", "doc-1")},
		nil)
	_, err = service.WriteData(ctx, dataWriterCaller(t), write)
	requireNoError(t, err)
	head, err := service.GetDataGeneration(ctx, dataWriterCaller(t), request)
	requireNoError(t, err)
	if !head.Valid() || head.Generation() != 1 {
		t.Fatalf("head response = %#v, want valid generation 1", head)
	}
}

func TestWriteDataReplaysSameCanonicalPayloadAndRejectsChangedPayload(t *testing.T) {
	ctx := context.Background()
	service, _ := newDataServiceFixture(t)
	alice := viewerTuple(t, "alice", "doc-1")
	bob := viewerTuple(t, "bob", "doc-1")

	first := writeRequest(t, "tenant-a", 0, "replay-1",
		[]policyengine.RelationshipTuple{alice, bob}, nil)
	committed, err := service.WriteData(ctx, dataWriterCaller(t), first)
	requireNoError(t, err)
	if committed.Generation() != 1 || committed.Replayed() {
		t.Fatalf("first response generation/replayed = %d/%t, want 1/false",
			committed.Generation(), committed.Replayed())
	}

	sameCanonicalPayload := writeRequest(t, "tenant-a", 0, "replay-1",
		[]policyengine.RelationshipTuple{bob, alice}, nil)
	replayed, err := service.WriteData(ctx, dataWriterCaller(t), sameCanonicalPayload)
	requireNoError(t, err)
	if replayed.Generation() != 1 || !replayed.Replayed() {
		t.Fatalf("replay response generation/replayed = %d/%t, want 1/true",
			replayed.Generation(), replayed.Replayed())
	}

	changed := writeRequest(t, "tenant-a", 0, "replay-1",
		[]policyengine.RelationshipTuple{viewerTuple(t, "mallory", "doc-1")}, nil)
	_, err = service.WriteData(ctx, dataWriterCaller(t), changed)
	requireCategory(t, err, policyengine.ErrorConflict)
}

func TestWriteDataTupleExpiryAtReadAtIsAbsent(t *testing.T) {
	ctx := context.Background()
	service, memoryStore := newDataServiceFixture(t)
	expiry := time.Unix(200, 0).UTC()
	expiring := viewerTupleWithExpiry(t, "alice", "doc-1", expiry)
	request := writeRequest(t, "tenant-a", 0, "expiry-1",
		[]policyengine.RelationshipTuple{expiring}, nil)
	_, err := service.WriteData(ctx, dataWriterCaller(t), request)
	requireNoError(t, err)

	snapshot := openSnapshot(t, memoryStore, "tenant-a", 1)
	defer func() { requireNoError(t, snapshot.Close()) }()
	assertTupleAbsent(t, snapshot, "alice", "doc-1")
}

func TestWriteDataDoesNotRevealCrossNamespaceRevisionExistence(t *testing.T) {
	ctx := context.Background()
	service, _ := newDataServiceFixture(t)
	request := writeRequest(t, "tenant-b", 0, "cross-1",
		[]policyengine.RelationshipTuple{viewerTuple(t, "alice", "doc-1")}, nil)

	_, err := service.WriteData(ctx, dataWriterCaller(t), request)
	requireCategory(t, err, policyengine.ErrorNotFound)
}

func TestContextualAttributeEqualToPersistentValueIsAcceptedOnce(t *testing.T) {
	ctx := context.Background()
	service, memoryStore := newDataServiceFixture(t)
	persistent := amountAttribute(t, "doc-1", 5000)
	request := writeRequest(t, "tenant-a", 0, "attribute-1", nil,
		[]policyengine.Attribute{persistent})
	_, err := service.WriteData(ctx, dataWriterCaller(t), request)
	requireNoError(t, err)
	snapshot := openSnapshot(t, memoryStore, "tenant-a", 1)
	defer func() { requireNoError(t, snapshot.Close()) }()
	contextual, err := policyengine.NewContextualData(nil, []policyengine.Attribute{persistent})
	requireNoError(t, err)

	normalized, err := domain.NormalizeContextualData(ctx, snapshot, contextual)
	requireNoError(t, err)
	if got := len(normalized.Attributes()); got != 0 {
		t.Fatalf("normalized contextual attributes = %d, want 0 duplicate overlays", got)
	}
}

func TestContextualAttributeDifferentFromPersistentValueIsInvalid(t *testing.T) {
	ctx := context.Background()
	service, memoryStore := newDataServiceFixture(t)
	request := writeRequest(t, "tenant-a", 0, "attribute-1", nil,
		[]policyengine.Attribute{amountAttribute(t, "doc-1", 5000)})
	_, err := service.WriteData(ctx, dataWriterCaller(t), request)
	requireNoError(t, err)
	snapshot := openSnapshot(t, memoryStore, "tenant-a", 1)
	defer func() { requireNoError(t, snapshot.Close()) }()
	contextual, err := policyengine.NewContextualData(nil,
		[]policyengine.Attribute{amountAttribute(t, "doc-1", 6000)})
	requireNoError(t, err)

	_, err = domain.NormalizeContextualData(ctx, snapshot, contextual)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
}

func newDataServiceFixture(t testing.TB) (*app.DataService, *memory.Store) {
	t.Helper()
	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	memoryStore, err := memory.NewWithClock(clock)
	requireNoError(t, err)
	policyService, err := app.NewPolicyService(memoryStore, allowAuthorizer{}, clock)
	requireNoError(t, err)
	publishSource(
		context.Background(),
		t,
		policyService,
		dataWriterCaller(t),
		"data-policy.cdr",
		dataPolicySource,
	)
	service, err := app.NewDataService(memoryStore, memoryStore, memoryStore, allowAuthorizer{})
	requireNoError(t, err)
	return service, memoryStore
}

func writeRequest(
	t testing.TB,
	namespace string,
	expectedGeneration uint64,
	idempotencyKey string,
	tuples []policyengine.RelationshipTuple,
	attributes []policyengine.Attribute,
) policyengine.WriteDataRequest {
	t.Helper()
	artifact, err := dsl.CompileArtifact("data-policy.cdr", []byte(dataPolicySource))
	requireNoError(t, err)
	revisionID, err := policyengine.RevisionIDFromArtifact(artifact)
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            namespace,
		ValidationRevisionID: revisionID.String(),
		ExpectedGeneration:   expectedGeneration,
		IdempotencyKey:       idempotencyKey,
		TupleWrites:          tuples,
		AttributeWrites:      attributes,
	})
	requireNoError(t, err)
	return request
}

func viewerTuple(t testing.TB, subjectID, documentID string) policyengine.RelationshipTuple {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: documentID},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: subjectID},
	}, nil)
	requireNoError(t, err)
	return tuple
}

func viewerTupleWithExpiry(
	t testing.TB,
	subjectID string,
	documentID string,
	expiry time.Time,
) policyengine.RelationshipTuple {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: documentID},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: subjectID},
	}, &expiry)
	requireNoError(t, err)
	return tuple
}

func amountAttribute(t testing.TB, documentID string, amount int64) policyengine.Attribute {
	t.Helper()
	attribute, err := policyengine.NewAttribute(
		dsl.EntityRef{Type: "document", ID: documentID},
		"amount",
		policyengine.NewIntegerValue(amount),
	)
	requireNoError(t, err)
	return attribute
}

func dataWriterCaller(t testing.TB) policyengine.Caller {
	t.Helper()
	return mustCaller(t)
}

func openSnapshot(
	t testing.TB,
	memoryStore *memory.Store,
	namespace string,
	generation uint64,
) store.Snapshot {
	t.Helper()
	request, err := store.NewSnapshotRequest(namespace, generation, time.Unix(200, 0).UTC())
	requireNoError(t, err)
	snapshot, err := memoryStore.OpenSnapshot(context.Background(), request)
	requireNoError(t, err)
	return snapshot
}

func assertTuplePresent(t testing.TB, snapshot store.Snapshot, subjectID, documentID string) {
	t.Helper()
	query, err := store.NewTupleQuery(
		dsl.EntityRef{Type: "document", ID: documentID},
		"viewer",
		10,
	)
	requireNoError(t, err)
	result, err := snapshot.QueryTuples(context.Background(), query)
	requireNoError(t, err)
	for _, subject := range result.Subjects() {
		if subject.Type == "user" && subject.ID == subjectID && subject.Relation == "" {
			return
		}
	}
	t.Fatalf("tuple user:%s viewer document:%s is absent", subjectID, documentID)
}

func assertTupleAbsent(t testing.TB, snapshot store.Snapshot, subjectID, documentID string) {
	t.Helper()
	query, err := store.NewTupleQuery(
		dsl.EntityRef{Type: "document", ID: documentID},
		"viewer",
		10,
	)
	requireNoError(t, err)
	result, err := snapshot.QueryTuples(context.Background(), query)
	requireNoError(t, err)
	for _, subject := range result.Subjects() {
		if subject.Type == "user" && subject.ID == subjectID && subject.Relation == "" {
			t.Fatalf("tuple user:%s viewer document:%s is present", subjectID, documentID)
		}
	}
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
