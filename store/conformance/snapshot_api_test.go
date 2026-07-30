package conformance_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestSnapshotRequestAndBoundedResultsAreImmutable(t *testing.T) {
	t.Parallel()

	readAt := time.Unix(20, 0).UTC()
	request, err := store.NewSnapshotRequest("tenant-a", 1, readAt)
	if err != nil {
		t.Fatalf("NewSnapshotRequest() error = %v", err)
	}
	query, err := store.NewTupleQuery(dsl.EntityRef{Type: "document", ID: "roadmap"}, "viewer", 2)
	if err != nil {
		t.Fatalf("NewTupleQuery() error = %v", err)
	}
	subjects := []dsl.SubjectRef{{Type: "user", ID: "bob"}, {Type: "group", ID: "engineering", Relation: "member"}}
	result, err := store.NewTupleResult(query, subjects)
	if err != nil {
		t.Fatalf("NewTupleResult() error = %v", err)
	}
	subjects[0] = dsl.SubjectRef{}
	if got := result.Subjects(); len(got) != 2 {
		t.Fatalf("TupleResult.Subjects() count = %d", len(got))
	}
	returned := result.Subjects()
	returned[0] = dsl.SubjectRef{}
	if reflect.DeepEqual(returned, result.Subjects()) {
		t.Fatal("TupleResult.Subjects returned aliased state")
	}
	if !request.Valid() || request.Namespace() != "tenant-a" || request.MinimumGeneration() != 1 || !request.ReadAt().Equal(readAt) {
		t.Fatalf("snapshot request metadata = %v", request)
	}

	key, err := policyengine.NewAttributeKeyPath(dsl.EntityRef{Type: "document", ID: "roadmap"}, []string{"region", "country"})
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := store.NewAttributeResult(key, policyengine.NewBooleanValue(true), true)
	if err != nil {
		t.Fatalf("NewAttributeResult() error = %v", err)
	}
	if value, found := attribute.Value(); !found || value.Kind() != policyengine.ValueKindBoolean {
		t.Fatalf("AttributeResult.Value() = %v/%v", value, found)
	}
	missing, err := store.NewAttributeResult(key, policyengine.Value{}, false)
	if err != nil {
		t.Fatalf("missing NewAttributeResult() error = %v", err)
	}
	if _, found := missing.Value(); found {
		t.Fatal("missing attribute reported found")
	}
}

func TestSnapshotPortUsesLifetimeBearingBoundedQueries(t *testing.T) {
	t.Parallel()
	var _ store.DataReader = snapshotReaderContract{}
}

type snapshotReaderContract struct{}

func (snapshotReaderContract) GetDataGeneration(context.Context, policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	return policyengine.GetDataGenerationResponse{}, nil
}

func (snapshotReaderContract) OpenSnapshot(context.Context, store.SnapshotRequest) (store.Snapshot, error) {
	return nil, nil
}
