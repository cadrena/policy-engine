package conformance_test

import (
	"strings"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

func TestSnapshotValueConstructorsRejectForgedAndOverBudgetState(t *testing.T) {
	t.Parallel()

	readAt := time.Unix(20, 0).UTC()
	if _, err := store.NewSnapshotRequest("tenant-a", 0, time.Time{}); err == nil {
		t.Fatal("zero ReadAt error = nil")
	}
	if _, err := store.NewSnapshotRequest("", 0, readAt); err == nil {
		t.Fatal("empty namespace error = nil")
	}
	resource := dsl.EntityRef{Type: "document", ID: "roadmap"}
	if _, err := store.NewTupleQuery(resource, "viewer", 0); err == nil {
		t.Fatal("zero query limit error = nil")
	}
	if _, err := store.NewTupleQuery(resource, "viewer", policyengine.MaxAggregateWorkItems+1); err == nil {
		t.Fatal("oversized query limit error = nil")
	}
	query, err := store.NewTupleQuery(resource, "viewer", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewTupleResult(query, []dsl.SubjectRef{{Type: "user", ID: "one"}, {Type: "user", ID: "two"}}); err == nil {
		t.Fatal("tuple overflow error = nil")
	}
	if _, err := store.NewTupleResult(query, []dsl.SubjectRef{{}}); err == nil {
		t.Fatal("invalid subject error = nil")
	}
	largeQuery, err := store.NewTupleQuery(resource, "viewer", 4096)
	if err != nil {
		t.Fatal(err)
	}
	largeSubjects := make([]dsl.SubjectRef, 4096)
	for index := range largeSubjects {
		largeSubjects[index] = dsl.SubjectRef{Type: "u", ID: strings.Repeat("a", 1020)}
	}
	_, err = store.NewTupleResult(largeQuery, largeSubjects)
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr == nil || engineErr.Category() != policyengine.ErrorResourceExhausted {
		t.Fatal("metadata-over-budget tuple result did not return direct RESOURCE_EXHAUSTED")
	}

	key, err := policyengine.NewAttributeKey(resource, "classification")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewAttributeResult(key, policyengine.NewBooleanValue(true), false); err == nil {
		t.Fatal("missing result with value error = nil")
	}
	if (store.TupleResult{}).Valid() || (store.AttributeResult{}).Valid() || (store.SnapshotRequest{}).Valid() {
		t.Fatal("zero forged value reported valid")
	}
}

func TestSnapshotValuesArePrivacySafe(t *testing.T) {
	t.Parallel()

	readAt := time.Unix(20, 0).UTC()
	request, err := store.NewSnapshotRequest("tenant-secret", 0, readAt)
	if err != nil {
		t.Fatal(err)
	}
	query, err := store.NewTupleQuery(dsl.EntityRef{Type: "document", ID: "resource-secret"}, "viewer", 1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.NewTupleResult(query, []dsl.SubjectRef{{Type: "user", ID: "subject-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := policyengine.NewAttributeKeyPath(
		dsl.EntityRef{Type: "document", ID: "attribute-secret"},
		[]string{"path_secret", "leaf_secret"},
	)
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := store.NewAttributeResult(key, policyengine.NewBooleanValue(true), true)
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, request, "tenant-secret")
	assertRedacted(t, query, "resource-secret")
	assertRedacted(t, result, "subject-secret")
	assertRedacted(t, attribute, "attribute-secret")
	assertRedacted(t, attribute, "path_secret")
	assertRedacted(t, attribute, "leaf_secret")
}
