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

func TestWriteDataReplaySurvivesReopenWithoutAnotherGenerationOrEvent(t *testing.T) {
	// This catches idempotency state kept only in memory, a replay that reaches
	// mutation/event code, or a changed request incorrectly treated as replay.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	revision := newSQLiteRevisionWrite(t, "idempotency-reopen", "idem.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request := newSQLiteDataRequest(t, "idempotency-reopen", revision.Metadata().ID(), 0, "same-key", "one")
	first, err := adapter.WriteData(context.Background(), request)
	if err != nil || first.Generation() != 1 || first.Replayed() {
		t.Fatalf("first WriteData() = %#v, %v", first, err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := Open(config)
	if err != nil {
		t.Fatalf("reopen Open() error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	replay, err := reopened.WriteData(context.Background(), request)
	if err != nil || replay.Generation() != 1 || !replay.Replayed() {
		t.Fatalf("replay WriteData() = %#v, %v", replay, err)
	}
	headRequest, err := policyengine.NewGetDataGenerationRequest("idempotency-reopen")
	if err != nil {
		t.Fatalf("NewGetDataGenerationRequest() error = %v", err)
	}
	head, err := reopened.GetDataGeneration(context.Background(), headRequest)
	if err != nil || head.Generation() != 1 {
		t.Fatalf("GetDataGeneration() = %#v, %v", head, err)
	}
	changed := newSQLiteDataRequest(t, "idempotency-reopen", revision.Metadata().ID(), 0, "same-key", "changed")
	if _, err := reopened.WriteData(context.Background(), changed); categoryOf(err) != policyengine.ErrorConflict {
		t.Fatalf("changed same-key category = %v, want CONFLICT", categoryOf(err))
	}
}

func TestWriteDataRollbackLeavesNoPartialMutationOrGenerationGap(t *testing.T) {
	// This catches a failure after SQL mutation that leaves data, idempotency,
	// head generation, or event sequencing partially durable.
	adapter, hooks := openMigratedStoreWithHooksForTest(t)
	revision := newSQLiteRevisionWrite(t, "idempotency-rollback", "rollback.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request := newSQLiteDataRequest(t, "idempotency-rollback", revision.Metadata().ID(), 0, "rollback-key", "one")
	hooks.armNextAttributeMutationFailure()
	if _, err := adapter.WriteData(context.Background(), request); categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("failed WriteData() category = %v, want UNAVAILABLE", categoryOf(err))
	}
	headRequest, err := policyengine.NewGetDataGenerationRequest("idempotency-rollback")
	if err != nil {
		t.Fatalf("NewGetDataGenerationRequest() error = %v", err)
	}
	head, err := adapter.GetDataGeneration(context.Background(), headRequest)
	if err != nil || head.Generation() != 0 {
		t.Fatalf("head after rollback = %#v, %v", head, err)
	}
	response, err := adapter.WriteData(context.Background(), request)
	if err != nil || response.Generation() != 1 || response.Replayed() {
		t.Fatalf("retry WriteData() = %#v, %v", response, err)
	}
}

func TestWriteDataMutationAndCommitFaultsRollbackEveryDurableEffect(t *testing.T) {
	// Each fault fires after the named durable boundary. A successful retry with
	// the same idempotency key proves no tuple/attribute/idempotency/head/event
	// residue escaped the failed transaction.
	for _, test := range []struct {
		name      string
		arm       func(*sqliteLifecycleTestHooks)
		withTuple bool
	}{
		{name: "after-tuple-mutation", arm: (*sqliteLifecycleTestHooks).armNextTupleMutationFailure, withTuple: true},
		{name: "after-attribute-mutation", arm: (*sqliteLifecycleTestHooks).armNextAttributeMutationFailure},
		{name: "before-event-append", arm: (*sqliteLifecycleTestHooks).armNextEventAppendFailure},
		{name: "before-commit", arm: (*sqliteLifecycleTestHooks).armNextCommitFailure},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			adapter, hooks := openMigratedStoreWithHooksForTest(t)
			namespace := "fault-" + test.name
			revision := newSQLiteRevisionWrite(t, namespace, "fault.cdr", []byte("entity document {}"), time.Unix(1, 0).UTC())
			if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
				t.Fatalf("PutRevision() error = %v", err)
			}
			var request policyengine.WriteDataRequest
			var tupleKey policyengine.TupleKey
			var attributeKey policyengine.AttributeKey
			if test.withTuple {
				request, tupleKey = newSQLiteTupleWriteRequest(t, namespace, revision.Metadata().ID(), "fault-key")
			} else {
				request = newSQLiteDataRequest(t, namespace, revision.Metadata().ID(), 0, "fault-key", "one")
				var err error
				attributeKey, err = policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "doc"}, "classification")
				if err != nil {
					t.Fatalf("NewAttributeKey() error = %v", err)
				}
			}
			test.arm(hooks)
			if _, err := adapter.WriteData(context.Background(), request); categoryOf(err) != policyengine.ErrorUnavailable {
				t.Fatalf("failed WriteData() category = %v, want UNAVAILABLE", categoryOf(err))
			}

			headRequest, err := policyengine.NewGetDataGenerationRequest(namespace)
			if err != nil {
				t.Fatalf("NewGetDataGenerationRequest() error = %v", err)
			}
			head, err := adapter.GetDataGeneration(context.Background(), headRequest)
			if err != nil || head.Generation() != 0 {
				t.Fatalf("head after failure = %#v, %v", head, err)
			}
			if events := sqliteEventsForTest(t, adapter, namespace); len(events) != 1 {
				t.Fatalf("events after failure = %d, want revision only", len(events))
			}
			snapshotRequest, err := store.NewSnapshotRequest(namespace, 0, time.Unix(100, 0).UTC())
			if err != nil {
				t.Fatalf("NewSnapshotRequest() error = %v", err)
			}
			snapshot, err := adapter.OpenSnapshot(context.Background(), snapshotRequest)
			if err != nil {
				t.Fatalf("OpenSnapshot() error = %v", err)
			}
			if test.withTuple {
				query, queryErr := store.NewTupleQuery(tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 1)
				if queryErr != nil {
					t.Fatalf("NewTupleQuery() error = %v", queryErr)
				}
				result, queryErr := snapshot.QueryTuples(context.Background(), query)
				if queryErr != nil || len(result.Subjects()) != 0 {
					t.Fatalf("tuple after failure = %#v, %v", result, queryErr)
				}
			} else {
				result, getErr := snapshot.GetAttribute(context.Background(), attributeKey)
				if getErr != nil || result.Found() {
					t.Fatalf("attribute after failure = %#v, %v", result, getErr)
				}
			}
			if err := snapshot.Close(); err != nil {
				t.Fatalf("snapshot.Close() error = %v", err)
			}

			response, err := adapter.WriteData(context.Background(), request)
			if err != nil || response.Generation() != 1 || response.Replayed() {
				t.Fatalf("retry WriteData() = %#v, %v", response, err)
			}
		})
	}
}

func newSQLiteTupleWriteRequest(t testing.TB, namespace, revisionID, key string) (policyengine.WriteDataRequest, policyengine.TupleKey) {
	t.Helper()
	tupleValue := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: "user"},
	}
	tuple, err := policyengine.NewRelationshipTuple(tupleValue, nil)
	if err != nil {
		t.Fatalf("NewRelationshipTuple() error = %v", err)
	}
	tupleKey, err := policyengine.NewTupleKey(tupleValue)
	if err != nil {
		t.Fatalf("NewTupleKey() error = %v", err)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: namespace, ValidationRevisionID: revisionID, IdempotencyKey: key,
		TupleWrites: []policyengine.RelationshipTuple{tuple},
	})
	if err != nil {
		t.Fatalf("NewWriteDataRequest() error = %v", err)
	}
	return request, tupleKey
}

func sqliteEventsForTest(t testing.TB, adapter *Store, namespace string) []policyengine.StateEvent {
	t.Helper()
	request, err := policyengine.NewListEventsRequest(namespace, "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	result, err := adapter.ListEvents(context.Background(), request)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	return result.Events()
}
