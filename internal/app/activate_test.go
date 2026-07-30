package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	storecontract "github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestPolicyServiceRejectsStoreResponsesOutsideAuthorizedRequestScope(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(200, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	artifact, err := dsl.CompileArtifact("foreign.cdr", []byte("entity foreign {}"))
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	metadata, err := policyengine.NewRevisionMetadata("tenant-a", id, clock.Now())
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	foreignActivation, err := policyengine.NewActivation(
		"tenant-a",
		"stable",
		id.String(),
		1,
		clock.Now(),
	)
	if err != nil {
		t.Fatalf("NewActivation() error = %v", err)
	}
	foreignListRequest, err := policyengine.NewListRevisionsRequest("tenant-a", "", 10)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest(foreign) error = %v", err)
	}
	foreignList, err := policyengine.NewListRevisionsResponse(
		foreignListRequest,
		[]policyengine.RevisionMetadata{metadata},
		"",
	)
	if err != nil {
		t.Fatalf("NewListRevisionsResponse(foreign) error = %v", err)
	}
	foreignActivate, err := policyengine.NewActivateResponse(foreignActivation)
	if err != nil {
		t.Fatalf("NewActivateResponse(foreign) error = %v", err)
	}
	foreignResolve, err := policyengine.NewResolveResponse(foreignActivation)
	if err != nil {
		t.Fatalf("NewResolveResponse(foreign) error = %v", err)
	}
	foreignHistoryRequest, err := policyengine.NewListActivationHistoryRequest(
		"tenant-a",
		"stable",
		"",
		10,
	)
	if err != nil {
		t.Fatalf("NewListActivationHistoryRequest(foreign) error = %v", err)
	}
	foreignHistory, err := policyengine.NewListActivationHistoryResponse(
		foreignHistoryRequest,
		[]policyengine.Activation{foreignActivation},
		"",
	)
	if err != nil {
		t.Fatalf("NewListActivationHistoryResponse(foreign) error = %v", err)
	}
	hostile := &scopeConfusingStore{
		Store:      adapter,
		revisions:  foreignList,
		activation: foreignActivate,
		resolve:    foreignResolve,
		history:    foreignHistory,
	}
	service, err := app.NewPolicyService(hostile, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	ctx := context.Background()
	caller := mustCaller(t)

	t.Run("revision list", func(t *testing.T) {
		request, err := policyengine.NewListRevisionsRequest("tenant-b", "", 10)
		if err != nil {
			t.Fatalf("NewListRevisionsRequest() error = %v", err)
		}
		_, err = service.ListRevisions(ctx, caller, request)
		requireCategory(t, err, policyengine.ErrorIntegrity)
	})
	t.Run("activate", func(t *testing.T) {
		request, err := policyengine.NewActivateRequest(
			"tenant-b",
			"stable",
			id.String(),
			policyengine.NewUnsetSlotExpectation(),
		)
		if err != nil {
			t.Fatalf("NewActivateRequest() error = %v", err)
		}
		_, err = service.Activate(ctx, caller, request)
		requireCategory(t, err, policyengine.ErrorIntegrity)
	})
	t.Run("resolve", func(t *testing.T) {
		request, err := policyengine.NewResolveRequest("tenant-b", "stable")
		if err != nil {
			t.Fatalf("NewResolveRequest() error = %v", err)
		}
		_, err = service.Resolve(ctx, caller, request)
		requireCategory(t, err, policyengine.ErrorIntegrity)
	})
	t.Run("activation history", func(t *testing.T) {
		request, err := policyengine.NewListActivationHistoryRequest(
			"tenant-b",
			"stable",
			"",
			10,
		)
		if err != nil {
			t.Fatalf("NewListActivationHistoryRequest() error = %v", err)
		}
		_, err = service.ListActivationHistory(ctx, caller, request)
		requireCategory(t, err, policyengine.ErrorIntegrity)
	})
}

func TestRollbackUsesOrdinaryActivateCAS(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(200, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	ctx := context.Background()
	caller := mustCaller(t)
	older := publishSource(ctx, t, service, caller, "older.cdr", "entity older {}")
	newer := publishSource(ctx, t, service, caller, "newer.cdr", "entity newer {}")

	firstRequest, err := policyengine.NewActivateRequest(
		"tenant-a",
		"stable",
		older.Revision().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(first) error = %v", err)
	}
	first, err := service.Activate(ctx, caller, firstRequest)
	if err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	newerExpectation, err := policyengine.NewActiveSlotExpectation(
		first.Activation().RevisionID(),
		first.Activation().Generation(),
	)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation(newer) error = %v", err)
	}
	newerRequest, err := policyengine.NewActivateRequest(
		"tenant-a",
		"stable",
		newer.Revision().ID(),
		newerExpectation,
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(newer) error = %v", err)
	}
	activeNewer, err := service.Activate(ctx, caller, newerRequest)
	if err != nil {
		t.Fatalf("Activate(newer) error = %v", err)
	}

	rollbackExpectation, err := policyengine.NewActiveSlotExpectation(
		activeNewer.Activation().RevisionID(),
		activeNewer.Activation().Generation(),
	)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation(rollback) error = %v", err)
	}
	rollbackRequest, err := policyengine.NewActivateRequest(
		"tenant-a",
		"stable",
		older.Revision().ID(),
		rollbackExpectation,
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(rollback) error = %v", err)
	}
	rolledBack, err := service.Activate(ctx, caller, rollbackRequest)
	if err != nil {
		t.Fatalf("Activate(rollback) error = %v", err)
	}
	if got, want := rolledBack.Activation().RevisionID(), older.Revision().ID(); got != want {
		t.Fatalf("rollback revision = %q, want older %q", got, want)
	}
	if got, want := rolledBack.Activation().Generation(), uint64(3); got != want {
		t.Fatalf("rollback generation = %d, want %d", got, want)
	}

	_, err = service.Activate(ctx, caller, rollbackRequest)
	requireCategory(t, err, policyengine.ErrorConflict)
}

func TestActivatePerformsCASAndRecordsBoundedHistory(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(200, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	ctx := context.Background()
	caller := mustCaller(t)
	first := publishSource(ctx, t, service, caller, "first.cdr", "entity first {}")
	second := publishSource(ctx, t, service, caller, "second.cdr", "entity second {}")

	initialRequest, err := policyengine.NewActivateRequest(
		"tenant-a",
		"stable",
		first.Revision().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(initial) error = %v", err)
	}
	initial, err := service.Activate(ctx, caller, initialRequest)
	if err != nil {
		t.Fatalf("Activate(initial) error = %v", err)
	}
	if got, want := initial.Activation().Generation(), uint64(1); got != want {
		t.Fatalf("initial generation = %d, want %d", got, want)
	}

	expectation, err := policyengine.NewActiveSlotExpectation(first.Revision().ID(), 1)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation() error = %v", err)
	}
	secondRequest, err := policyengine.NewActivateRequest(
		"tenant-a",
		"stable",
		second.Revision().ID(),
		expectation,
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(second) error = %v", err)
	}
	secondActivation, err := service.Activate(ctx, caller, secondRequest)
	if err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	if got, want := secondActivation.Activation().Generation(), uint64(2); got != want {
		t.Fatalf("second generation = %d, want %d", got, want)
	}

	_, err = service.Activate(ctx, caller, secondRequest)
	requireCategory(t, err, policyengine.ErrorConflict)
	for generation := uint64(2); generation < 5; generation++ {
		active, activeErr := policyengine.NewActiveSlotExpectation(second.Revision().ID(), generation)
		if activeErr != nil {
			t.Fatalf("NewActiveSlotExpectation(%d) error = %v", generation, activeErr)
		}
		request, requestErr := policyengine.NewActivateRequest(
			"tenant-a",
			"stable",
			second.Revision().ID(),
			active,
		)
		if requestErr != nil {
			t.Fatalf("NewActivateRequest(%d) error = %v", generation, requestErr)
		}
		if _, activateErr := service.Activate(ctx, caller, request); activateErr != nil {
			t.Fatalf("Activate(%d) error = %v", generation, activateErr)
		}
	}

	resolveRequest, err := policyengine.NewResolveRequest("tenant-a", "stable")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	resolved, err := service.Resolve(ctx, caller, resolveRequest)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := resolved.Activation().RevisionID(), second.Revision().ID(); got != want {
		t.Fatalf("resolved revision = %q, want %q", got, want)
	}
	if got, want := resolved.Activation().Generation(), uint64(5); got != want {
		t.Fatalf("resolved generation = %d, want %d", got, want)
	}

	historyRequest, err := policyengine.NewListActivationHistoryRequest(
		"tenant-a",
		"stable",
		"",
		10,
	)
	if err != nil {
		t.Fatalf("NewListActivationHistoryRequest() error = %v", err)
	}
	history, err := service.ListActivationHistory(ctx, caller, historyRequest)
	if err != nil {
		t.Fatalf("ListActivationHistory() error = %v", err)
	}
	activations := history.Activations()
	if got, want := len(activations), 3; got != want {
		t.Fatalf("retained history length = %d, want %d", got, want)
	}
	for index, want := range []uint64{3, 4, 5} {
		if got := activations[index].Generation(); got != want {
			t.Fatalf("history[%d] generation = %d, want %d", index, got, want)
		}
	}
}

func publishSource(
	ctx context.Context,
	t testing.TB,
	service *app.PolicyService,
	caller policyengine.Caller,
	sourceName string,
	source string,
) policyengine.PublishResponse {
	t.Helper()
	request, err := policyengine.NewPublishRequest("tenant-a", sourceName, []byte(source))
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	response, err := service.Publish(ctx, caller, request)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	return response
}

type scopeConfusingStore struct {
	*memory.Store
	revisions  policyengine.ListRevisionsResponse
	activation policyengine.ActivateResponse
	resolve    policyengine.ResolveResponse
	history    policyengine.ListActivationHistoryResponse
}

func (s *scopeConfusingStore) ListRevisions(
	context.Context,
	policyengine.ListRevisionsRequest,
) (policyengine.ListRevisionsResponse, error) {
	return s.revisions, nil
}

func (s *scopeConfusingStore) Activate(
	context.Context,
	policyengine.ActivateRequest,
) (policyengine.ActivateResponse, error) {
	return s.activation, nil
}

func (s *scopeConfusingStore) Resolve(
	context.Context,
	policyengine.ResolveRequest,
) (policyengine.ResolveResponse, error) {
	return s.resolve, nil
}

func (s *scopeConfusingStore) ListActivationHistory(
	context.Context,
	policyengine.ListActivationHistoryRequest,
) (policyengine.ListActivationHistoryResponse, error) {
	return s.history, nil
}

var _ storecontract.Store = (*scopeConfusingStore)(nil)
