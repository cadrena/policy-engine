package app_test

import (
	"context"
	"testing"
	"time"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/internal/app"
	"github.com/conductera/policy-engine/store/memory"
)

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
