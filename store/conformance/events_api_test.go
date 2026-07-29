package conformance_test

import (
	"context"
	"testing"
	"time"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

func TestStoreContractComposesEventListing(t *testing.T) {
	t.Parallel()
	var candidate completeContract
	var _ store.EventStore = candidate
	var _ store.Store = candidate
}

func TestContextErrorIsNilSafeAndPreservesCancellationCategory(t *testing.T) {
	t.Parallel()

	var nilContext context.Context
	assertCategory(t, store.ContextError(nilContext), policyengine.ErrorInvalidArgument)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	assertCategory(t, store.ContextError(canceled), policyengine.ErrorCanceled)
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	assertCategory(t, store.ContextError(deadline), policyengine.ErrorDeadlineExceeded)
	if err := store.ContextError(context.Background()); err != nil {
		t.Fatalf("ContextError(background) returned %T", err)
	}
}

type completeContract struct{ revisionSlotContract }

func (completeContract) ListEvents(context.Context, policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error) {
	return policyengine.ListEventsResponse{}, nil
}

func assertCategory(t *testing.T, err error, want policyengine.ErrorCategory) {
	t.Helper()
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr == nil || engineErr.Category() != want {
		t.Fatalf("error type/category mismatch, want %s", want)
	}
}
