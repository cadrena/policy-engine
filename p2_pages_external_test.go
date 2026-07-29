package policyengine_test

import (
	"testing"
	"time"

	policyengine "github.com/conductera/policy-engine"
)

func TestListRevisionResponseRequiresOriginatingRequest(t *testing.T) {
	t.Parallel()

	request, err := policyengine.NewListRevisionsRequest("page-namespace", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	id, err := policyengine.ParseRevisionID(testRevisionID(t))
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewRevisionMetadata("page-namespace", id, time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListRevisionsResponse(request, []policyengine.RevisionMetadata{item}, "next"); err != nil {
		t.Fatalf("request-bound page error = %v", err)
	}
}

func TestActivationHistoryResponseRequiresOriginatingRequest(t *testing.T) {
	t.Parallel()

	request, err := policyengine.NewListActivationHistoryRequest("page-namespace", "stable", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewActivation("page-namespace", "stable", testRevisionID(t), 1, time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListActivationHistoryResponse(request, []policyengine.Activation{item}, "next"); err != nil {
		t.Fatalf("request-bound page error = %v", err)
	}
}

func TestEventsResponseRequiresOriginatingRequest(t *testing.T) {
	t.Parallel()

	request, err := policyengine.NewListEventsRequest("page-namespace", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace: "page-namespace", Cursor: "event-1", Kind: policyengine.StateEventDataWritten,
		DataGeneration: 1, OccurredAt: time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListEventsResponse(request, []policyengine.StateEvent{item}, "next"); err != nil {
		t.Fatalf("request-bound page error = %v", err)
	}
}

func TestRequestBoundRevisionPagesRejectScopeDuplicatesOrderAndLimitViolations(t *testing.T) {
	t.Parallel()
	request, err := policyengine.NewListRevisionsRequest("page-namespace", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	firstID, secondID := distinctRevisionIDs(t)
	firstParsed, err := policyengine.ParseRevisionID(firstID)
	if err != nil {
		t.Fatal(err)
	}
	secondParsed, err := policyengine.ParseRevisionID(secondID)
	if err != nil {
		t.Fatal(err)
	}
	firstTime := time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC)
	first, err := policyengine.NewRevisionMetadata("page-namespace", firstParsed, firstTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := policyengine.NewRevisionMetadata("page-namespace", secondParsed, firstTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	other, err := policyengine.NewRevisionMetadata("other-namespace", secondParsed, firstTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListRevisionsResponse(request, []policyengine.RevisionMetadata{first, second}, "next"); err != nil {
		t.Fatalf("valid page error = %v", err)
	}
	for name, values := range map[string][]policyengine.RevisionMetadata{
		"wrong namespace": {first, other}, "duplicate": {first, first}, "unordered": {second, first},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policyengine.NewListRevisionsResponse(request, values, "next"); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}
	limited, err := policyengine.NewListRevisionsRequest("page-namespace", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListRevisionsResponse(limited, []policyengine.RevisionMetadata{first, second}, "next"); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestRequestBoundActivationPagesRejectScopeDuplicatesOrderAndLimitViolations(t *testing.T) {
	t.Parallel()
	request, err := policyengine.NewListActivationHistoryRequest("page-namespace", "stable", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC)
	newActivation := func(namespace, slot string, generation uint64) policyengine.Activation {
		t.Helper()
		value, valueErr := policyengine.NewActivation(namespace, slot, testRevisionID(t), generation, now)
		if valueErr != nil {
			t.Fatal(valueErr)
		}
		return value
	}
	first := newActivation("page-namespace", "stable", 1)
	second := newActivation("page-namespace", "stable", 2)
	if _, err := policyengine.NewListActivationHistoryResponse(request, []policyengine.Activation{first, second}, "next"); err != nil {
		t.Fatalf("valid page error = %v", err)
	}
	for name, values := range map[string][]policyengine.Activation{
		"wrong namespace": {first, newActivation("other-namespace", "stable", 2)},
		"wrong slot":      {first, newActivation("page-namespace", "canary", 2)},
		"duplicate":       {first, first},
		"unordered":       {second, first},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policyengine.NewListActivationHistoryResponse(request, values, "next"); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}
	limited, err := policyengine.NewListActivationHistoryRequest("page-namespace", "stable", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListActivationHistoryResponse(limited, []policyengine.Activation{first, second}, "next"); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestRequestBoundEventPagesRejectScopeDuplicatesAndLimitButPreserveOpaqueOrder(t *testing.T) {
	t.Parallel()
	request, err := policyengine.NewListEventsRequest("page-namespace", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 29, 16, 0, 0, 0, time.UTC)
	newEvent := func(namespace, cursor string, generation uint64) policyengine.StateEvent {
		t.Helper()
		value, valueErr := policyengine.NewStateEvent(policyengine.StateEventInput{
			Namespace: namespace, Cursor: cursor, Kind: policyengine.StateEventDataWritten,
			DataGeneration: generation, OccurredAt: now,
		})
		if valueErr != nil {
			t.Fatal(valueErr)
		}
		return value
	}
	first := newEvent("page-namespace", "opaque-z", 1)
	second := newEvent("page-namespace", "opaque-a", 2)
	response, err := policyengine.NewListEventsResponse(request, []policyengine.StateEvent{first, second}, "next")
	if err != nil {
		t.Fatalf("opaque store-order page error = %v", err)
	}
	if got := response.Events(); got[0].Cursor() != "opaque-z" || got[1].Cursor() != "opaque-a" {
		t.Fatal("opaque event order was not preserved")
	}
	for name, values := range map[string][]policyengine.StateEvent{
		"wrong namespace":  {first, newEvent("other-namespace", "opaque-a", 2)},
		"duplicate cursor": {first, newEvent("page-namespace", "opaque-z", 2)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policyengine.NewListEventsResponse(request, values, "next"); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}
	limited, err := policyengine.NewListEventsRequest("page-namespace", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewListEventsResponse(limited, []policyengine.StateEvent{first, second}, "next"); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}
