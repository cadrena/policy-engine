package policyengine

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
)

func requireCostResourceExhausted(t *testing.T, err error) {
	t.Helper()
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Category() != ErrorResourceExhausted {
		t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestCostAccountingIncludesFixedMetadataExpiryTimestampsDigestsAndCollections(t *testing.T) {
	budget := budgetCounter{max: math.MaxInt}
	if err := addFixedFieldCost(&budget, uint64Bytes); err != nil {
		t.Fatal(err)
	}
	if want := fieldMetadataBytes + uint64Bytes; budget.used != want {
		t.Fatalf("fixed field cost = %d, want %d", budget.used, want)
	}

	tuple := RelationshipTuple{tuple: dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "one"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}}
	withoutExpiry := budgetCounter{max: math.MaxInt}
	if err := addRelationshipTupleCost(&withoutExpiry, tuple); err != nil {
		t.Fatal(err)
	}
	tuple.hasExpiry = true
	tuple.expiresAt = time.Unix(1, 0)
	withExpiry := budgetCounter{max: math.MaxInt}
	if err := addRelationshipTupleCost(&withExpiry, tuple); err != nil {
		t.Fatal(err)
	}
	if got, want := withExpiry.used-withoutExpiry.used, fieldMetadataBytes+timestampBytes; got != want {
		t.Fatalf("tuple expiry cost delta = %d, want %d", got, want)
	}

	binding := EvidenceBinding{
		caller:         CallerBinding{valid: true},
		namespace:      "acme",
		selector:       Selector{slot: "stable"},
		revisionID:     strings.Repeat("a", 64),
		slotGeneration: 1,
		evaluatedAt:    time.Unix(1, 0),
		fingerprint:    EvidenceFingerprint{valid: true},
		validBinding:   true,
	}
	bindingBudget := budgetCounter{max: math.MaxInt}
	if err := addEvidenceBindingCost(&bindingBudget, binding); err != nil {
		t.Fatal(err)
	}
	wantBinding := 2*(fieldMetadataBytes+digestBytes) +
		(fieldMetadataBytes + len(binding.namespace)) +
		(fieldMetadataBytes + len(binding.selector.slot)) +
		(fieldMetadataBytes + len(binding.selector.revisionID)) +
		(fieldMetadataBytes + len(binding.revisionID)) +
		2*(fieldMetadataBytes+uint64Bytes) +
		(fieldMetadataBytes + timestampBytes)
	if bindingBudget.used != wantBinding {
		t.Fatalf("evidence binding cost = %d, want %d", bindingBudget.used, wantBinding)
	}

	for name, add := range map[string]func(*budgetCounter) error{
		"identifiers": func(b *budgetCounter) error { return addIdentifiersCost(b, nil) },
		"arguments":   func(b *budgetCounter) error { return addArgumentsCost(b, nil) },
		"contextual":  func(b *budgetCounter) error { return addContextualDataCost(b, ContextualData{}) },
		"batch":       func(b *budgetCounter) error { return addBatchResponseCost(b, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			collectionBudget := budgetCounter{max: math.MaxInt}
			if err := add(&collectionBudget); err != nil {
				t.Fatal(err)
			}
			want := collectionMetadataBytes
			if name == "contextual" {
				want *= 2
			}
			if collectionBudget.used != want {
				t.Fatalf("collection metadata cost = %d, want %d", collectionBudget.used, want)
			}
		})
	}
}

func TestCostAccountingIsOverflowSafe(t *testing.T) {
	budget := budgetCounter{used: math.MaxInt - 1, max: math.MaxInt}
	requireCostResourceExhausted(t, budget.add(2))
	if budget.used != math.MaxInt-1 {
		t.Fatalf("overflowing add mutated used = %d", budget.used)
	}

	budget = budgetCounter{max: math.MaxInt}
	requireCostResourceExhausted(t, budget.addMany(math.MaxInt, 2))
	if budget.used != 0 {
		t.Fatalf("overflowing addMany mutated used = %d", budget.used)
	}

	budget = budgetCounter{used: -1, max: math.MaxInt}
	requireCostResourceExhausted(t, budget.add(1))
}

func TestConstructorProducedAggregateValuesPassValid(t *testing.T) {
	now := time.Date(2026, time.July, 29, 14, 0, 0, 0, time.UTC)
	revisionID := strings.Repeat("a", 64)
	parsedRevision, err := ParseRevisionID(revisionID)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	caller, err := NewCaller("caller", map[string]string{"issuer": "adapter"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewGrant("acme", []Capability{CapabilityPolicyRead, CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := NewCallerAuthorization([]Grant{grant})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewEvidenceBinding(EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: "acme", Selector: selector,
		RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now,
		Fingerprint: NewEvidenceFingerprint([32]byte{1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := NewApprovalVerificationRequest(binding, []string{"manager"}, []byte("approval"))
	if err != nil {
		t.Fatal(err)
	}
	approvalResult, err := NewApprovalVerificationResult([]string{"manager"})
	if err != nil {
		t.Fatal(err)
	}
	delegationRequest, err := NewDelegationVerificationRequest(binding, []byte("delegation"))
	if err != nil {
		t.Fatal(err)
	}
	contextual, err := NewContextualData(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	delegationResult, err := NewDelegationVerificationResult(contextual)
	if err != nil {
		t.Fatal(err)
	}
	publish, err := NewPublishRequest("acme", "policy.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatal(err)
	}
	revision, err := NewRevisionMetadata("acme", parsedRevision, now)
	if err != nil {
		t.Fatal(err)
	}
	revisionListRequest, err := NewListRevisionsRequest("acme", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	revisionPage, err := NewListRevisionsResponse(revisionListRequest, []RevisionMetadata{revision}, "next")
	if err != nil {
		t.Fatal(err)
	}
	activation, err := NewActivation("acme", "stable", revisionID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	activationListRequest, err := NewListActivationHistoryRequest("acme", "stable", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	activationPage, err := NewListActivationHistoryResponse(activationListRequest, []Activation{activation}, "next")
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewStateEvent(StateEventInput{Namespace: "acme", Cursor: "one", Kind: StateEventRevisionPublished, RevisionID: revisionID, OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}
	eventListRequest, err := NewListEventsRequest("acme", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	eventPage, err := NewListEventsResponse(eventListRequest, []StateEvent{event}, "next")
	if err != nil {
		t.Fatal(err)
	}
	component, err := NewComponentStatus("store", ComponentReady, "READY")
	if err != nil {
		t.Fatal(err)
	}
	status, err := NewStatusResponse(true, []ComponentStatus{component})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := NewDecisionResult(DecisionResultInput{Decision: DecisionAllow, DecisionID: "decision", ReasonCode: "ALLOWED", RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	check, err := NewCheckRequest(CheckRequestInput{Namespace: "acme", Selector: selector, Subject: dsl.EntityRef{Type: "user", ID: "alice"}, Resource: dsl.EntityRef{Type: "document", ID: "one"}, Action: "read"})
	if err != nil {
		t.Fatal(err)
	}
	checkResponse, err := NewCheckResponse(check, decision)
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewBatchCheckItem(check.subject, check.resource, check.action, nil)
	if err != nil {
		t.Fatal(err)
	}
	batchRequest, err := NewBatchCheckRequest(BatchCheckRequestInput{Namespace: "acme", Selector: selector, Items: []BatchCheckItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	batchResponse, err := NewBatchCheckResponse(batchRequest, []DecisionResult{decision})
	if err != nil {
		t.Fatal(err)
	}
	explainRequest, err := NewExplainRequest(check)
	if err != nil {
		t.Fatal(err)
	}
	step, err := NewExplainStep("document.read", "relation", true)
	if err != nil {
		t.Fatal(err)
	}
	explainResponse, err := NewExplainResponse(explainRequest, decision, []ExplainStep{step})
	if err != nil {
		t.Fatal(err)
	}
	tupleKey, err := NewTupleKey(dsl.Tuple{Resource: dsl.EntityRef{Type: "document", ID: "one"}, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	write, err := NewWriteDataRequest(WriteDataRequestInput{Namespace: "acme", ValidationRevisionID: revisionID, IdempotencyKey: "write", TupleDeletes: []TupleKey{tupleKey}})
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string]bool{
		"caller": caller.valid(), "grant": grant.valid(), "authorization": authorization.valid(),
		"binding": binding.valid(), "approval request": approvalRequest.valid(), "approval result": approvalResult.valid(),
		"delegation request": delegationRequest.valid(), "delegation result": delegationResult.valid(),
		"publish": publish.valid(), "revision": revision.valid(), "revision page": revisionPage.valid(),
		"activation": activation.valid(), "activation page": activationPage.valid(), "event": event.valid(),
		"event page": eventPage.valid(), "component": component.valid(), "status": status.valid(),
		"contextual": contextual.valid(), "write": write.valid(), "check": check.valid(),
		"check response": checkResponse.valid(), "batch request": batchRequest.valid(), "batch response": batchResponse.valid(),
		"explain request": explainRequest.valid(), "decision": decision.valid(), "explain response": explainResponse.valid(),
	}
	for name, valid := range checks {
		if !valid {
			t.Errorf("constructor-produced %s failed valid()", name)
		}
	}
}

func TestForgedZeroAggregateValuesFailValid(t *testing.T) {
	checks := map[string]bool{
		"caller": Caller{}.valid(), "grant": Grant{}.valid(), "authorization": CallerAuthorization{}.valid(),
		"binding": EvidenceBinding{}.valid(), "approval request": ApprovalVerificationRequest{}.valid(),
		"approval result": ApprovalVerificationResult{}.valid(), "delegation request": DelegationVerificationRequest{}.valid(),
		"delegation result": DelegationVerificationResult{}.valid(), "publish": PublishRequest{}.valid(),
		"revision": RevisionMetadata{}.valid(), "revision page": ListRevisionsResponse{}.valid(),
		"activation": Activation{}.valid(), "activation page": ListActivationHistoryResponse{}.valid(),
		"event": StateEvent{}.valid(), "event page": ListEventsResponse{}.valid(), "component": ComponentStatus{}.valid(),
		"status": StatusResponse{}.valid(), "write": WriteDataRequest{}.valid(), "check": CheckRequest{}.valid(),
		"check response": CheckResponse{}.valid(), "batch request": BatchCheckRequest{}.valid(),
		"batch response": BatchCheckResponse{}.valid(), "explain request": ExplainRequest{}.valid(),
		"decision": DecisionResult{}.valid(), "explain response": ExplainResponse{}.valid(),
	}
	for name, valid := range checks {
		if valid {
			t.Errorf("forged zero %s passed valid()", name)
		}
	}
}

func TestForgedNonCanonicalCollectionsFailValid(t *testing.T) {
	first, err := NewAttribute(dsl.EntityRef{Type: "document", ID: "one"}, "a", NewBooleanValue(true))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAttribute(dsl.EntityRef{Type: "document", ID: "one"}, "b", NewBooleanValue(true))
	if err != nil {
		t.Fatal(err)
	}
	if (ContextualData{attributes: []Attribute{second, first}}).valid() {
		t.Fatal("unsorted contextual attributes passed valid()")
	}
	if (ContextualData{attributes: []Attribute{first, first}}).valid() {
		t.Fatal("duplicate contextual attributes passed valid()")
	}

	unsortedGrant := Grant{
		namespacePattern: "acme",
		capabilities:     []Capability{CapabilityAuthorizationCheck, CapabilityPolicyRead},
	}
	if unsortedGrant.valid() {
		t.Fatal("unsorted grant capabilities passed valid()")
	}
	readGrant, err := NewGrant("z", []Capability{CapabilityPolicyRead})
	if err != nil {
		t.Fatal(err)
	}
	otherGrant, err := NewGrant("a", []Capability{CapabilityPolicyRead})
	if err != nil {
		t.Fatal(err)
	}
	if (CallerAuthorization{grants: []Grant{readGrant, otherGrant}}).valid() {
		t.Fatal("unsorted caller grants passed valid()")
	}

	firstTuple, err := NewTupleKey(dsl.Tuple{Resource: dsl.EntityRef{Type: "document", ID: "one"}, Relation: "a", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	secondTuple, err := NewTupleKey(dsl.Tuple{Resource: dsl.EntityRef{Type: "document", ID: "one"}, Relation: "b", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	forgedWrite := WriteDataRequest{
		namespace: "acme", validationRevisionID: strings.Repeat("a", 64), idempotencyKey: "write",
		tupleDeletes: []TupleKey{secondTuple, firstTuple},
	}
	if forgedWrite.valid() {
		t.Fatal("unsorted write mutations passed valid()")
	}

	forgedApproval := ApprovalVerificationResult{validResult: true, satisfiedRequirementIDs: []string{"z", "a"}}
	if forgedApproval.valid() {
		t.Fatal("unsorted approval identifiers passed valid()")
	}
	forgedDecision := DecisionResult{
		validResult: true, decision: DecisionRequireApproval, decisionID: "decision", reasonCode: "APPROVAL",
		revisionID: strings.Repeat("a", 64), evaluatedAt: time.Unix(1, 0), requirements: []string{"z", "a"},
	}
	if forgedDecision.valid() {
		t.Fatal("unsorted decision requirements passed valid()")
	}

	ready, err := NewComponentStatus("a", ComponentReady, "READY")
	if err != nil {
		t.Fatal(err)
	}
	later, err := NewComponentStatus("z", ComponentReady, "READY")
	if err != nil {
		t.Fatal(err)
	}
	if (StatusResponse{validResponse: true, components: []ComponentStatus{later, ready}}).valid() {
		t.Fatal("unsorted status components passed valid()")
	}
}

func TestForgedExplainResponseWithMismatchedSelectorFailsValid(t *testing.T) {
	result := DecisionResult{
		validResult: true,
		decision:    DecisionAllow,
		decisionID:  "decision",
		reasonCode:  "ALLOWED",
		revisionID:  strings.Repeat("a", 64),
		evaluatedAt: time.Unix(1, 0),
	}
	response := ExplainResponse{
		selector: Selector{revisionID: strings.Repeat("b", 64)},
		result:   result,
	}
	if response.valid() {
		t.Fatal("explain response with mismatched exact selector passed valid()")
	}
}
