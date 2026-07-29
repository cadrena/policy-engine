package policyengine_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
)

func maxUniqueIdentifier(index int) string {
	prefix := fmt.Sprintf("%08d-", index)
	return prefix + strings.Repeat("x", policyengine.MaxIdentifierBytes-len(prefix))
}

func requireResourceExhausted(t *testing.T, err error) {
	t.Helper()
	if !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestAggregateDecisionRequirementsReturnResourceExhausted(t *testing.T) {
	requirements := make([]string, policyengine.MaxVerifierOutputItems+1)
	for index := range requirements {
		requirements[index] = maxUniqueIdentifier(index)
	}
	_, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision:       policyengine.DecisionRequireApproval,
		DecisionID:     "decision",
		ReasonCode:     "APPROVAL_REQUIRED",
		RevisionID:     testRevisionID(t),
		SlotGeneration: 1,
		EvaluatedAt:    time.Date(2026, time.July, 29, 14, 0, 0, 0, time.UTC),
		Requirements:   requirements,
	})
	requireResourceExhausted(t, err)
}

func TestAggregateBatchResponseCountsCombinedResultBytes(t *testing.T) {
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "alice"},
		dsl.EntityRef{Type: "document", ID: "report"},
		"read",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems)
	for index := range items {
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: "acme",
		Selector:  selector,
		Items:     items,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 29, 14, 0, 0, 0, time.UTC)
	revisionID := testRevisionID(t)
	results := make([]policyengine.DecisionResult, len(items))
	for index := range results {
		requirements := make([]string, 5)
		for requirementIndex := range requirements {
			requirements[requirementIndex] = maxUniqueIdentifier(index*len(requirements) + requirementIndex)
		}
		result, resultErr := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
			Decision:       policyengine.DecisionRequireApproval,
			DecisionID:     maxUniqueIdentifier(10_000 + index),
			ReasonCode:     "APPROVAL_REQUIRED",
			RevisionID:     revisionID,
			SlotGeneration: 1,
			EvaluatedAt:    now,
			Requirements:   requirements,
		})
		if resultErr != nil {
			t.Fatalf("NewDecisionResult(%d) error = %v", index, resultErr)
		}
		results[index] = result
	}
	_, err = policyengine.NewBatchCheckResponse(request, results)
	requireResourceExhausted(t, err)
}

func TestAggregateExplainResponseCountsResultAndSteps(t *testing.T) {
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewExplainRequest(relationalCheckRequest(t, selector))
	if err != nil {
		t.Fatal(err)
	}
	result := relationalDecision(t, testRevisionID(t), 1)
	steps := make([]policyengine.ExplainStep, policyengine.MaxExplainSteps)
	for index := range steps {
		step, stepErr := policyengine.NewExplainStep(maxUniqueIdentifier(index), maxUniqueIdentifier(index+policyengine.MaxExplainSteps), index%2 == 0)
		if stepErr != nil {
			t.Fatalf("NewExplainStep(%d) error = %v", index, stepErr)
		}
		steps[index] = step
	}
	_, err = policyengine.NewExplainResponse(request, result, steps)
	requireResourceExhausted(t, err)
}

func TestAggregateConstructorsAcceptReachableLegalMaxima(t *testing.T) {
	now := time.Date(2026, time.July, 29, 14, 0, 0, 0, time.UTC)
	revisionID := testRevisionID(t)
	maxNamespace := maxUniqueIdentifier(90_000)
	maxSlot := maxUniqueIdentifier(90_001)
	selector, err := policyengine.NewSelector(maxSlot, "")
	if err != nil {
		t.Fatal(err)
	}
	caller, err := policyengine.NewCaller(maxUniqueIdentifier(90_002), nil)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: maxNamespace, Selector: selector,
		RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now,
		Fingerprint: policyengine.NewEvidenceFingerprint([32]byte{1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	identifiers := make([]string, policyengine.MaxVerifierOutputItems)
	for index := range identifiers {
		identifiers[index] = maxUniqueIdentifier(index)
	}
	evidence := make([]byte, policyengine.MaxEvidenceBytes)
	if _, err := policyengine.NewApprovalVerificationRequest(binding, identifiers, evidence); err != nil {
		t.Fatalf("maximum reachable approval request error = %v", err)
	}
	if _, err := policyengine.NewDelegationVerificationRequest(binding, evidence); err != nil {
		t.Fatalf("maximum reachable delegation request error = %v", err)
	}
	if _, err := policyengine.NewApprovalVerificationResult(identifiers); err != nil {
		t.Fatalf("maximum reachable approval result error = %v", err)
	}
	if _, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision: policyengine.DecisionRequireApproval, DecisionID: maxUniqueIdentifier(91_000),
		ReasonCode: maxUniqueIdentifier(91_001), RevisionID: revisionID, SlotGeneration: 1,
		EvaluatedAt: now, Requirements: identifiers,
	}); err != nil {
		t.Fatalf("maximum reachable decision result error = %v", err)
	}

	attributes := make(map[string]string, policyengine.MaxCallerAttributes)
	for index := 0; index < policyengine.MaxCallerAttributes; index++ {
		attributes[maxUniqueIdentifier(index)] = strings.Repeat("v", policyengine.MaxIdentifierBytes)
	}
	if _, err := policyengine.NewCaller(maxUniqueIdentifier(92_000), attributes); err != nil {
		t.Fatalf("maximum reachable caller error = %v", err)
	}
	allCapabilities := []policyengine.Capability{
		policyengine.CapabilityPolicyRead, policyengine.CapabilityPolicyPublish, policyengine.CapabilityPolicyActivate,
		policyengine.CapabilityAuthorizationCheck, policyengine.CapabilityAuthorizationContextualData,
		policyengine.CapabilityAuthorizationExplicitRevision, policyengine.CapabilityAuthorizationExplain,
		policyengine.CapabilityDataWrite, policyengine.CapabilityEventsRead, policyengine.CapabilitySystemStatus,
	}
	grants := make([]policyengine.Grant, policyengine.MaxCallerGrants)
	for index := range grants {
		grant, grantErr := policyengine.NewGrant(maxUniqueIdentifier(93_000+index), allCapabilities)
		if grantErr != nil {
			t.Fatal(grantErr)
		}
		grants[index] = grant
	}
	if _, err := policyengine.NewCallerAuthorization(grants); err != nil {
		t.Fatalf("maximum reachable caller authorization error = %v", err)
	}
	if _, err := policyengine.NewPublishRequest(maxNamespace, maxUniqueIdentifier(94_000), make([]byte, policyengine.MaxPolicySourceBytes)); err != nil {
		t.Fatalf("maximum reachable publish request error = %v", err)
	}

	maxValue, err := policyengine.NewStringValue(strings.Repeat("v", policyengine.MaxStringValueBytes))
	if err != nil {
		t.Fatal(err)
	}
	delegatedAttributes := make([]policyengine.Attribute, 61)
	for index := range delegatedAttributes {
		attribute, attributeErr := policyengine.NewAttribute(
			dsl.EntityRef{Type: maxUniqueIdentifier(95_000 + index), ID: maxUniqueIdentifier(96_000 + index)},
			maxUniqueIdentifier(97_000+index),
			maxValue,
		)
		if attributeErr != nil {
			t.Fatal(attributeErr)
		}
		delegatedAttributes[index] = attribute
	}
	contextual, err := policyengine.NewContextualData(nil, delegatedAttributes)
	if err != nil {
		t.Fatalf("maximum reachable contextual data error = %v", err)
	}
	if _, err := policyengine.NewDelegationVerificationResult(contextual); err != nil {
		t.Fatalf("maximum reachable delegation result error = %v", err)
	}

	revisionRequest, err := policyengine.NewListRevisionsRequest(maxNamespace, "", policyengine.MaxPageRequestItems)
	if err != nil {
		t.Fatal(err)
	}
	revisions := make([]policyengine.RevisionMetadata, policyengine.MaxPageResponseItems)
	for index := range revisions {
		id, parseErr := policyengine.ParseRevisionID(fmt.Sprintf("%064x", index+1))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		revision, revisionErr := policyengine.NewRevisionMetadata(maxNamespace, id, now)
		if revisionErr != nil {
			t.Fatal(revisionErr)
		}
		revisions[index] = revision
	}
	if _, err := policyengine.NewListRevisionsResponse(revisionRequest, revisions, maxUniqueIdentifier(98_000)); err != nil {
		t.Fatalf("maximum reachable revision page error = %v", err)
	}
	activationRequest, err := policyengine.NewListActivationHistoryRequest(maxNamespace, maxSlot, "", policyengine.MaxPageRequestItems)
	if err != nil {
		t.Fatal(err)
	}
	activations := make([]policyengine.Activation, policyengine.MaxPageResponseItems)
	for index := range activations {
		activation, activationErr := policyengine.NewActivation(maxNamespace, maxSlot, revisionID, uint64(index+1), now)
		if activationErr != nil {
			t.Fatal(activationErr)
		}
		activations[index] = activation
	}
	if _, err := policyengine.NewListActivationHistoryResponse(activationRequest, activations, maxUniqueIdentifier(98_001)); err != nil {
		t.Fatalf("maximum reachable activation page error = %v", err)
	}
	eventRequest, err := policyengine.NewListEventsRequest(maxNamespace, "", policyengine.MaxPageRequestItems)
	if err != nil {
		t.Fatal(err)
	}
	events := make([]policyengine.StateEvent, policyengine.MaxPageRequestItems)
	for index := range events {
		event, eventErr := policyengine.NewStateEvent(policyengine.StateEventInput{
			Namespace: maxNamespace, Cursor: maxUniqueIdentifier(98_002 + index), Kind: policyengine.StateEventSlotActivated,
			RevisionID: revisionID, Slot: maxSlot, SlotGeneration: uint64(index + 1), OccurredAt: now,
		})
		if eventErr != nil {
			t.Fatal(eventErr)
		}
		events[index] = event
	}
	if _, err := policyengine.NewListEventsResponse(eventRequest, events, maxUniqueIdentifier(99_000)); err != nil {
		t.Fatalf("maximum reachable event page error = %v", err)
	}
	components := make([]policyengine.ComponentStatus, policyengine.MaxStatusComponents)
	for index := range components {
		component, componentErr := policyengine.NewComponentStatus(maxUniqueIdentifier(99_000+index), policyengine.ComponentReady, maxUniqueIdentifier(100_000+index))
		if componentErr != nil {
			t.Fatal(componentErr)
		}
		components[index] = component
	}
	if _, err := policyengine.NewStatusResponse(true, components); err != nil {
		t.Fatalf("maximum reachable status response error = %v", err)
	}
}
