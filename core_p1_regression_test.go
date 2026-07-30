package policyengine_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

func distinctRevisionIDs(t *testing.T) (string, string) {
	t.Helper()

	compile := func(name, source string) string {
		t.Helper()
		artifact, err := dsl.CompileArtifact(name, []byte(source))
		if err != nil {
			t.Fatalf("CompileArtifact(%q) error = %v", name, err)
		}
		id, err := policyengine.RevisionIDFromArtifact(artifact)
		if err != nil {
			t.Fatalf("RevisionIDFromArtifact(%q) error = %v", name, err)
		}
		return id.String()
	}

	first := compile("first.cdr", "entity user {}")
	second := compile("second.cdr", "entity document {}")
	if first == second {
		t.Fatal("distinct DSL artifacts produced the same revision ID")
	}
	return first, second
}

func relationalCheckRequest(t *testing.T, selector policyengine.Selector) policyengine.CheckRequest {
	t.Helper()
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "acme",
		Selector:  selector,
		Subject:   dsl.EntityRef{Type: "user", ID: "u-1"},
		Resource:  dsl.EntityRef{Type: "document", ID: "d-1"},
		Action:    "view",
	})
	if err != nil {
		t.Fatalf("NewCheckRequest() error = %v", err)
	}
	return request
}

func relationalDecision(t *testing.T, revisionID string, slotGeneration uint64) policyengine.DecisionResult {
	t.Helper()
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision:       policyengine.DecisionAllow,
		DecisionID:     "decision-1",
		ReasonCode:     "GRAPH_ALLOWED",
		RevisionID:     revisionID,
		SlotGeneration: slotGeneration,
		DataGeneration: 7,
		EvaluatedAt:    time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewDecisionResult() error = %v", err)
	}
	return result
}

func TestExactSelectorBindingsRejectDifferentRealArtifactRevision(t *testing.T) {
	t.Parallel()

	revisionA, revisionB := distinctRevisionIDs(t)
	caller, err := policyengine.NewCaller("caller-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := policyengine.NewSelector("", revisionA)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := policyengine.NewEvidenceFingerprint(sha256.Sum256([]byte("request")))
	input := policyengine.EvidenceBindingInput{
		Caller:         caller.Binding(),
		Namespace:      "acme",
		Selector:       exact,
		RevisionID:     revisionA,
		SlotGeneration: 0,
		DataGeneration: 7,
		EvaluatedAt:    time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC),
		Fingerprint:    fingerprint,
	}
	if _, err := policyengine.NewEvidenceBinding(input); err != nil {
		t.Fatalf("matching exact evidence binding error = %v", err)
	}
	input.RevisionID = revisionB
	if _, err := policyengine.NewEvidenceBinding(input); err == nil {
		t.Fatal("exact evidence binding accepted a different resolved revision")
	}

	slot, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	input.Selector = slot
	input.SlotGeneration = 1
	if _, err := policyengine.NewEvidenceBinding(input); err != nil {
		t.Fatalf("slot evidence binding with resolved revision error = %v", err)
	}
}

func TestResponsesBindOriginatingSelectorToResultSnapshot(t *testing.T) {
	t.Parallel()

	revisionA, revisionB := distinctRevisionIDs(t)
	exact, err := policyengine.NewSelector("", revisionA)
	if err != nil {
		t.Fatal(err)
	}
	exactCheck := relationalCheckRequest(t, exact)
	matchingExact := relationalDecision(t, revisionA, 0)
	mismatchingExact := relationalDecision(t, revisionB, 0)

	if _, err := policyengine.NewCheckResponse(exactCheck, matchingExact); err != nil {
		t.Fatalf("matching exact check response error = %v", err)
	}
	if _, err := policyengine.NewCheckResponse(exactCheck, mismatchingExact); err == nil {
		t.Fatal("exact check response accepted a different result revision")
	}

	explainRequest, err := policyengine.NewExplainRequest(exactCheck)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewExplainResponse(explainRequest, matchingExact, nil); err != nil {
		t.Fatalf("matching exact explain response error = %v", err)
	}
	if _, err := policyengine.NewExplainResponse(explainRequest, mismatchingExact, nil); err == nil {
		t.Fatal("exact explain response accepted a different result revision")
	}

	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "u-1"},
		dsl.EntityRef{Type: "document", ID: "d-1"},
		"view",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: "acme",
		Selector:  exact,
		Items:     []policyengine.BatchCheckItem{item},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewBatchCheckResponse(batch, []policyengine.DecisionResult{matchingExact}); err != nil {
		t.Fatalf("matching exact batch response error = %v", err)
	}
	if _, err := policyengine.NewBatchCheckResponse(batch, []policyengine.DecisionResult{mismatchingExact}); err == nil {
		t.Fatal("exact batch response accepted a different result revision")
	}

	slot, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	slotCheck := relationalCheckRequest(t, slot)
	slotResult := relationalDecision(t, revisionB, 1)
	if _, err := policyengine.NewCheckResponse(slotCheck, slotResult); err != nil {
		t.Fatalf("matching slot check response error = %v", err)
	}
	slotExplain, err := policyengine.NewExplainRequest(slotCheck)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewExplainResponse(slotExplain, slotResult, nil); err != nil {
		t.Fatalf("matching slot explain response error = %v", err)
	}
}

func approvalBinding(t *testing.T) policyengine.EvidenceBinding {
	t.Helper()
	revisionID, _ := distinctRevisionIDs(t)
	caller, err := policyengine.NewCaller("caller-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller:         caller.Binding(),
		Namespace:      "acme",
		Selector:       selector,
		RevisionID:     revisionID,
		SlotGeneration: 1,
		EvaluatedAt:    time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC),
		Fingerprint:    policyengine.NewEvidenceFingerprint(sha256.Sum256([]byte("approval"))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestApprovalVerifierResultIsRequestedSubset(t *testing.T) {
	t.Parallel()

	request, err := policyengine.NewApprovalVerificationRequest(
		approvalBinding(t),
		[]string{"manager", "security"},
		[]byte("opaque-evidence"),
	)
	if err != nil {
		t.Fatal(err)
	}

	for name, ids := range map[string][]string{
		"requested subset":   {"manager"},
		"exact complete set": {"security", "manager"},
	} {
		t.Run(name, func(t *testing.T) {
			result, resultErr := policyengine.NewApprovalVerificationResult(ids)
			if resultErr != nil {
				t.Fatal(resultErr)
			}
			got, invokeErr := policyengine.InvokeApprovalVerifier(context.Background(), approvalVerifierFunc(
				func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
					return result, nil
				},
			), request)
			if invokeErr != nil {
				t.Fatalf("InvokeApprovalVerifier() error = %v", invokeErr)
			}
			if len(got.SatisfiedRequirementIDs()) != len(ids) {
				t.Fatalf("satisfied IDs = %#v", got.SatisfiedRequirementIDs())
			}
		})
	}

	unknown, err := policyengine.NewApprovalVerificationResult([]string{"attacker-controlled-unknown"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policyengine.InvokeApprovalVerifier(context.Background(), approvalVerifierFunc(
		func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
			return unknown, nil
		},
	), request)
	if !isCategory(err, policyengine.ErrorInternal) || strings.Contains(err.Error(), "attacker-controlled") {
		t.Fatalf("unknown satisfied ID error = %#v", err)
	}

	secret := "hostile-extension-secret"
	_, err = policyengine.InvokeApprovalVerifier(context.Background(), approvalVerifierFunc(
		func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
			return policyengine.ApprovalVerificationResult{}, errors.New(secret)
		},
	), request)
	if !isCategory(err, policyengine.ErrorUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("hostile verifier error = %#v", err)
	}
}

func TestApprovalRequirementIDsUseSharedValidation(t *testing.T) {
	t.Parallel()

	binding := approvalBinding(t)
	malformed := []string{"bad\x00id", "bad\u2060id", string([]byte{0xff})}
	for _, id := range malformed {
		if _, err := policyengine.NewApprovalVerificationRequest(binding, []string{id}, []byte("evidence")); !isCategory(err, policyengine.ErrorInvalidArgument) {
			t.Fatalf("request malformed ID %q error = %#v", id, err)
		}
		if _, err := policyengine.NewApprovalVerificationResult([]string{id}); !isCategory(err, policyengine.ErrorInvalidArgument) {
			t.Fatalf("result malformed ID %q error = %#v", id, err)
		}
	}

	oversized := strings.Repeat("x", policyengine.MaxIdentifierBytes+1)
	if _, err := policyengine.NewApprovalVerificationRequest(binding, []string{oversized}, []byte("evidence")); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("request oversized ID error = %#v", err)
	}
	if _, err := policyengine.NewApprovalVerificationResult([]string{oversized}); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("result oversized ID error = %#v", err)
	}
}

func TestPublicConstructorsUseSharedNamespaceAndIdentifierValidation(t *testing.T) {
	t.Parallel()

	revisionID, _ := distinctRevisionIDs(t)
	now := time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC)
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "u-1"},
		dsl.EntityRef{Type: "document", ID: "d-1"},
		"view",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tupleKey, err := policyengine.NewTupleKey(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "d-1"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "u-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := policyengine.ParseRevisionID(revisionID)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := policyengine.NewRevisionMetadata("acme", revision, now)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := policyengine.NewActivation("acme", "stable", revisionID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	event, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace:  "acme",
		Cursor:     "cursor-1",
		Kind:       policyengine.StateEventRevisionPublished,
		RevisionID: revisionID,
		OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	revisionPageRequest, err := policyengine.NewListRevisionsRequest("acme", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	activationPageRequest, err := policyengine.NewListActivationHistoryRequest("acme", "stable", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	eventPageRequest, err := policyengine.NewListEventsRequest("acme", "", 1)
	if err != nil {
		t.Fatal(err)
	}

	unsafeNamespace := "bad\x00namespace"
	unsafeIdentifier := "bad\u2060identifier"
	tests := []struct {
		name string
		call func() error
	}{
		{"activation history namespace", func() error {
			_, err := policyengine.NewListActivationHistoryRequest(unsafeNamespace, "stable", "", 1)
			return err
		}},
		{"activation history slot", func() error {
			_, err := policyengine.NewListActivationHistoryRequest("acme", unsafeIdentifier, "", 1)
			return err
		}},
		{"activation history cursor", func() error {
			_, err := policyengine.NewListActivationHistoryRequest("acme", "stable", unsafeIdentifier, 1)
			return err
		}},
		{"data head namespace", func() error { _, err := policyengine.NewGetDataGenerationRequest(unsafeNamespace); return err }},
		{"status authorization namespace", func() error { _, err := policyengine.NewStatusRequest(unsafeNamespace); return err }},
		{"batch namespace wildcard", func() error {
			_, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: "*", Selector: selector, Items: []policyengine.BatchCheckItem{item}})
			return err
		}},
		{"write namespace wildcard", func() error {
			_, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{Namespace: "*", ValidationRevisionID: revisionID, IdempotencyKey: "key", TupleDeletes: []policyengine.TupleKey{tupleKey}})
			return err
		}},
		{"write idempotency key", func() error {
			_, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{Namespace: "acme", ValidationRevisionID: revisionID, IdempotencyKey: unsafeIdentifier, TupleDeletes: []policyengine.TupleKey{tupleKey}})
			return err
		}},
		{"decision ID", func() error {
			_, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{Decision: policyengine.DecisionAllow, DecisionID: unsafeIdentifier, ReasonCode: "ALLOW", RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now})
			return err
		}},
		{"decision reason", func() error {
			_, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{Decision: policyengine.DecisionAllow, DecisionID: "decision", ReasonCode: unsafeIdentifier, RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now})
			return err
		}},
		{"decision requirement", func() error {
			_, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{Decision: policyengine.DecisionRequireApproval, DecisionID: "decision", ReasonCode: "APPROVAL", RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now, Requirements: []string{unsafeIdentifier}})
			return err
		}},
		{"completed event reason", func() error {
			_, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{Decision: policyengine.DecisionAllow, ReasonCode: unsafeIdentifier, RevisionID: revisionID, SlotGeneration: 1, CompletedAt: now})
			return err
		}},
		{"revision response cursor", func() error {
			_, err := policyengine.NewListRevisionsResponse(revisionPageRequest, []policyengine.RevisionMetadata{metadata}, unsafeIdentifier)
			return err
		}},
		{"activation response cursor", func() error {
			_, err := policyengine.NewListActivationHistoryResponse(activationPageRequest, []policyengine.Activation{activation}, unsafeIdentifier)
			return err
		}},
		{"event response cursor", func() error {
			_, err := policyengine.NewListEventsResponse(eventPageRequest, []policyengine.StateEvent{event}, unsafeIdentifier)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}

	oversizedNamespace := strings.Repeat("n", policyengine.MaxNamespaceBytes+1)
	for name, call := range map[string]func() error{
		"data head": func() error { _, err := policyengine.NewGetDataGenerationRequest(oversizedNamespace); return err },
		"status":    func() error { _, err := policyengine.NewStatusRequest(oversizedNamespace); return err },
		"batch": func() error {
			_, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: oversizedNamespace, Selector: selector, Items: []policyengine.BatchCheckItem{item}})
			return err
		},
		"write": func() error {
			_, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{Namespace: oversizedNamespace, ValidationRevisionID: revisionID, IdempotencyKey: "key", TupleDeletes: []policyengine.TupleKey{tupleKey}})
			return err
		},
	} {
		t.Run(name+" oversized namespace", func(t *testing.T) {
			if err := call(); !isCategory(err, policyengine.ErrorResourceExhausted) {
				t.Fatalf("error = %#v, want RESOURCE_EXHAUSTED", err)
			}
		})
	}

	if _, err := policyengine.NewListActivationHistoryRequest("acme", "stable", "", 1); err != nil {
		t.Fatalf("empty optional activation cursor error = %v", err)
	}
	if _, err := policyengine.NewListRevisionsResponse(revisionPageRequest, []policyengine.RevisionMetadata{metadata}, ""); err != nil {
		t.Fatalf("empty optional revision response cursor error = %v", err)
	}
}

func TestNestedZeroValuesAreRejectedAtPublicBoundaries(t *testing.T) {
	t.Parallel()

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"publish response": func() error {
			_, err := policyengine.NewPublishResponse(policyengine.RevisionMetadata{}, false)
			return err
		},
		"batch item": func() error {
			_, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: "acme", Selector: selector, Items: []policyengine.BatchCheckItem{{}}})
			return err
		},
		"context tuple": func() error {
			_, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{{}}, nil)
			return err
		},
		"status component": func() error {
			_, err := policyengine.NewStatusResponse(false, []policyengine.ComponentStatus{{}})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func maxStringValue(t testing.TB) policyengine.Value {
	t.Helper()
	return mustStringValue(t, strings.Repeat("v", policyengine.MaxStringValueBytes))
}

func aggregateAttributes(t *testing.T, count int) []policyengine.Attribute {
	t.Helper()
	value := maxStringValue(t)
	attributes := make([]policyengine.Attribute, count)
	for index := range attributes {
		attribute, err := policyengine.NewAttribute(
			dsl.EntityRef{Type: "document", ID: fmt.Sprintf("document-%d", index)},
			"classification",
			value,
		)
		if err != nil {
			t.Fatalf("NewAttribute(%d) error = %v", index, err)
		}
		attributes[index] = attribute
	}
	return attributes
}

func TestAggregateByteBudgetsRejectCombinedValidValues(t *testing.T) {
	value := maxStringValue(t)

	if _, err := policyengine.NewContextualData(nil, aggregateAttributes(t, 65)); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized contextual data error = %#v", err)
	}

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	items := make([]policyengine.BatchCheckItem, 65)
	for index := range items {
		item, itemErr := policyengine.NewBatchCheckItem(
			dsl.EntityRef{Type: "user", ID: fmt.Sprintf("user-%d", index)},
			dsl.EntityRef{Type: "document", ID: fmt.Sprintf("document-%d", index)},
			"view",
			map[string]policyengine.Value{"payload": value},
		)
		if itemErr != nil {
			t.Fatal(itemErr)
		}
		items[index] = item
	}
	if _, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: "acme", Selector: selector, Items: items}); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized batch error = %#v", err)
	}

	revisionID, _ := distinctRevisionIDs(t)
	if _, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "acme",
		ValidationRevisionID: revisionID,
		IdempotencyKey:       "write-1",
		AttributeWrites:      aggregateAttributes(t, 65),
	}); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized mutation error = %#v", err)
	}

	contextual, err := policyengine.NewContextualData(nil, aggregateAttributes(t, 40))
	if err != nil {
		t.Fatal(err)
	}
	arguments := make(map[string]policyengine.Value, 40)
	for index := 0; index < 40; index++ {
		arguments[fmt.Sprintf("argument-%d", index)] = value
	}
	if _, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace:      "acme",
		Selector:       selector,
		Subject:        dsl.EntityRef{Type: "user", ID: "u-1"},
		Resource:       dsl.EntityRef{Type: "document", ID: "d-1"},
		Action:         "view",
		Arguments:      arguments,
		ContextualData: contextual,
	}); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized complete check error = %#v", err)
	}
}

func TestVerifierAndExplainAggregateOutputsAreBounded(t *testing.T) {
	tuples := make([]policyengine.RelationshipTuple, 600)
	for index := range tuples {
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: fmt.Sprintf("d-%d", index)},
			Relation: "viewer",
			Subject:  dsl.SubjectRef{Type: "user", ID: fmt.Sprintf("u-%d", index)},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		tuples[index] = tuple
	}
	attributes := make([]policyengine.Attribute, 600)
	for index := range attributes {
		attribute, err := policyengine.NewAttribute(
			dsl.EntityRef{Type: "document", ID: fmt.Sprintf("d-%d", index)},
			"flag",
			policyengine.NewBooleanValue(true),
		)
		if err != nil {
			t.Fatal(err)
		}
		attributes[index] = attribute
	}
	contextual, err := policyengine.NewContextualData(tuples, attributes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewDelegationVerificationResult(contextual); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("combined delegation output items error = %#v", err)
	}

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	check := relationalCheckRequest(t, selector)
	explain, err := policyengine.NewExplainRequest(check)
	if err != nil {
		t.Fatal(err)
	}
	result := relationalDecision(t, testRevisionID(t), 1)
	field := strings.Repeat("s", 800)
	steps := make([]policyengine.ExplainStep, 3000)
	for index := range steps {
		step, stepErr := policyengine.NewExplainStep(field, field, index%2 == 0)
		if stepErr != nil {
			t.Fatal(stepErr)
		}
		steps[index] = step
	}
	if _, err := policyengine.NewExplainResponse(explain, result, steps); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized explanation error = %#v", err)
	}
}

func TestAggregateWorkLimitAppliesAcrossBatchItems(t *testing.T) {
	arguments := make(map[string]policyengine.Value, 101)
	for index := 0; index < 101; index++ {
		arguments[fmt.Sprintf("a-%d", index)] = policyengine.NewBooleanValue(true)
	}
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems)
	for index := range items {
		item, err := policyengine.NewBatchCheckItem(
			dsl.EntityRef{Type: "user", ID: "u"},
			dsl.EntityRef{Type: "document", ID: "d"},
			"view",
			arguments,
		)
		if err != nil {
			t.Fatal(err)
		}
		items[index] = item
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: "acme", Selector: selector, Items: items}); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("batch aggregate work error = %#v", err)
	}
}

func TestValidateTextChecksHardByteLimitBeforeRuneScan(t *testing.T) {
	value := "\x00" + strings.Repeat("x", policyengine.MaxIdentifierBytes)
	if _, err := policyengine.NewCaller(value, nil); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized malformed identifier error = %#v", err)
	}
}
