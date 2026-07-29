package policyengine_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
)

func TestTask5RevisionIdentityAndPolicyReadAreMetadataOnly(t *testing.T) {
	t.Parallel()

	artifact, err := dsl.CompileArtifact("policy.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	if got, want := id.String(), fmt.Sprintf("%x", artifact.Digest()); got != want {
		t.Fatalf("revision ID = %q, want artifact digest %q", got, want)
	}
	if _, err := policyengine.ParseRevisionID("not-the-artifact-digest"); err == nil {
		t.Fatal("ParseRevisionID(arbitrary) error = nil")
	}
	metadata, err := policyengine.NewRevisionMetadata("acme", id, time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	response, err := policyengine.NewGetRevisionResponse(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{metadata, response, policyengine.PublishResponse{}, policyengine.ListRevisionsResponse{}} {
		typ := reflect.TypeOf(value)
		for _, forbidden := range []string{"Artifact", "CanonicalSource", "CanonicalIR", "IR", "Source"} {
			if _, ok := typ.MethodByName(forbidden); ok {
				t.Fatalf("%s exposes forbidden %s accessor", typ, forbidden)
			}
		}
	}
	if _, err := policyengine.NewGetRevisionRequest("acme", "not-the-artifact-digest"); err == nil {
		t.Fatal("arbitrary lookup revision ID accepted")
	}
	if _, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision: policyengine.DecisionAllow, DecisionID: "d", ReasonCode: "R",
		RevisionID: "not-the-artifact-digest", EvaluatedAt: time.Now(),
	}); err == nil {
		t.Fatal("arbitrary decision revision ID accepted")
	}
}

func TestTask5BatchResponseRequiresCompleteSingleSnapshot(t *testing.T) {
	t.Parallel()

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "alice"},
		dsl.EntityRef{Type: "document", ID: "one"},
		"read",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: "acme", Selector: selector, Items: []policyengine.BatchCheckItem{item, item},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	first := mustDecision(t, "decision-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 0, now)
	mixed := mustDecision(t, "decision-2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2, 1, now.Add(time.Second))
	if _, err := policyengine.NewBatchCheckResponse(request, []policyengine.DecisionResult{first}); err == nil {
		t.Fatal("count mismatch accepted")
	}
	if _, err := policyengine.NewBatchCheckResponse(request, []policyengine.DecisionResult{first, mixed}); err == nil {
		t.Fatal("mixed revision/generation/time snapshot accepted")
	}
	second := mustDecision(t, "decision-2", first.RevisionID(), first.SlotGeneration(), first.DataGeneration(), first.EvaluatedAt())
	response, err := policyengine.NewBatchCheckResponse(request, []policyengine.DecisionResult{first, second})
	if err != nil || response.Results()[0].DecisionID() != "decision-1" || response.Results()[1].DecisionID() != "decision-2" {
		t.Fatalf("complete ordered response = %#v, %v", response, err)
	}
}

func mustDecision(t *testing.T, id, revision string, slotGeneration, dataGeneration uint64, evaluatedAt time.Time) policyengine.DecisionResult {
	t.Helper()
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision: policyengine.DecisionAllow, DecisionID: id, ReasonCode: "GRAPH_ALLOWED",
		RevisionID: revision, SlotGeneration: slotGeneration, DataGeneration: dataGeneration, EvaluatedAt: evaluatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTask5EvidenceBindingPreventsReplayAndIsImmutable(t *testing.T) {
	t.Parallel()

	caller, err := policyengine.NewCaller("caller-secret", map[string]string{"issuer": "adapter"})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintA := [32]byte{1}
	fingerprintB := [32]byte{2}
	bindingA, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller:         caller.Binding(),
		Namespace:      "acme",
		Selector:       selector,
		RevisionID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SlotGeneration: 3,
		DataGeneration: 0,
		EvaluatedAt:    time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC),
		Fingerprint:    policyengine.NewEvidenceFingerprint(fingerprintA),
	})
	if err != nil {
		t.Fatalf("NewEvidenceBinding(A) error = %v", err)
	}
	bindingB, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller:         caller.Binding(),
		Namespace:      "acme",
		Selector:       selector,
		RevisionID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SlotGeneration: 3,
		DataGeneration: 0,
		EvaluatedAt:    time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC),
		Fingerprint:    policyengine.NewEvidenceFingerprint(fingerprintB),
	})
	if err != nil {
		t.Fatalf("NewEvidenceBinding(B) error = %v", err)
	}
	if bindingA == bindingB {
		t.Fatal("different complete-request fingerprints are indistinguishable")
	}
	if got := bindingA.Fingerprint().Bytes(); got != fingerprintA {
		t.Fatalf("Fingerprint().Bytes() = %x", got)
	}

	evidence := []byte("opaque-secret")
	requirements := []string{"manager", "admin"}
	approvalA, err := policyengine.NewApprovalVerificationRequest(bindingA, requirements, evidence)
	if err != nil {
		t.Fatalf("NewApprovalVerificationRequest() error = %v", err)
	}
	approvalB, err := policyengine.NewApprovalVerificationRequest(bindingB, requirements, evidence)
	if err != nil {
		t.Fatalf("NewApprovalVerificationRequest(B) error = %v", err)
	}
	if approvalA.Binding() == approvalB.Binding() {
		t.Fatal("same requirements with different binding are indistinguishable")
	}
	requirements[0] = "mutated"
	evidence[0] = 'X'
	gotEvidence := approvalA.Evidence()
	gotEvidence[0] = 'Y'
	if !reflect.DeepEqual(approvalA.RequirementIDs(), []string{"admin", "manager"}) || string(approvalA.Evidence()) != "opaque-secret" {
		t.Fatal("approval request accessors are mutable")
	}

	delegation, err := policyengine.NewDelegationVerificationRequest(bindingA, []byte("delegation"))
	if err != nil || delegation.Binding() != bindingA {
		t.Fatalf("NewDelegationVerificationRequest() = %#v, %v", delegation, err)
	}
}

func TestTask5DataGenerationZeroAndHeadOperation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	decision, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision:       policyengine.DecisionAllow,
		DecisionID:     "decision-0",
		ReasonCode:     "GRAPH_ALLOWED",
		RevisionID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DataGeneration: 0,
		EvaluatedAt:    now,
	})
	if err != nil || decision.DataGeneration() != 0 {
		t.Fatalf("initial generation decision = %#v, %v", decision, err)
	}
	if _, err := policyengine.NewCheckResponse(policyengine.CheckRequest{}, policyengine.DecisionResult{}); err == nil {
		t.Fatal("zero DecisionResult became valid")
	}

	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision:       policyengine.DecisionAllow,
		ReasonCode:     "GRAPH_ALLOWED",
		RevisionID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DataGeneration: 0,
		CompletedAt:    now,
	})
	if err != nil || event.DataGeneration() != 0 {
		t.Fatalf("initial generation completed event = %#v, %v", event, err)
	}

	request, err := policyengine.NewGetDataGenerationRequest("acme")
	if err != nil {
		t.Fatalf("NewGetDataGenerationRequest() error = %v", err)
	}
	if got := request.RequiredCapabilities(); !reflect.DeepEqual(got, []policyengine.Capability{policyengine.CapabilityDataWrite}) {
		t.Fatalf("RequiredCapabilities() = %#v", got)
	}
	response, err := policyengine.NewGetDataGenerationResponse(0)
	if err != nil || response.Generation() != 0 {
		t.Fatalf("NewGetDataGenerationResponse(0) = %#v, %v", response, err)
	}
	if (policyengine.GetDataGenerationResponse{}).Valid() {
		t.Fatal("zero GetDataGenerationResponse became valid")
	}
}

func TestTask5ActivationExpectationIsABASafeAndUnambiguous(t *testing.T) {
	t.Parallel()

	unset := policyengine.NewUnsetSlotExpectation()
	if !unset.IsUnset() {
		t.Fatal("unset expectation does not report UNSET")
	}
	if _, _, ok := unset.Active(); ok {
		t.Fatal("unset expectation reports ACTIVE")
	}

	stale, err := policyengine.NewActiveSlotExpectation("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation(A/gen1) error = %v", err)
	}
	if _, err := policyengine.NewActiveSlotExpectation("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0); err == nil {
		t.Fatal("NewActiveSlotExpectation(A/gen0) error = nil")
	}
	current, err := policyengine.NewActiveSlotExpectation("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 3)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation(A/gen3) error = %v", err)
	}
	if stale == current {
		t.Fatal("A/gen1 and A/gen3 expectations are indistinguishable")
	}

	request, err := policyengine.NewActivateRequest(
		"acme",
		"stable",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		stale,
	)
	if err != nil {
		t.Fatalf("NewActivateRequest() error = %v", err)
	}
	revision, generation, active := request.Expectation().Active()
	if !active || revision != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || generation != 1 {
		t.Fatalf("Expectation().Active() = %q, %d, %v", revision, generation, active)
	}
	if _, err := policyengine.NewActivateRequest("acme", "stable", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", policyengine.SlotExpectation{}); err == nil {
		t.Fatal("NewActivateRequest(ambiguous zero expectation) error = nil")
	}
}
