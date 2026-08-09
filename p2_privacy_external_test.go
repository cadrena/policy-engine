package policyengine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

type redactionCase struct {
	name   string
	value  any
	canary string
}

func assertGenericRedaction(t *testing.T, test redactionCase) {
	t.Helper()

	outputs := map[string]string{
		"%v":     fmt.Sprintf("%v", test.value),
		"%+v":    fmt.Sprintf("%+v", test.value),
		"%#v":    fmt.Sprintf("%#v", test.value),
		"%s":     fmt.Sprintf("%s", test.value),
		"String": fmt.Sprint(test.value),
	}
	if stringer, ok := test.value.(fmt.Stringer); ok {
		outputs["String()"] = stringer.String()
	} else {
		t.Errorf("%T does not implement fmt.Stringer", test.value)
	}
	if goStringer, ok := test.value.(fmt.GoStringer); ok {
		outputs["GoString()"] = goStringer.GoString()
	} else {
		t.Errorf("%T does not implement fmt.GoStringer", test.value)
	}
	var buffer bytes.Buffer
	slog.New(slog.NewTextHandler(&buffer, nil)).Info("value", "value", test.value)
	outputs["slog"] = buffer.String()

	for operation, output := range outputs {
		if strings.Contains(output, test.canary) {
			t.Errorf("%s %s leaked canary %q in %q", test.name, operation, test.canary, output)
		}
	}
}

func TestSecuritySensitiveExportedValuesRedactGenericFormattingAndSlog(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 14, 0, 0, 0, time.UTC)
	revisionID := testRevisionID(t)
	parsedRevisionID, err := policyengine.ParseRevisionID(revisionID)
	if err != nil {
		t.Fatal(err)
	}

	valueCanary := "value-canary-7bb9"
	value := mustStringValue(t, valueCanary)
	tupleCanary := "tuple-canary-4e18"
	rawTuple := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: tupleCanary},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "subject-canary-1d37"},
	}
	tuple, err := policyengine.NewRelationshipTuple(rawTuple, nil)
	if err != nil {
		t.Fatal(err)
	}
	tupleKey, err := policyengine.NewTupleKey(rawTuple)
	if err != nil {
		t.Fatal(err)
	}
	attributeCanary := "attribute-canary-335a"
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: attributeCanary}, "classification", value)
	if err != nil {
		t.Fatal(err)
	}
	attributeKeyCanary := "attribute-key-canary-c2a4"
	attributeKey, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: attributeKeyCanary}, "classification")
	if err != nil {
		t.Fatal(err)
	}
	contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, []policyengine.Attribute{attribute})
	if err != nil {
		t.Fatal(err)
	}

	selectorCanary := "selector-canary-337e"
	selector, err := policyengine.NewSelector(selectorCanary, "")
	if err != nil {
		t.Fatal(err)
	}
	revisionCanary := "revision-namespace-canary-77ac"
	revision, err := policyengine.NewRevisionMetadata(revisionCanary, parsedRevisionID, now)
	if err != nil {
		t.Fatal(err)
	}
	publishCanary := "publish-source-canary-cc91"
	publish, err := policyengine.NewPublishRequest("publish-namespace-canary-6c17", "policy.cdr", []byte(publishCanary))
	if err != nil {
		t.Fatal(err)
	}
	publishResponse, err := policyengine.NewPublishResponse(revision, true)
	if err != nil {
		t.Fatal(err)
	}
	getRevisionCanary := "get-revision-namespace-canary-f831"
	getRevision, err := policyengine.NewGetRevisionRequest(getRevisionCanary, revisionID)
	if err != nil {
		t.Fatal(err)
	}
	getRevisionResponse, err := policyengine.NewGetRevisionResponse(revision)
	if err != nil {
		t.Fatal(err)
	}
	listRevisionsCanary := "list-revisions-cursor-canary-09e1"
	listRevisions, err := policyengine.NewListRevisionsRequest(revisionCanary, listRevisionsCanary, 1)
	if err != nil {
		t.Fatal(err)
	}
	listRevisionsResponse, err := policyengine.NewListRevisionsResponse(listRevisions, []policyengine.RevisionMetadata{revision}, "next-revisions-canary-6ff2")
	if err != nil {
		t.Fatal(err)
	}

	activateCanary := "activate-namespace-canary-a867"
	activate, err := policyengine.NewActivateRequest(activateCanary, "stable", revisionID, policyengine.NewUnsetSlotExpectation())
	if err != nil {
		t.Fatal(err)
	}
	activationCanary := "activation-slot-canary-2db4"
	activation, err := policyengine.NewActivation("activation-namespace-canary-d215", activationCanary, revisionID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	activateResponse, err := policyengine.NewActivateResponse(activation)
	if err != nil {
		t.Fatal(err)
	}
	resolveCanary := "resolve-slot-canary-c183"
	resolve, err := policyengine.NewResolveRequest("resolve-namespace-canary-a431", resolveCanary)
	if err != nil {
		t.Fatal(err)
	}
	resolveResponse, err := policyengine.NewResolveResponse(activation)
	if err != nil {
		t.Fatal(err)
	}
	historyCanary := "history-cursor-canary-a2e7"
	history, err := policyengine.NewListActivationHistoryRequest("activation-namespace-canary-d215", activationCanary, historyCanary, 1)
	if err != nil {
		t.Fatal(err)
	}
	historyResponse, err := policyengine.NewListActivationHistoryResponse(history, []policyengine.Activation{activation}, "next-history-canary-c5b3")
	if err != nil {
		t.Fatal(err)
	}

	writeInput := policyengine.WriteDataRequestInput{
		Namespace:            "write-namespace-canary-e50f",
		ValidationRevisionID: revisionID,
		IdempotencyKey:       "write-idempotency-canary-c783",
		TupleWrites:          []policyengine.RelationshipTuple{tuple},
		AttributeWrites:      []policyengine.Attribute{attribute},
	}
	writeRequest, err := policyengine.NewWriteDataRequest(writeInput)
	if err != nil {
		t.Fatal(err)
	}
	dataHeadCanary := "data-head-namespace-canary-72ae"
	dataHead, err := policyengine.NewGetDataGenerationRequest(dataHeadCanary)
	if err != nil {
		t.Fatal(err)
	}

	callerCanary := "caller-canary-c205"
	caller, err := policyengine.NewCaller(callerCanary, map[string]string{"issuer": "caller-attribute-canary-482a"})
	if err != nil {
		t.Fatal(err)
	}
	grantCanary := "grant-namespace-canary-c391/*"
	grant, err := policyengine.NewGrant(grantCanary, []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
	if err != nil {
		t.Fatal(err)
	}

	checkInput := policyengine.CheckRequestInput{
		Namespace:          "check-namespace-canary-fb15",
		Selector:           selector,
		Subject:            dsl.EntityRef{Type: "user", ID: "check-subject-canary-e013"},
		Resource:           dsl.EntityRef{Type: "document", ID: "check-resource-canary-ae76"},
		Action:             "check-action-canary-2c9e",
		Arguments:          map[string]policyengine.Value{"check-argument-canary-a047": value},
		ContextualData:     contextual,
		ApprovalEvidence:   []byte("check-approval-canary-2510"),
		DelegationEvidence: []byte("check-delegation-canary-d30e"),
	}
	checkRequest, err := policyengine.NewCheckRequest(checkInput)
	if err != nil {
		t.Fatal(err)
	}
	decisionInput := policyengine.DecisionResultInput{
		Decision:              policyengine.DecisionRequireApproval,
		DecisionID:            "decision-id-canary-bba5",
		ReasonCode:            "APPROVAL_REQUIRED",
		RevisionID:            revisionID,
		SlotGeneration:        1,
		EvaluatedAt:           now,
		Requirements:          []string{"decision-requirement-canary-b38c"},
		ApprovalBindingDigest: [32]byte{1},
	}
	decisionResult, err := policyengine.NewDecisionResult(decisionInput)
	if err != nil {
		t.Fatal(err)
	}
	checkResponse, err := policyengine.NewCheckResponse(checkRequest, decisionResult)
	if err != nil {
		t.Fatal(err)
	}
	batchItem, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "batch-subject-canary-082f"},
		dsl.EntityRef{Type: "document", ID: "batch-resource-canary-c832"},
		"batch-action-canary-232f",
		map[string]policyengine.Value{"batch-argument-canary-d29b": value},
	)
	if err != nil {
		t.Fatal(err)
	}
	batchInput := policyengine.BatchCheckRequestInput{
		Namespace: "batch-namespace-canary-33c2", Selector: selector,
		Items: []policyengine.BatchCheckItem{batchItem}, ContextualData: contextual,
		ApprovalEvidence: []byte("batch-approval-canary-39fb"), DelegationEvidence: []byte("batch-delegation-canary-9e1c"),
	}
	batchRequest, err := policyengine.NewBatchCheckRequest(batchInput)
	if err != nil {
		t.Fatal(err)
	}
	batchResponse, err := policyengine.NewBatchCheckResponse(batchRequest, []policyengine.DecisionResult{decisionResult})
	if err != nil {
		t.Fatal(err)
	}
	explainRequest, err := policyengine.NewExplainRequest(checkRequest)
	if err != nil {
		t.Fatal(err)
	}
	explainResponse, err := policyengine.NewExplainResponse(explainRequest, decisionResult, nil)
	if err != nil {
		t.Fatal(err)
	}

	bindingInput := policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: "binding-namespace-canary-f8e5", Selector: selector,
		RevisionID: revisionID, SlotGeneration: 1, EvaluatedAt: now,
		Fingerprint: policyengine.NewEvidenceFingerprint(sha256.Sum256([]byte("fingerprint-canary-digest"))),
	}
	binding, err := policyengine.NewEvidenceBinding(bindingInput)
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := policyengine.NewApprovalVerificationRequest(binding, []string{"approval-requirement-canary-5012"}, []byte("approval-evidence-canary-c4b1"))
	if err != nil {
		t.Fatal(err)
	}
	approvalResult, err := policyengine.NewApprovalVerificationResult([]string{"approval-result-canary-a6df"})
	if err != nil {
		t.Fatal(err)
	}
	delegationRequest, err := policyengine.NewDelegationVerificationRequest(binding, []byte("delegation-evidence-canary-c892"))
	if err != nil {
		t.Fatal(err)
	}
	delegationResult, err := policyengine.NewDelegationVerificationResult(contextual)
	if err != nil {
		t.Fatal(err)
	}

	stateInput := policyengine.StateEventInput{
		Namespace: "event-namespace-canary-f202", Cursor: "event-cursor-canary-1c6a",
		Kind: policyengine.StateEventSlotActivated, RevisionID: revisionID,
		Slot: "event-slot-canary-dac4", SlotGeneration: 1, OccurredAt: now,
	}
	stateEvent, err := policyengine.NewStateEvent(stateInput)
	if err != nil {
		t.Fatal(err)
	}
	listEvents, err := policyengine.NewListEventsRequest("event-namespace-canary-f202", "after-event-canary-02b6", 1)
	if err != nil {
		t.Fatal(err)
	}
	listEventsResponse, err := policyengine.NewListEventsResponse(listEvents, []policyengine.StateEvent{stateEvent}, "next-event-canary-a9b2")
	if err != nil {
		t.Fatal(err)
	}
	statusRequest, err := policyengine.NewStatusRequest("status-namespace-canary-a6f0")
	if err != nil {
		t.Fatal(err)
	}

	optionsCanary := "option-port-canary-c0e2"
	options, err := policyengine.NewOptions(policyengine.WithCallerAuthorizer(canaryAuthorizer{canary: optionsCanary}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []redactionCase{
		{"Value", value, valueCanary},
		{"RelationshipTuple", tuple, tupleCanary},
		{"TupleKey", tupleKey, tupleCanary},
		{"Attribute", attribute, attributeCanary},
		{"AttributeKey", attributeKey, attributeKeyCanary},
		{"ContextualData", contextual, tupleCanary},
		{"Selector", selector, selectorCanary},
		{"RevisionMetadata", revision, revisionCanary},
		{"PublishRequest", publish, publishCanary},
		{"PublishResponse", publishResponse, revisionCanary},
		{"GetRevisionRequest", getRevision, getRevisionCanary},
		{"GetRevisionResponse", getRevisionResponse, revisionCanary},
		{"ListRevisionsRequest", listRevisions, listRevisionsCanary},
		{"ListRevisionsResponse", listRevisionsResponse, "next-revisions-canary-6ff2"},
		{"ActivateRequest", activate, activateCanary},
		{"Activation", activation, activationCanary},
		{"ActivateResponse", activateResponse, activationCanary},
		{"ResolveRequest", resolve, resolveCanary},
		{"ResolveResponse", resolveResponse, activationCanary},
		{"ListActivationHistoryRequest", history, historyCanary},
		{"ListActivationHistoryResponse", historyResponse, "next-history-canary-c5b3"},
		{"GetDataGenerationRequest", dataHead, dataHeadCanary},
		{"WriteDataRequestInput", writeInput, "write-idempotency-canary-c783"},
		{"WriteDataRequest", writeRequest, "write-idempotency-canary-c783"},
		{"Caller", caller, callerCanary},
		{"Grant", grant, grantCanary},
		{"CallerAuthorization", authorization, grantCanary},
		{"CheckRequestInput", checkInput, "check-approval-canary-2510"},
		{"CheckRequest", checkRequest, "check-approval-canary-2510"},
		{"DecisionResultInput", decisionInput, "decision-requirement-canary-b38c"},
		{"DecisionResult", decisionResult, "decision-requirement-canary-b38c"},
		{"CheckResponse", checkResponse, "decision-requirement-canary-b38c"},
		{"BatchCheckItem", batchItem, "batch-argument-canary-d29b"},
		{"BatchCheckRequestInput", batchInput, "batch-approval-canary-39fb"},
		{"BatchCheckRequest", batchRequest, "batch-approval-canary-39fb"},
		{"BatchCheckResponse", batchResponse, "decision-requirement-canary-b38c"},
		{"ExplainRequest", explainRequest, "check-approval-canary-2510"},
		{"ExplainResponse", explainResponse, "decision-requirement-canary-b38c"},
		{"EvidenceBindingInput", bindingInput, "binding-namespace-canary-f8e5"},
		{"EvidenceBinding", binding, "binding-namespace-canary-f8e5"},
		{"ApprovalVerificationRequest", approvalRequest, "approval-evidence-canary-c4b1"},
		{"ApprovalVerificationResult", approvalResult, "approval-result-canary-a6df"},
		{"DelegationVerificationRequest", delegationRequest, "delegation-evidence-canary-c892"},
		{"DelegationVerificationResult", delegationResult, tupleCanary},
		{"StateEventInput", stateInput, "event-cursor-canary-1c6a"},
		{"StateEvent", stateEvent, "event-cursor-canary-1c6a"},
		{"ListEventsRequest", listEvents, "after-event-canary-02b6"},
		{"ListEventsResponse", listEventsResponse, "next-event-canary-a9b2"},
		{"StatusRequest", statusRequest, "status-namespace-canary-a6f0"},
		{"Options", options, optionsCanary},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertGenericRedaction(t, test) })
	}
}

type canaryAuthorizer struct{ canary string }

func (canaryAuthorizer) Authorize(_ context.Context, _ policyengine.Caller, _ string, _ []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	return policyengine.CallerAuthorization{}, nil
}
