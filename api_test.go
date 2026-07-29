package policyengine_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
)

func testRevisionID(t *testing.T) string {
	t.Helper()
	artifact, err := dsl.CompileArtifact("test.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	return id.String()
}

// embeddedEngine models a transport adapter or embedded implementation and
// keeps the public service surface compile-time checked from an external package.
type embeddedEngine struct{}

var (
	_ policyengine.PolicyService        = (*embeddedEngine)(nil)
	_ policyengine.AuthorizationService = (*embeddedEngine)(nil)
	_ policyengine.DataService          = (*embeddedEngine)(nil)
	_ policyengine.EventsService        = (*embeddedEngine)(nil)
	_ policyengine.SystemService        = (*embeddedEngine)(nil)
	_ policyengine.Engine               = (*embeddedEngine)(nil)
)

func (*embeddedEngine) Publish(context.Context, policyengine.Caller, policyengine.PublishRequest) (policyengine.PublishResponse, error) {
	return policyengine.PublishResponse{}, nil
}

func (*embeddedEngine) GetRevision(context.Context, policyengine.Caller, policyengine.GetRevisionRequest) (policyengine.GetRevisionResponse, error) {
	return policyengine.GetRevisionResponse{}, nil
}

func (*embeddedEngine) ListRevisions(context.Context, policyengine.Caller, policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error) {
	return policyengine.ListRevisionsResponse{}, nil
}

func (*embeddedEngine) Activate(context.Context, policyengine.Caller, policyengine.ActivateRequest) (policyengine.ActivateResponse, error) {
	return policyengine.ActivateResponse{}, nil
}

func (*embeddedEngine) Resolve(context.Context, policyengine.Caller, policyengine.ResolveRequest) (policyengine.ResolveResponse, error) {
	return policyengine.ResolveResponse{}, nil
}

func (*embeddedEngine) ListActivationHistory(context.Context, policyengine.Caller, policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error) {
	return policyengine.ListActivationHistoryResponse{}, nil
}

func (*embeddedEngine) Check(context.Context, policyengine.Caller, policyengine.CheckRequest) (policyengine.CheckResponse, error) {
	return policyengine.CheckResponse{}, nil
}

func (*embeddedEngine) BatchCheck(context.Context, policyengine.Caller, policyengine.BatchCheckRequest) (policyengine.BatchCheckResponse, error) {
	return policyengine.BatchCheckResponse{}, nil
}

func (*embeddedEngine) Explain(context.Context, policyengine.Caller, policyengine.ExplainRequest) (policyengine.ExplainResponse, error) {
	return policyengine.ExplainResponse{}, nil
}

func (*embeddedEngine) GetDataGeneration(context.Context, policyengine.Caller, policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	return policyengine.GetDataGenerationResponse{}, nil
}

func (*embeddedEngine) WriteData(context.Context, policyengine.Caller, policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error) {
	return policyengine.WriteDataResponse{}, nil
}

func (*embeddedEngine) ListEvents(context.Context, policyengine.Caller, policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error) {
	return policyengine.ListEventsResponse{}, nil
}

func (*embeddedEngine) Status(context.Context, policyengine.Caller, policyengine.StatusRequest) (policyengine.StatusResponse, error) {
	return policyengine.StatusResponse{}, nil
}

func TestEmbeddedServiceSurfaceCompiles(t *testing.T) {
	t.Parallel()
}

func TestPolicyValuesAreImmutableAndSelectorIsExclusive(t *testing.T) {
	t.Parallel()

	if _, err := policyengine.NewSelector("", ""); err == nil {
		t.Fatal("NewSelector(empty) error = nil")
	}
	if _, err := policyengine.NewSelector("stable", testRevisionID(t)); err == nil {
		t.Fatal("NewSelector(slot and revision) error = nil")
	}
	slotSelector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatalf("NewSelector(slot) error = %v", err)
	}
	if slot, ok := slotSelector.Slot(); !ok || slot != "stable" {
		t.Fatalf("Slot() = %q, %v, want stable, true", slot, ok)
	}
	if revision, ok := slotSelector.ExactRevision(); ok || revision != "" {
		t.Fatalf("ExactRevision() = %q, %v, want empty, false", revision, ok)
	}
	revisionSelector, err := policyengine.NewSelector("", testRevisionID(t))
	if err != nil {
		t.Fatalf("NewSelector(revision) error = %v", err)
	}
	if revision, ok := revisionSelector.ExactRevision(); !ok || revision != testRevisionID(t) {
		t.Fatalf("ExactRevision() = %q, %v, want rev-1, true", revision, ok)
	}

	source := []byte("entity user {}")
	publish, err := policyengine.NewPublishRequest("acme", "policy.cdr", source)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	source[0] = 'X'
	gotSource := publish.Source()
	if string(gotSource) != "entity user {}" {
		t.Fatalf("Source() = %q after input mutation", gotSource)
	}
	gotSource[0] = 'Y'
	if string(publish.Source()) != "entity user {}" {
		t.Fatal("Source() returned mutable request-owned bytes")
	}
	if publish.Namespace() != "acme" || publish.SourceName() != "policy.cdr" {
		t.Fatalf("publish identity = %q/%q", publish.Namespace(), publish.SourceName())
	}

	artifact, err := dsl.CompileArtifact("policy.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatalf("dsl.CompileArtifact() error = %v", err)
	}
	publishedAt := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	revisionID, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	revision, err := policyengine.NewRevisionMetadata("acme", revisionID, publishedAt)
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	if revision.Namespace() != "acme" || revision.ID() != revisionID.String() || !revision.PublishedAt().Equal(publishedAt) {
		t.Fatal("Revision accessors did not preserve immutable values")
	}

	listRequest, err := policyengine.NewListRevisionsRequest("acme", "", 1)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	listResponse, err := policyengine.NewListRevisionsResponse(listRequest, []policyengine.RevisionMetadata{revision}, "next")
	if err != nil {
		t.Fatalf("NewListRevisionsResponse() error = %v", err)
	}
	listed := listResponse.Revisions()
	listed[0] = policyengine.RevisionMetadata{}
	if !reflect.DeepEqual(listResponse.Revisions(), []policyengine.RevisionMetadata{revision}) {
		t.Fatal("Revisions() returned mutable response-owned state")
	}
	if listResponse.NextCursor() != "next" {
		t.Fatalf("NextCursor() = %q, want next", listResponse.NextCursor())
	}
}

func TestPolicyOperationValuesCoverLifecycleSurface(t *testing.T) {
	t.Parallel()

	artifact, err := dsl.CompileArtifact("policy.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatalf("dsl.CompileArtifact() error = %v", err)
	}
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	revisionID, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	revision, err := policyengine.NewRevisionMetadata("acme", revisionID, now)
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	publishResponse, err := policyengine.NewPublishResponse(revision, true)
	if err != nil || !publishResponse.Created() || publishResponse.Revision().ID() != revisionID.String() {
		t.Fatalf("NewPublishResponse() = %#v, %v", publishResponse, err)
	}
	getRequest, err := policyengine.NewGetRevisionRequest("acme", revisionID.String())
	if err != nil || getRequest.Namespace() != "acme" || getRequest.RevisionID() != revisionID.String() {
		t.Fatalf("NewGetRevisionRequest() = %#v, %v", getRequest, err)
	}
	getResponse, err := policyengine.NewGetRevisionResponse(revision)
	if err != nil || getResponse.Revision().ID() != revisionID.String() {
		t.Fatalf("NewGetRevisionResponse() = %#v, %v", getResponse, err)
	}
	listRequest, err := policyengine.NewListRevisionsRequest("acme", "cursor", 25)
	if err != nil || listRequest.Namespace() != "acme" || listRequest.Cursor() != "cursor" || listRequest.Limit() != 25 {
		t.Fatalf("NewListRevisionsRequest() = %#v, %v", listRequest, err)
	}

	activateRequest, err := policyengine.NewActivateRequest("acme", "stable", testRevisionID(t), policyengine.NewUnsetSlotExpectation())
	if err != nil {
		t.Fatalf("NewActivateRequest() error = %v", err)
	}
	if !activateRequest.Expectation().IsUnset() {
		t.Fatal("Expectation() does not represent unset")
	}
	activation, err := policyengine.NewActivation("acme", "stable", testRevisionID(t), 1, now)
	if err != nil {
		t.Fatalf("NewActivation() error = %v", err)
	}
	activateResponse, err := policyengine.NewActivateResponse(activation)
	if err != nil || activateResponse.Activation().Generation() != 1 {
		t.Fatalf("NewActivateResponse() = %#v, %v", activateResponse, err)
	}
	resolveRequest, err := policyengine.NewResolveRequest("acme", "stable")
	if err != nil || resolveRequest.Namespace() != "acme" || resolveRequest.Slot() != "stable" {
		t.Fatalf("NewResolveRequest() = %#v, %v", resolveRequest, err)
	}
	resolveResponse, err := policyengine.NewResolveResponse(activation)
	if err != nil || resolveResponse.Activation().RevisionID() != testRevisionID(t) {
		t.Fatalf("NewResolveResponse() = %#v, %v", resolveResponse, err)
	}
	historyRequest, err := policyengine.NewListActivationHistoryRequest("acme", "stable", "cursor", 10)
	if err != nil || historyRequest.Limit() != 10 {
		t.Fatalf("NewListActivationHistoryRequest() = %#v, %v", historyRequest, err)
	}
	historyResponse, err := policyengine.NewListActivationHistoryResponse(historyRequest, []policyengine.Activation{activation}, "next")
	if err != nil {
		t.Fatalf("NewListActivationHistoryResponse() error = %v", err)
	}
	history := historyResponse.Activations()
	history[0] = policyengine.Activation{}
	if historyResponse.Activations()[0].RevisionID() != testRevisionID(t) || historyResponse.NextCursor() != "next" {
		t.Fatal("activation history did not return immutable values")
	}
}

func TestAuthorizationRequestsDefensivelyCopyDynamicInputs(t *testing.T) {
	t.Parallel()

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatalf("NewSelector() error = %v", err)
	}
	stringValue := mustStringValue(t, "prod")
	arguments := map[string]policyengine.Value{"environment": stringValue}
	approvalEvidence := []byte("approval-secret")
	delegationEvidence := []byte("delegation-secret")

	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}, nil)
	if err != nil {
		t.Fatalf("NewRelationshipTuple() error = %v", err)
	}
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc-1"}, "classification", stringValue)
	if err != nil {
		t.Fatalf("NewAttribute() error = %v", err)
	}
	contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, []policyengine.Attribute{attribute})
	if err != nil {
		t.Fatalf("NewContextualData() error = %v", err)
	}

	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace:          "acme",
		Selector:           selector,
		Subject:            dsl.EntityRef{Type: "user", ID: "alice"},
		Resource:           dsl.EntityRef{Type: "document", ID: "doc-1"},
		Action:             "read",
		Arguments:          arguments,
		ContextualData:     contextual,
		ApprovalEvidence:   approvalEvidence,
		DelegationEvidence: delegationEvidence,
		MinimumGeneration:  4,
	})
	if err != nil {
		t.Fatalf("NewCheckRequest() error = %v", err)
	}

	arguments["environment"] = mustStringValue(t, "mutated")
	approvalEvidence[0] = 'X'
	delegationEvidence[0] = 'Y'
	gotArguments := request.Arguments()
	gotArguments["environment"] = mustStringValue(t, "again")
	gotApproval := request.ApprovalEvidence()
	gotApproval[0] = 'Z'
	gotDelegation := request.DelegationEvidence()
	gotDelegation[0] = 'Z'

	value, ok := request.Arguments()["environment"].StringValue()
	if !ok || value != "prod" {
		t.Fatalf("Arguments() retained mutable alias: %q, %v", value, ok)
	}
	if string(request.ApprovalEvidence()) != "approval-secret" || string(request.DelegationEvidence()) != "delegation-secret" {
		t.Fatal("evidence accessors retained mutable byte aliases")
	}
	contextTuples := request.ContextualData().Tuples()
	contextTuples[0] = policyengine.RelationshipTuple{}
	if len(request.ContextualData().Tuples()) != 1 {
		t.Fatal("contextual tuples accessor retained mutable slice alias")
	}
	if request.Namespace() != "acme" || request.Action() != "read" || request.MinimumGeneration() != 4 {
		t.Fatal("check request identity accessors did not preserve values")
	}
}

func TestAuthorizationResponseValuesAreBoundedAndImmutable(t *testing.T) {
	t.Parallel()

	if _, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{}); err == nil {
		t.Fatal("NewDecisionResult(invalid decision) error = nil")
	}
	requirements := []string{"manager", "admin", "manager"}
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision:           policyengine.DecisionRequireApproval,
		DecisionID:         "decision-1",
		ReasonCode:         "APPROVAL_REQUIRED",
		RevisionID:         testRevisionID(t),
		SlotGeneration:     2,
		DataGeneration:     4,
		EvaluatedAt:        now,
		Requirements:       requirements,
		UsedContextualData: true,
		UsedApproval:       true,
	})
	if err != nil {
		t.Fatalf("NewDecisionResult() error = %v", err)
	}
	requirements[0] = "mutated"
	gotRequirements := result.Requirements()
	if want := []string{"admin", "manager"}; !reflect.DeepEqual(gotRequirements, want) {
		t.Fatalf("Requirements() = %#v, want %#v", gotRequirements, want)
	}
	gotRequirements[0] = "again"
	if result.Requirements()[0] != "admin" {
		t.Fatal("Requirements() returned mutable result-owned state")
	}
	if result.Decision() != policyengine.DecisionRequireApproval || result.Decision().String() != "REQUIRE_APPROVAL" {
		t.Fatalf("Decision() = %v", result.Decision())
	}
	if policyengine.DecisionAllow.String() != "ALLOW" || policyengine.DecisionDeny.String() != "DENY" {
		t.Fatal("public decision constants are not stable")
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	check := relationalCheckRequest(t, selector)
	response, err := policyengine.NewCheckResponse(check, result)
	if err != nil || response.Result().DecisionID() != "decision-1" {
		t.Fatalf("NewCheckResponse() = %#v, %v", response, err)
	}
}

func TestAuthorizationBatchAndExplainCoverTransportNeutralSurface(t *testing.T) {
	t.Parallel()

	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatalf("NewSelector() error = %v", err)
	}
	itemArguments := map[string]policyengine.Value{"attempt": policyengine.NewIntegerValue(1)}
	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "alice"},
		dsl.EntityRef{Type: "document", ID: "doc-1"},
		"read",
		itemArguments,
	)
	if err != nil {
		t.Fatalf("NewBatchCheckItem() error = %v", err)
	}
	batch, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: "acme",
		Selector:  selector,
		Items:     []policyengine.BatchCheckItem{item},
	})
	if err != nil {
		t.Fatalf("NewBatchCheckRequest() error = %v", err)
	}
	items := batch.Items()
	items[0] = policyengine.BatchCheckItem{}
	if len(batch.Items()) != 1 || batch.Items()[0].Action() != "read" {
		t.Fatal("Items() returned mutable batch-owned state")
	}
	itemArguments["attempt"] = policyengine.NewIntegerValue(2)
	if value, ok := batch.Items()[0].Arguments()["attempt"].Integer(); !ok || value != 1 {
		t.Fatal("batch item retained mutable argument map alias")
	}

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision:       policyengine.DecisionAllow,
		DecisionID:     "decision-1",
		ReasonCode:     "GRAPH_ALLOWED",
		RevisionID:     testRevisionID(t),
		SlotGeneration: 1,
		DataGeneration: 4,
		EvaluatedAt:    now,
	})
	if err != nil {
		t.Fatalf("NewDecisionResult() error = %v", err)
	}
	batchResponse, err := policyengine.NewBatchCheckResponse(batch, []policyengine.DecisionResult{result})
	if err != nil {
		t.Fatalf("NewBatchCheckResponse() error = %v", err)
	}
	batchResults := batchResponse.Results()
	batchResults[0] = policyengine.DecisionResult{}
	if batchResponse.Results()[0].Decision() != policyengine.DecisionAllow {
		t.Fatal("Results() returned mutable response-owned state")
	}

	check, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "acme",
		Selector:  selector,
		Subject:   dsl.EntityRef{Type: "user", ID: "alice"},
		Resource:  dsl.EntityRef{Type: "document", ID: "doc-1"},
		Action:    "read",
	})
	if err != nil {
		t.Fatalf("NewCheckRequest() error = %v", err)
	}
	explainRequest, err := policyengine.NewExplainRequest(check)
	if err != nil || explainRequest.Check().Action() != "read" {
		t.Fatalf("NewExplainRequest() = %#v, %v", explainRequest, err)
	}
	step, err := policyengine.NewExplainStep("document.read", "relation", true)
	if err != nil {
		t.Fatalf("NewExplainStep() error = %v", err)
	}
	explainResponse, err := policyengine.NewExplainResponse(explainRequest, result, []policyengine.ExplainStep{step})
	if err != nil {
		t.Fatalf("NewExplainResponse() error = %v", err)
	}
	steps := explainResponse.Steps()
	steps[0] = policyengine.ExplainStep{}
	if explainResponse.Steps()[0].SchemaPath() != "document.read" {
		t.Fatal("Steps() returned mutable response-owned state")
	}
}

func TestDataValuesDefensivelyCopyAtomicMutations(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}, &expiresAt)
	if err != nil {
		t.Fatalf("NewRelationshipTuple() error = %v", err)
	}
	deleteTuple := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-2"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}
	tupleKey, err := policyengine.NewTupleKey(deleteTuple)
	if err != nil {
		t.Fatalf("NewTupleKey() error = %v", err)
	}
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc-1"}, "classification", mustStringValue(t, "internal"))
	if err != nil {
		t.Fatalf("NewAttribute() error = %v", err)
	}
	attributeKey, err := policyengine.NewAttributeKey(
		dsl.EntityRef{Type: "document", ID: "doc-2"},
		attribute.Name(),
	)
	if err != nil {
		t.Fatalf("NewAttributeKey() error = %v", err)
	}

	tuples := []policyengine.RelationshipTuple{tuple}
	tupleDeletes := []policyengine.TupleKey{tupleKey}
	attributes := []policyengine.Attribute{attribute}
	attributeDeletes := []policyengine.AttributeKey{attributeKey}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "acme",
		ValidationRevisionID: testRevisionID(t),
		ExpectedGeneration:   4,
		IdempotencyKey:       "write-1",
		TupleWrites:          tuples,
		TupleDeletes:         tupleDeletes,
		AttributeWrites:      attributes,
		AttributeDeletes:     attributeDeletes,
	})
	if err != nil {
		t.Fatalf("NewWriteDataRequest() error = %v", err)
	}
	tuples[0] = policyengine.RelationshipTuple{}
	tupleDeletes[0] = policyengine.TupleKey{}
	attributes[0] = policyengine.Attribute{}
	attributeDeletes[0] = policyengine.AttributeKey{}
	gotTuples := request.TupleWrites()
	gotTuples[0] = policyengine.RelationshipTuple{}
	if request.TupleWrites()[0].Tuple().Relation != "viewer" {
		t.Fatal("TupleWrites() retained a mutable slice alias")
	}
	if request.TupleDeletes()[0].Tuple().Relation != "viewer" || request.AttributeWrites()[0].Name() != "classification" || request.AttributeDeletes()[0].Name() != "classification" {
		t.Fatal("write request mutation accessors did not preserve immutable values")
	}
	if request.Namespace() != "acme" || request.ValidationRevisionID() != testRevisionID(t) || request.ExpectedGeneration() != 4 || request.IdempotencyKey() != "write-1" {
		t.Fatal("write request metadata accessors did not preserve values")
	}

	response, err := policyengine.NewWriteDataResponse(5, true)
	if err != nil || response.Generation() != 5 || !response.Replayed() {
		t.Fatalf("NewWriteDataResponse() = %#v, %v", response, err)
	}
}

func TestEventsAndStatusValuesAreBoundedAndImmutable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	event, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace:  "acme",
		Cursor:     "42",
		Kind:       policyengine.StateEventRevisionPublished,
		RevisionID: testRevisionID(t),
		OccurredAt: now,
	})
	if err != nil {
		t.Fatalf("NewStateEvent() error = %v", err)
	}
	listRequest, err := policyengine.NewListEventsRequest("acme", "41", 10)
	if err != nil || listRequest.Namespace() != "acme" || listRequest.AfterCursor() != "41" || listRequest.Limit() != 10 {
		t.Fatalf("NewListEventsRequest() = %#v, %v", listRequest, err)
	}
	events := []policyengine.StateEvent{event}
	listResponse, err := policyengine.NewListEventsResponse(listRequest, events, "42")
	if err != nil {
		t.Fatalf("NewListEventsResponse() error = %v", err)
	}
	events[0] = policyengine.StateEvent{}
	gotEvents := listResponse.Events()
	gotEvents[0] = policyengine.StateEvent{}
	if listResponse.Events()[0].Kind() != policyengine.StateEventRevisionPublished || listResponse.NextCursor() != "42" {
		t.Fatal("event page retained mutable slice aliases")
	}

	statusRequest, err := policyengine.NewStatusRequest("system")
	if err != nil || statusRequest.AuthorizationNamespace() != "system" {
		t.Fatalf("NewStatusRequest() = %#v, %v", statusRequest, err)
	}
	store, err := policyengine.NewComponentStatus("store", policyengine.ComponentReady, "READY")
	if err != nil {
		t.Fatalf("NewComponentStatus() error = %v", err)
	}
	evaluator, err := policyengine.NewComponentStatus("evaluator", policyengine.ComponentReady, "READY")
	if err != nil {
		t.Fatalf("NewComponentStatus() error = %v", err)
	}
	components := []policyengine.ComponentStatus{store, evaluator}
	statusResponse, err := policyengine.NewStatusResponse(true, components)
	if err != nil {
		t.Fatalf("NewStatusResponse() error = %v", err)
	}
	components[0] = policyengine.ComponentStatus{}
	gotComponents := statusResponse.Components()
	gotComponents[0] = policyengine.ComponentStatus{}
	if names := []string{statusResponse.Components()[0].Name(), statusResponse.Components()[1].Name()}; !reflect.DeepEqual(names, []string{"evaluator", "store"}) {
		t.Fatalf("Components() order = %#v, want deterministic", names)
	}
	if !statusResponse.Ready() {
		t.Fatal("Ready() = false, want true")
	}
}

type recordingAuthorizer struct {
	required []policyengine.Capability
	result   policyengine.CallerAuthorization
}

func (a *recordingAuthorizer) Authorize(_ context.Context, _ policyengine.Caller, _ string, required []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	a.required = append([]policyengine.Capability(nil), required...)
	return a.result, nil
}

func TestEngineErrorsHaveStableSanitizedCategories(t *testing.T) {
	t.Parallel()

	_, validationErr := policyengine.NewSelector("", "")
	var validationEngineError *policyengine.EngineError
	if !errors.As(validationErr, &validationEngineError) || validationEngineError.Category() != policyengine.ErrorInvalidArgument {
		t.Fatalf("NewSelector() error = %#v, want typed INVALID_ARGUMENT", validationErr)
	}

	categories := []policyengine.ErrorCategory{
		policyengine.ErrorInvalidArgument,
		policyengine.ErrorPermissionDenied,
		policyengine.ErrorNotFound,
		policyengine.ErrorConflict,
		policyengine.ErrorFailedPrecondition,
		policyengine.ErrorResourceExhausted,
		policyengine.ErrorCanceled,
		policyengine.ErrorDeadlineExceeded,
		policyengine.ErrorUnavailable,
		policyengine.ErrorUnsupportedArtifact,
		policyengine.ErrorCursorExpired,
		policyengine.ErrorIntegrity,
		policyengine.ErrorInternal,
	}
	want := []string{
		"INVALID_ARGUMENT", "PERMISSION_DENIED", "NOT_FOUND", "CONFLICT",
		"FAILED_PRECONDITION", "RESOURCE_EXHAUSTED", "CANCELED",
		"DEADLINE_EXCEEDED", "UNAVAILABLE", "UNSUPPORTED_ARTIFACT",
		"CURSOR_EXPIRED", "INTEGRITY_ERROR", "INTERNAL",
	}
	got := make([]string, len(categories))
	for index, category := range categories {
		got[index] = category.String()
		engineError, err := policyengine.NewEngineError(category)
		if err != nil {
			t.Fatalf("NewEngineError(%q) error = %v", category, err)
		}
		wrapped := fmt.Errorf("adapter boundary: %w", engineError)
		var target *policyengine.EngineError
		if !errors.As(wrapped, &target) || target.Category() != category {
			t.Fatalf("errors.As(%q) did not preserve category", category)
		}
		if strings.Contains(engineError.Error(), "secret") {
			t.Fatal("sanitized engine error unexpectedly contains dynamic input")
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("error categories = %#v, want %#v", got, want)
	}
	if _, err := policyengine.NewEngineError(policyengine.ErrorCategory("UNKNOWN")); err == nil {
		t.Fatal("NewEngineError(unknown) error = nil")
	}
}

func TestCapabilitiesAndCallerAuthorizationAreAdditiveAndFailClosed(t *testing.T) {
	t.Parallel()

	allCapabilities := []policyengine.Capability{
		policyengine.CapabilityPolicyRead,
		policyengine.CapabilityPolicyPublish,
		policyengine.CapabilityPolicyActivate,
		policyengine.CapabilityAuthorizationCheck,
		policyengine.CapabilityAuthorizationContextualData,
		policyengine.CapabilityAuthorizationExplicitRevision,
		policyengine.CapabilityAuthorizationExplain,
		policyengine.CapabilityDataWrite,
		policyengine.CapabilityEventsRead,
		policyengine.CapabilitySystemStatus,
	}
	wantNames := []string{
		"policy.read", "policy.publish", "policy.activate", "authorization.check",
		"authorization.contextual_data", "authorization.explicit_revision",
		"authorization.explain", "data.write", "events.read", "system.status",
	}
	gotNames := make([]string, len(allCapabilities))
	for index, capability := range allCapabilities {
		gotNames[index] = string(capability)
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("capability constants = %#v, want %#v", gotNames, wantNames)
	}

	attributes := map[string]string{"issuer": "embedded-adapter"}
	caller, err := policyengine.NewCaller("caller-1", attributes)
	if err != nil {
		t.Fatalf("NewCaller() error = %v", err)
	}
	attributes["issuer"] = "mutated"
	gotAttributes := caller.Attributes()
	gotAttributes["issuer"] = "again"
	if caller.Attributes()["issuer"] != "embedded-adapter" || caller.ID() != "caller-1" {
		t.Fatal("Caller retained mutable attribute map alias")
	}

	grantCapabilities := []policyengine.Capability{
		policyengine.CapabilityAuthorizationExplicitRevision,
		policyengine.CapabilityAuthorizationCheck,
		policyengine.CapabilityAuthorizationContextualData,
		policyengine.CapabilityAuthorizationExplain,
	}
	grant, err := policyengine.NewGrant("acme/*", grantCapabilities)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	grantCapabilities[0] = policyengine.CapabilityPolicyActivate
	gotGrantCapabilities := grant.Capabilities()
	gotGrantCapabilities[0] = policyengine.CapabilityPolicyActivate
	if !grant.MatchesNamespace("acme/team-a") || grant.MatchesNamespace("other/team-a") {
		t.Fatal("namespace pattern grant matched incorrectly")
	}
	if _, err := policyengine.NewGrant("acme/*/invalid", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck}); err == nil {
		t.Fatal("NewGrant(invalid namespace pattern) error = nil")
	}

	secondGrant, err := policyengine.NewGrant("acme/team-a", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatalf("NewGrant(second) error = %v", err)
	}
	authorization, err := policyengine.NewCallerAuthorization([]policyengine.Grant{grant, secondGrant})
	if err != nil {
		t.Fatalf("NewCallerAuthorization() error = %v", err)
	}
	if got := authorization.Grants(); got[0].NamespacePattern() != "acme/team-a" || got[1].NamespacePattern() != "acme/*" {
		t.Fatalf("Grants() = %#v, want deterministic namespace-pattern order", got)
	}
	authorizer := &recordingAuthorizer{result: authorization}
	exactSelector, err := policyengine.NewSelector("", testRevisionID(t))
	if err != nil {
		t.Fatalf("NewSelector() error = %v", err)
	}
	contextual, err := policyengine.NewContextualData(nil, []policyengine.Attribute{mustAttribute(t)})
	if err != nil {
		t.Fatalf("NewContextualData() error = %v", err)
	}
	check, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace:      "acme/team-a",
		Selector:       exactSelector,
		Subject:        dsl.EntityRef{Type: "user", ID: "alice"},
		Resource:       dsl.EntityRef{Type: "document", ID: "doc-1"},
		Action:         "read",
		ContextualData: contextual,
	})
	if err != nil {
		t.Fatalf("NewCheckRequest() error = %v", err)
	}
	explain, err := policyengine.NewExplainRequest(check)
	if err != nil {
		t.Fatalf("NewExplainRequest() error = %v", err)
	}
	wantRequired := []policyengine.Capability{
		policyengine.CapabilityAuthorizationCheck,
		policyengine.CapabilityAuthorizationContextualData,
		policyengine.CapabilityAuthorizationExplicitRevision,
		policyengine.CapabilityAuthorizationExplain,
	}
	if got := explain.RequiredCapabilities(); !reflect.DeepEqual(got, wantRequired) {
		t.Fatalf("RequiredCapabilities() = %#v, want %#v", got, wantRequired)
	}
	if err := policyengine.AuthorizeCaller(context.Background(), authorizer, caller, check.Namespace(), explain.RequiredCapabilities()); err != nil {
		t.Fatalf("AuthorizeCaller() error = %v", err)
	}
	if !reflect.DeepEqual(authorizer.required, wantRequired) {
		t.Fatalf("authorizer required = %#v, want all %#v", authorizer.required, wantRequired)
	}

	err = policyengine.AuthorizeCaller(context.Background(), nil, caller, check.Namespace(), check.RequiredCapabilities())
	var engineError *policyengine.EngineError
	if !errors.As(err, &engineError) || engineError.Category() != policyengine.ErrorPermissionDenied {
		t.Fatalf("missing authorizer error = %#v, want PERMISSION_DENIED", err)
	}
}

func mustAttribute(t *testing.T) policyengine.Attribute {
	t.Helper()
	attribute, err := policyengine.NewAttribute(
		dsl.EntityRef{Type: "document", ID: "doc-1"},
		"classification",
		mustStringValue(t, "internal"),
	)
	if err != nil {
		t.Fatalf("NewAttribute() error = %v", err)
	}
	return attribute
}

func TestVerifierAndDecisionSinkDefaultsAreFailClosedAndPrivacySafe(t *testing.T) {
	t.Parallel()

	approvalEvidence := []byte("approval-secret")
	approvalRequest, err := policyengine.NewApprovalVerificationRequest(mustEvidenceBinding(t), []string{"manager", "admin"}, approvalEvidence)
	if err != nil {
		t.Fatalf("NewApprovalVerificationRequest() error = %v", err)
	}
	approvalEvidence[0] = 'X'
	gotApprovalEvidence := approvalRequest.Evidence()
	gotApprovalEvidence[0] = 'Y'
	if string(approvalRequest.Evidence()) != "approval-secret" {
		t.Fatal("approval evidence retained a mutable byte alias")
	}
	_, err = policyengine.DefaultApprovalVerifier().VerifyApproval(context.Background(), approvalRequest)
	var engineError *policyengine.EngineError
	if !errors.As(err, &engineError) || engineError.Category() != policyengine.ErrorPermissionDenied || strings.Contains(err.Error(), "approval-secret") {
		t.Fatalf("default approval verifier error = %#v", err)
	}

	delegationEvidence := []byte("delegation-secret")
	delegationRequest, err := policyengine.NewDelegationVerificationRequest(mustEvidenceBinding(t), delegationEvidence)
	if err != nil {
		t.Fatalf("NewDelegationVerificationRequest() error = %v", err)
	}
	delegationEvidence[0] = 'X'
	gotDelegationEvidence := delegationRequest.Evidence()
	gotDelegationEvidence[0] = 'Y'
	if string(delegationRequest.Evidence()) != "delegation-secret" {
		t.Fatal("delegation evidence retained a mutable byte alias")
	}
	_, err = policyengine.DefaultDelegationVerifier().VerifyDelegation(context.Background(), delegationRequest)
	if !errors.As(err, &engineError) || engineError.Category() != policyengine.ErrorPermissionDenied || strings.Contains(err.Error(), "delegation-secret") {
		t.Fatalf("default delegation verifier error = %#v", err)
	}

	approvalResult, err := policyengine.NewApprovalVerificationResult([]string{"manager", "admin", "manager"})
	if err != nil {
		t.Fatalf("NewApprovalVerificationResult() error = %v", err)
	}
	if got, want := approvalResult.SatisfiedRequirementIDs(), []string{"admin", "manager"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SatisfiedRequirementIDs() = %#v, want %#v", got, want)
	}
	delegationResult, err := policyengine.NewDelegationVerificationResult(mustContextualData(t))
	if err != nil || len(delegationResult.ContextualData().Attributes()) != 1 {
		t.Fatalf("NewDelegationVerificationResult() = %#v, %v", delegationResult, err)
	}

	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision:       policyengine.DecisionAllow,
		ReasonCode:     "GRAPH_ALLOWED",
		RevisionID:     testRevisionID(t),
		DataGeneration: 4,
		CompletedAt:    now,
	})
	if err != nil {
		t.Fatalf("NewCompletedDecisionEvent() error = %v", err)
	}
	delivery := policyengine.DefaultDecisionEventSink().RecordDecision(context.Background(), event)
	if delivery.Status() != policyengine.DecisionDeliveryDropped || delivery.ReasonCode() != "NO_SINK" {
		t.Fatalf("no-op sink delivery = %v/%q", delivery.Status(), delivery.ReasonCode())
	}

	options, err := policyengine.NewOptions()
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	_, err = options.ApprovalVerifier().VerifyApproval(context.Background(), approvalRequest)
	if !errors.As(err, &engineError) || engineError.Category() != policyengine.ErrorPermissionDenied {
		t.Fatalf("default options approval verifier error = %#v", err)
	}
	if got := options.DecisionEventSink().RecordDecision(context.Background(), event); got.Status() != policyengine.DecisionDeliveryDropped {
		t.Fatalf("default options sink status = %v", got.Status())
	}
}

func mustEvidenceBinding(t *testing.T) policyengine.EvidenceBinding {
	t.Helper()
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
		RevisionID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SlotGeneration: 1,
		EvaluatedAt:    time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC),
		Fingerprint:    policyengine.NewEvidenceFingerprint([32]byte{1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func mustContextualData(t *testing.T) policyengine.ContextualData {
	t.Helper()
	value, err := policyengine.NewContextualData(nil, []policyengine.Attribute{mustAttribute(t)})
	if err != nil {
		t.Fatalf("NewContextualData() error = %v", err)
	}
	return value
}
