package embedded_test

import (
	"context"
	"testing"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
)

const refundPolicy = `
entity user {}
entity refund {
    relation approver @user
    action approve = approver
}
guard refund.approve {
    allow when resource.amount == 5000
    allow otherwise
}
`

const approvalRefundPolicy = `
entity user {}
entity refund {
    relation approver @user
    action approve = approver
}
guard refund.approve { require_approval finance otherwise }
`

func TestEmbeddedEngineCompletesPublishDataCheckLoop(t *testing.T) {
	engine := newMemoryEngine(t)
	revision := publishRefundPolicy(t, engine)
	activateProduction(t, engine, revision)
	writeRefundRelations(t, engine, revision)

	response, err := engine.Check(
		context.Background(),
		runtimeCaller(t),
		refundCheck(t),
	)
	requireNoError(t, err)
	if response.Result().Decision() != policyengine.DecisionAllow {
		t.Fatalf("decision = %s, want allow", response.Result().Decision())
	}
}

func TestEmbeddedEngineComposesAuthorizedEventsAndStatus(t *testing.T) {
	engine := newMemoryEngine(t)
	publishRefundPolicy(t, engine)

	eventsRequest, err := policyengine.NewListEventsRequest("tenant-a", "", 10)
	requireNoError(t, err)
	events, err := engine.ListEvents(context.Background(), runtimeCaller(t), eventsRequest)
	requireNoError(t, err)
	if got := len(events.Events()); got != 1 {
		t.Fatalf("events = %d, want 1", got)
	}

	statusRequest, err := policyengine.NewStatusRequest("tenant-a")
	requireNoError(t, err)
	status, err := engine.Status(context.Background(), runtimeCaller(t), statusRequest)
	requireNoError(t, err)
	if !status.Ready() || len(status.Components()) == 0 {
		t.Fatal("embedded engine did not report ready components")
	}
}

func TestEmbeddedEngineDefaultsRejectSuppliedEvidence(t *testing.T) {
	t.Run("approval", func(t *testing.T) {
		engine := newMemoryEngine(t)
		revision := publishPolicy(t, engine, approvalRefundPolicy)
		activateProduction(t, engine, revision)
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "refund", ID: "refund-1"}, Relation: "approver",
			Subject: dsl.SubjectRef{Type: "user", ID: "alice"},
		}, nil)
		requireNoError(t, err)
		contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, nil)
		requireNoError(t, err)
		request := refundCheckInput(t, contextual, []byte("approval-evidence"), nil)
		_, err = engine.Check(context.Background(), runtimeCaller(t), request)
		requireCategory(t, err, policyengine.ErrorPermissionDenied)
	})

	t.Run("delegation", func(t *testing.T) {
		engine := newMemoryEngine(t)
		revision := publishRefundPolicy(t, engine)
		activateProduction(t, engine, revision)
		writeRefundRelations(t, engine, revision)
		request := refundCheckInput(t, policyengine.ContextualData{}, nil, []byte("delegation-evidence"))
		_, err := engine.Check(context.Background(), runtimeCaller(t), request)
		requireCategory(t, err, policyengine.ErrorPermissionDenied)
	})
}

func newMemoryEngine(t testing.TB) policyengine.Engine {
	t.Helper()
	storage, err := memory.New()
	requireNoError(t, err)
	engine, err := embedded.New(
		embedded.WithStore(storage),
		embedded.WithCallerAuthorizer(requestAuthorizer{}),
	)
	requireNoError(t, err)
	return engine
}

func publishRefundPolicy(t testing.TB, engine policyengine.Engine) string {
	t.Helper()
	return publishPolicy(t, engine, refundPolicy)
}

func publishPolicy(t testing.TB, engine policyengine.Engine, source string) string {
	t.Helper()
	request, err := policyengine.NewPublishRequest("tenant-a", "refund.cdr", []byte(source))
	requireNoError(t, err)
	response, err := engine.Publish(context.Background(), runtimeCaller(t), request)
	requireNoError(t, err)
	return response.Revision().ID()
}

func activateProduction(t testing.TB, engine policyengine.Engine, revision string) {
	t.Helper()
	request, err := policyengine.NewActivateRequest(
		"tenant-a", "production", revision, policyengine.NewUnsetSlotExpectation(),
	)
	requireNoError(t, err)
	_, err = engine.Activate(context.Background(), runtimeCaller(t), request)
	requireNoError(t, err)
}

func writeRefundRelations(t testing.TB, engine policyengine.Engine, revision string) {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "refund", ID: "refund-1"},
		Relation: "approver",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}, nil)
	requireNoError(t, err)
	amount, err := policyengine.NewAttribute(
		dsl.EntityRef{Type: "refund", ID: "refund-1"},
		"amount",
		policyengine.NewIntegerValue(5000),
	)
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "tenant-a",
		ValidationRevisionID: revision,
		ExpectedGeneration:   0,
		IdempotencyKey:       "refund-data-1",
		TupleWrites:          []policyengine.RelationshipTuple{tuple},
		AttributeWrites:      []policyengine.Attribute{amount},
	})
	requireNoError(t, err)
	_, err = engine.WriteData(context.Background(), runtimeCaller(t), request)
	requireNoError(t, err)
}

func refundCheck(t testing.TB) policyengine.CheckRequest {
	t.Helper()
	return refundCheckInput(t, policyengine.ContextualData{}, nil, nil)
}

func refundCheckInput(t testing.TB, contextual policyengine.ContextualData, approval, delegation []byte) policyengine.CheckRequest {
	t.Helper()
	selector, err := policyengine.NewSelector("production", "")
	requireNoError(t, err)
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace:          "tenant-a",
		Selector:           selector,
		Subject:            dsl.EntityRef{Type: "user", ID: "alice"},
		Resource:           dsl.EntityRef{Type: "refund", ID: "refund-1"},
		Action:             "approve",
		ContextualData:     contextual,
		ApprovalEvidence:   approval,
		DelegationEvidence: delegation,
	})
	requireNoError(t, err)
	return request
}

func runtimeCaller(t testing.TB) policyengine.Caller {
	t.Helper()
	caller, err := policyengine.NewCaller("runtime-test", nil)
	requireNoError(t, err)
	return caller
}

type requestAuthorizer struct{}

func (requestAuthorizer) Authorize(
	_ context.Context,
	_ policyengine.Caller,
	namespace string,
	capabilities []policyengine.Capability,
) (policyengine.CallerAuthorization, error) {
	grant, err := policyengine.NewGrant(namespace, capabilities)
	if err != nil {
		return policyengine.CallerAuthorization{}, err
	}
	return policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireCategory(t testing.TB, err error, want policyengine.ErrorCategory) {
	t.Helper()
	typed, ok := err.(*policyengine.EngineError)
	if !ok || typed == nil || typed.Category() != want {
		t.Fatalf("error category mismatch")
	}
}
