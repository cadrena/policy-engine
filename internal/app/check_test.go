package app_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	"github.com/cadrena/policy-engine/internal/cache"
	"github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

const (
	allowCheckSource = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { allow otherwise }
`
	denyCheckSource = `
entity user {}
entity document {
    relation editor @user
    action view = editor
}
guard document.view { allow otherwise }
`
	approvalCheckSource = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { require_approval finance otherwise }
`
)

func TestCheckPinsRevisionBeforeConcurrentActivation(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	fixture.revisions.pauseNextGet()

	result := make(chan policyengine.CheckResponse, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := fixture.service.Check(
			context.Background(),
			mustCaller(t),
			fixture.checkRequest(t),
		)
		if err != nil {
			failures <- err
			return
		}
		result <- response
	}()

	fixture.revisions.waitUntilGet(t)
	fixture.activate(t, fixture.denyRevision)
	fixture.revisions.resumeGet()

	select {
	case err := <-failures:
		t.Fatal(err)
	case response := <-result:
		if response.Result().RevisionID() != fixture.allowRevision {
			t.Fatalf("revision switched during check")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("check did not complete")
	}
}

func TestCheckMapsDSLAllowAndDenyAsDecisions(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	allowed, err := fixture.service.Check(context.Background(), mustCaller(t), fixture.checkRequest(t))
	requireNoError(t, err)
	if got := allowed.Result(); got.Decision() != policyengine.DecisionAllow ||
		got.ReasonCode() != dsl.ReasonGuardAllowed || got.RevisionID() != fixture.allowRevision {
		t.Fatalf("allow result = %#v", got)
	}

	fixture.activate(t, fixture.denyRevision)
	deniedRequest := checkRequestForSelector(t, "production", "", []policyengine.RelationshipTuple{
		mustContextualTuple(t, "document", "editor", "user", "bob"),
	})
	denied, err := fixture.service.Check(context.Background(), mustCaller(t), deniedRequest)
	requireNoError(t, err)
	if got := denied.Result(); got.Decision() != policyengine.DecisionDeny ||
		got.ReasonCode() != dsl.ReasonGraphDenied || got.RevisionID() != fixture.denyRevision {
		t.Fatalf("deny result = %#v", got)
	}
}

func TestCheckRequiresAndVerifiesApprovalEvidence(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	revision := publishSource(context.Background(), t, fixture.policyService, mustCaller(t), "approval.cdr", approvalCheckSource).Revision().ID()
	fixture.activate(t, revision)

	withoutEvidence, err := fixture.service.Check(context.Background(), mustCaller(t), fixture.checkRequest(t))
	requireNoError(t, err)
	if got := withoutEvidence.Result(); got.Decision() != policyengine.DecisionRequireApproval ||
		len(got.Requirements()) != 1 || got.Requirements()[0] != "finance" || got.UsedApproval() {
		t.Fatalf("require-approval result = %#v", got)
	}

	service := fixture.newService(t, approvalVerifierFunc(func(_ context.Context, request policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
		binding := request.Binding()
		if binding.RevisionID() != revision || binding.DataGeneration() != 0 || binding.SlotGeneration() == 0 {
			t.Fatalf("approval binding is not exact")
		}
		return policyengine.NewApprovalVerificationResult([]string{"finance"})
	}), policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	withEvidence := withApprovalEvidence(t, fixture.checkRequest(t), []byte("approval-token"))
	approved, err := service.Check(context.Background(), mustCaller(t), withEvidence)
	requireNoError(t, err)
	if got := approved.Result(); got.Decision() != policyengine.DecisionAllow || !got.UsedApproval() || len(got.Requirements()) != 0 {
		t.Fatalf("approved result = %#v", got)
	}
}

func TestCheckApprovalContinuationDigestIsStableAcrossRetries(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	revision := publishSource(context.Background(), t, fixture.policyService, mustCaller(t), "approval.cdr", approvalCheckSource).Revision().ID()
	fixture.activate(t, revision)
	request := withApprovalEvidence(t, fixture.checkRequest(t), []byte("approval-token"))

	firstVerifier := &approvalCaptureVerifier{}
	firstService := fixture.newServiceWithClock(t, firstVerifier, policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), fixture.adapter, time.Unix(100, 0).UTC())
	firstResponse, err := firstService.Check(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
	firstResult := firstResponse.Result()
	assertApprovalVerifierMatchesResult(t, firstVerifier, firstResult)

	retryVerifier := &approvalCaptureVerifier{}
	retryService := fixture.newServiceWithClock(t, retryVerifier, policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), fixture.adapter, time.Unix(160, 0).UTC())
	retryResponse, err := retryService.Check(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
	retryResult := retryResponse.Result()
	assertApprovalVerifierMatchesResult(t, retryVerifier, retryResult)

	if got, want := mustApprovalDigest(t, retryResult), mustApprovalDigest(t, firstResult); got != want {
		t.Fatalf("retry approval digest = %x, want %x", got, want)
	}
}

func TestCheckDelegationEvidenceIsExactlyBoundAndRejectsByDefault(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	base := checkRequestForSelector(t, "production", "", nil)
	withEvidence := withDelegationEvidence(t, base, []byte("delegation-token"))

	_, err := fixture.service.Check(context.Background(), mustCaller(t), withEvidence)
	requireCategory(t, err, policyengine.ErrorPermissionDenied)

	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(_ context.Context, request policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		binding := request.Binding()
		if binding.RevisionID() != fixture.allowRevision || binding.DataGeneration() != 0 || binding.SlotGeneration() == 0 {
			t.Fatalf("delegation binding is not exact")
		}
		contextual, contextualErr := policyengine.NewContextualData([]policyengine.RelationshipTuple{viewerContextualTuple(t)}, nil)
		if contextualErr != nil {
			return policyengine.DelegationVerificationResult{}, contextualErr
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	response, err := service.Check(context.Background(), mustCaller(t), withEvidence)
	requireNoError(t, err)
	if got := response.Result(); got.Decision() != policyengine.DecisionAllow || !got.UsedDelegation() || !got.UsedContextualData() {
		t.Fatalf("delegated result = %#v", got)
	}
}

func TestCheckRejectsInvalidDirectContextualDataBeforeDelegationVerification(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	invalidTuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "group", ID: "finance"},
	}, nil)
	requireNoError(t, err)
	request := withDelegationEvidence(t,
		checkRequestForSelector(t, "production", "", []policyengine.RelationshipTuple{invalidTuple}),
		[]byte("delegation-token"),
	)
	var calls atomic.Int32
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		calls.Add(1)
		return policyengine.NewDelegationVerificationResult(policyengine.ContextualData{})
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)

	_, err = service.Check(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
	if calls.Load() != 0 {
		t.Fatalf("delegation verifier calls = %d, want 0 for invalid direct contextual data", calls.Load())
	}
}

func TestCheckRejectsContextualTuplesOutsideSelectedArtifactSchema(t *testing.T) {
	for _, test := range []struct {
		name  string
		tuple dsl.Tuple
	}{
		{name: "undeclared relation", tuple: dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "owner",
			Subject: dsl.SubjectRef{Type: "user", ID: "alice"},
		}},
		{name: "undeclared resource type", tuple: dsl.Tuple{
			Resource: dsl.EntityRef{Type: "invoice", ID: "invoice-1"}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "user", ID: "alice"},
		}},
		{name: "wrong relation target", tuple: dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "group", ID: "finance"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthorizationFixture(t)
			fixture.activate(t, fixture.allowRevision)
			contextualTuple, err := policyengine.NewRelationshipTuple(test.tuple, nil)
			requireNoError(t, err)
			request := checkRequestForSelector(t, "production", "", []policyengine.RelationshipTuple{contextualTuple})

			_, err = fixture.service.Check(context.Background(), mustCaller(t), request)
			requireCategory(t, err, policyengine.ErrorInvalidArgument)
		})
	}
}

func TestCheckRejectsDelegatedTuplesOutsideSelectedArtifactSchema(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	base := checkRequestForSelector(t, "production", "", nil)
	request := withDelegationEvidence(t, base, []byte("delegation-token"))
	invalidTuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "group", ID: "finance"},
	}, nil)
	requireNoError(t, err)
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		contextual, contextualErr := policyengine.NewContextualData([]policyengine.RelationshipTuple{invalidTuple}, nil)
		if contextualErr != nil {
			return policyengine.DelegationVerificationResult{}, contextualErr
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)

	_, err = service.Check(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
}

func TestCheckRejectsUnexpectedApprovalEvidence(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.denyRevision)
	deniedRequest := checkRequestForSelector(t, "production", "", []policyengine.RelationshipTuple{
		mustContextualTuple(t, "document", "editor", "user", "bob"),
	})
	_, err := fixture.service.Check(context.Background(), mustCaller(t), withApprovalEvidence(t, deniedRequest, []byte("unexpected")))
	requireCategory(t, err, policyengine.ErrorFailedPrecondition)
}

func TestCheckUnknownSlotAndRevisionFailClosed(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	unknownSlot := checkRequestForSelector(t, "missing", "", nil)
	_, slotErr := fixture.service.Check(context.Background(), mustCaller(t), unknownSlot)
	requireCategory(t, slotErr, policyengine.ErrorNotFound)

	unknownRevision := checkRequestForSelector(t, "", "0000000000000000000000000000000000000000000000000000000000000000", nil)
	_, revisionErr := fixture.service.Check(context.Background(), mustCaller(t), unknownRevision)
	requireCategory(t, revisionErr, policyengine.ErrorNotFound)
}

func TestCheckMapsArtifactSnapshotAndCancellationFailures(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)

	badRevisions := &invalidRevisionStore{RevisionStore: fixture.adapter}
	badService := fixture.newServiceWithStores(t, badRevisions, fixture.adapter)
	_, err := badService.Check(context.Background(), mustCaller(t), exactCheckRequest(t, fixture.allowRevision))
	requireCategory(t, err, policyengine.ErrorIntegrity)

	openFailure := &failingDataReader{DataReader: fixture.adapter, openErr: mustEngineError(t, policyengine.ErrorUnavailable)}
	openService := fixture.newServiceWithStores(t, fixture.adapter, openFailure)
	_, err = openService.Check(context.Background(), mustCaller(t), exactCheckRequest(t, fixture.allowRevision))
	requireCategory(t, err, policyengine.ErrorUnavailable)

	queryFailure := &failingDataReader{DataReader: fixture.adapter, queryErr: mustEngineError(t, policyengine.ErrorResourceExhausted)}
	queryService := fixture.newServiceWithStores(t, fixture.adapter, queryFailure)
	_, err = queryService.Check(context.Background(), mustCaller(t), exactCheckRequest(t, fixture.allowRevision))
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fixture.service.Check(canceled, mustCaller(t), fixture.checkRequest(t))
	requireCategory(t, err, policyengine.ErrorCanceled)
}

func TestCheckDoesNotTraverseHostileDependencyErrors(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	request := exactCheckRequest(t, fixture.allowRevision)

	t.Run("As cannot manufacture a category", func(t *testing.T) {
		manufactured := mustEngineError(t, policyengine.ErrorPermissionDenied).(*policyengine.EngineError)
		hostile := &manufacturingAsError{manufactured: manufactured}
		service := fixture.newServiceWithStores(t, &errorRevisionStore{RevisionStore: fixture.adapter, err: hostile}, fixture.adapter)
		_, err, panicValue := checkWithoutPanic(service, request, t)
		if panicValue != nil {
			t.Fatalf("Check panicked: %v", panicValue)
		}
		requireCategory(t, err, policyengine.ErrorInternal)
		if hostile.called.Load() {
			t.Fatal("hostile As was invoked")
		}
	})

	t.Run("Unwrap cannot panic", func(t *testing.T) {
		hostile := &panickingUnwrapError{}
		service := fixture.newServiceWithStores(t, &errorRevisionStore{RevisionStore: fixture.adapter, err: hostile}, fixture.adapter)
		_, err, panicValue := checkWithoutPanic(service, request, t)
		if panicValue != nil {
			t.Fatalf("Check panicked: %v", panicValue)
		}
		requireCategory(t, err, policyengine.ErrorInternal)
		if hostile.called.Load() {
			t.Fatal("hostile Unwrap was invoked")
		}
	})

	t.Run("DSL tuple-reader wrapping cannot manufacture a category", func(t *testing.T) {
		manufactured := mustEngineError(t, policyengine.ErrorPermissionDenied).(*policyengine.EngineError)
		hostile := &manufacturingAsError{manufactured: manufactured}
		data := &failingDataReader{DataReader: fixture.adapter, queryErr: hostile}
		service := fixture.newServiceWithStores(t, fixture.adapter, data)
		_, err, panicValue := checkWithoutPanic(service, request, t)
		if panicValue != nil {
			t.Fatalf("Check panicked: %v", panicValue)
		}
		requireCategory(t, err, policyengine.ErrorFailedPrecondition)
		if hostile.called.Load() {
			t.Fatal("hostile As inside DSL CheckError was invoked")
		}
	})
}

func TestCheckClosesNewerSnapshotAndFailsWhenDataAdvancesAfterHeadRead(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	data := newPausingOpenDataReader(fixture.adapter)
	sink := &recordingDecisionSink{}
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), policyengine.DefaultDelegationVerifier(), sink, data)
	result := make(chan policyengine.CheckResponse, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := service.Check(context.Background(), mustCaller(t), fixture.checkRequest(t))
		if err != nil {
			failures <- err
			return
		}
		result <- response
	}()

	data.waitUntilOpen(t)
	write, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "tenant-a", ValidationRevisionID: fixture.allowRevision,
		ExpectedGeneration: 0, IdempotencyKey: "advance-after-head",
		TupleWrites: []policyengine.RelationshipTuple{viewerTuple(t, "bob", "doc-2")},
	})
	requireNoError(t, err)
	_, err = fixture.adapter.WriteData(context.Background(), write)
	requireNoError(t, err)
	data.resumeOpen()

	select {
	case response := <-result:
		t.Fatalf("Check returned decision from changed generation: %#v", response.Result())
	case err := <-failures:
		requireCategory(t, err, policyengine.ErrorFailedPrecondition)
	case <-time.After(5 * time.Second):
		t.Fatal("Check did not complete")
	}
	if snapshot := data.openedSnapshot(); snapshot == nil || snapshot.closeCalls.Load() != 1 {
		t.Fatal("newer snapshot was not closed exactly once")
	}
	if sink.calls != 0 {
		t.Fatalf("decision sink calls = %d, want 0", sink.calls)
	}
}

func TestCheckDecisionSinkFailureDoesNotChangeDecision(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	sink := &recordingDecisionSink{}
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), policyengine.DefaultDelegationVerifier(), sink, fixture.adapter)
	response, err := service.Check(context.Background(), mustCaller(t), fixture.checkRequest(t))
	requireNoError(t, err)
	if response.Result().Decision() != policyengine.DecisionAllow || sink.calls != 1 {
		t.Fatalf("decision/calls = %v/%d", response.Result().Decision(), sink.calls)
	}
	if sink.event.RevisionID() != fixture.allowRevision || sink.event.Decision() != policyengine.DecisionAllow {
		t.Fatal("sink did not receive privacy-safe pinned decision metadata")
	}
}

type authorizationFixture struct {
	service       *app.AuthorizationService
	policyService *app.PolicyService
	revisions     *pausingRevisionStore
	allowRevision string
	denyRevision  string
	adapter       *memory.Store
}

func newAuthorizationFixture(t testing.TB) *authorizationFixture {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	adapter, err := memory.NewWithClock(fixedClock{now: now})
	requireNoError(t, err)
	policyService, err := app.NewPolicyService(adapter, allowAuthorizer{}, fixedClock{now: now})
	requireNoError(t, err)
	caller := mustCaller(t)
	allowRevision := publishSource(context.Background(), t, policyService, caller, "allow.cdr", allowCheckSource).Revision().ID()
	denyRevision := publishSource(context.Background(), t, policyService, caller, "deny.cdr", denyCheckSource).Revision().ID()
	revisionCache, err := cache.NewRevisionCache(cache.RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	requireNoError(t, err)
	pointerCache, err := cache.NewPointerCache(8)
	requireNoError(t, err)
	revisions := newPausingRevisionStore(adapter)
	service, err := app.NewAuthorizationService(app.AuthorizationDependencies{
		Revisions:          revisions,
		Slots:              adapter,
		Data:               adapter,
		RevisionCache:      revisionCache,
		PointerCache:       pointerCache,
		CallerAuthorizer:   allowAuthorizer{},
		ApprovalVerifier:   policyengine.DefaultApprovalVerifier(),
		DelegationVerifier: policyengine.DefaultDelegationVerifier(),
		DecisionSink:       policyengine.DefaultDecisionEventSink(),
		Clock:              func() time.Time { return now },
	})
	requireNoError(t, err)
	return &authorizationFixture{
		service: service, policyService: policyService, revisions: revisions,
		allowRevision: allowRevision, denyRevision: denyRevision, adapter: adapter,
	}
}

func (f *authorizationFixture) newService(t testing.TB, approval policyengine.ApprovalVerifier, delegation policyengine.DelegationVerifier, sink policyengine.DecisionEventSink, data store.DataReader) *app.AuthorizationService {
	return f.newServiceWithClock(t, approval, delegation, sink, data, time.Unix(100, 0).UTC())
}

func (f *authorizationFixture) newServiceWithClock(t testing.TB, approval policyengine.ApprovalVerifier, delegation policyengine.DelegationVerifier, sink policyengine.DecisionEventSink, data store.DataReader, now time.Time) *app.AuthorizationService {
	t.Helper()
	revisionCache, err := cache.NewRevisionCache(cache.RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	requireNoError(t, err)
	pointerCache, err := cache.NewPointerCache(8)
	requireNoError(t, err)
	service, err := app.NewAuthorizationService(app.AuthorizationDependencies{
		Revisions: f.adapter, Slots: f.adapter, Data: data, RevisionCache: revisionCache,
		PointerCache: pointerCache, CallerAuthorizer: allowAuthorizer{}, ApprovalVerifier: approval,
		DelegationVerifier: delegation, DecisionSink: sink, Clock: func() time.Time { return now },
	})
	requireNoError(t, err)
	return service
}

func (f *authorizationFixture) newServiceWithStores(t testing.TB, revisions store.RevisionStore, data store.DataReader) *app.AuthorizationService {
	t.Helper()
	revisionCache, err := cache.NewRevisionCache(cache.RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	requireNoError(t, err)
	pointerCache, err := cache.NewPointerCache(8)
	requireNoError(t, err)
	service, err := app.NewAuthorizationService(app.AuthorizationDependencies{
		Revisions: revisions, Slots: f.adapter, Data: data, RevisionCache: revisionCache,
		PointerCache: pointerCache, CallerAuthorizer: allowAuthorizer{},
		ApprovalVerifier: policyengine.DefaultApprovalVerifier(), DelegationVerifier: policyengine.DefaultDelegationVerifier(),
		DecisionSink: policyengine.DefaultDecisionEventSink(), Clock: func() time.Time { return time.Unix(100, 0).UTC() },
	})
	requireNoError(t, err)
	return service
}

func (f *authorizationFixture) activate(t testing.TB, revision string) {
	t.Helper()
	expectation := policyengine.NewUnsetSlotExpectation()
	resolve, err := f.policyService.Resolve(context.Background(), mustCaller(t), mustResolveRequest(t, "production"))
	if err == nil {
		current := resolve.Activation()
		expectation, err = policyengine.NewActiveSlotExpectation(current.RevisionID(), current.Generation())
		requireNoError(t, err)
	}
	request, err := policyengine.NewActivateRequest("tenant-a", "production", revision, expectation)
	requireNoError(t, err)
	_, err = f.policyService.Activate(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
}

func (f *authorizationFixture) checkRequest(t testing.TB) policyengine.CheckRequest {
	t.Helper()
	selector, err := policyengine.NewSelector("production", "")
	requireNoError(t, err)
	contextualTuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}, nil)
	requireNoError(t, err)
	contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{contextualTuple}, nil)
	requireNoError(t, err)
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "tenant-a", Selector: selector,
		Subject:  dsl.EntityRef{Type: "user", ID: "alice"},
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"},
		Action:   "view", ContextualData: contextual,
	})
	requireNoError(t, err)
	return request
}

func mustResolveRequest(t testing.TB, slot string) policyengine.ResolveRequest {
	t.Helper()
	request, err := policyengine.NewResolveRequest("tenant-a", slot)
	requireNoError(t, err)
	return request
}

func withApprovalEvidence(t testing.TB, request policyengine.CheckRequest, evidence []byte) policyengine.CheckRequest {
	t.Helper()
	result, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: request.Namespace(), Selector: request.Selector(), Subject: request.Subject(), Resource: request.Resource(),
		Action: request.Action(), Arguments: request.Arguments(), ContextualData: request.ContextualData(),
		ApprovalEvidence: evidence, DelegationEvidence: request.DelegationEvidence(), MinimumGeneration: request.MinimumGeneration(),
	})
	requireNoError(t, err)
	return result
}

func withDelegationEvidence(t testing.TB, request policyengine.CheckRequest, evidence []byte) policyengine.CheckRequest {
	t.Helper()
	result, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: request.Namespace(), Selector: request.Selector(), Subject: request.Subject(), Resource: request.Resource(),
		Action: request.Action(), Arguments: request.Arguments(), ContextualData: request.ContextualData(),
		ApprovalEvidence: request.ApprovalEvidence(), DelegationEvidence: evidence, MinimumGeneration: request.MinimumGeneration(),
	})
	requireNoError(t, err)
	return result
}

func exactCheckRequest(t testing.TB, revision string) policyengine.CheckRequest {
	t.Helper()
	return checkRequestForSelector(t, "", revision, []policyengine.RelationshipTuple{viewerContextualTuple(t)})
}

func checkRequestForSelector(t testing.TB, slot, revision string, tuples []policyengine.RelationshipTuple) policyengine.CheckRequest {
	t.Helper()
	selector, err := policyengine.NewSelector(slot, revision)
	requireNoError(t, err)
	contextual, err := policyengine.NewContextualData(tuples, nil)
	requireNoError(t, err)
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "tenant-a", Selector: selector, Subject: dsl.EntityRef{Type: "user", ID: "alice"},
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Action: "view", ContextualData: contextual,
	})
	requireNoError(t, err)
	return request
}

func viewerContextualTuple(t testing.TB) policyengine.RelationshipTuple {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: "alice"},
	}, nil)
	requireNoError(t, err)
	return tuple
}

func mustContextualTuple(t testing.TB, resourceType, relation, subjectType, subjectID string) policyengine.RelationshipTuple {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: resourceType, ID: "doc-1"}, Relation: relation,
		Subject: dsl.SubjectRef{Type: subjectType, ID: subjectID},
	}, nil)
	requireNoError(t, err)
	return tuple
}

type approvalVerifierFunc func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error)

func (f approvalVerifierFunc) VerifyApproval(ctx context.Context, request policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	return f(ctx, request)
}

type approvalCaptureVerifier struct {
	mu       sync.Mutex
	bindings []policyengine.EvidenceBinding
}

func (v *approvalCaptureVerifier) VerifyApproval(_ context.Context, request policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	v.mu.Lock()
	v.bindings = append(v.bindings, request.Binding())
	v.mu.Unlock()
	return policyengine.NewApprovalVerificationResult(nil)
}

func (v *approvalCaptureVerifier) Bindings() []policyengine.EvidenceBinding {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]policyengine.EvidenceBinding(nil), v.bindings...)
}

func mustApprovalDigest(t testing.TB, result policyengine.DecisionResult) [32]byte {
	t.Helper()
	digest, ok := result.ApprovalBindingDigest()
	if !ok {
		t.Fatal("require-approval result has no approval digest")
	}
	return digest
}

func assertApprovalVerifierMatchesResult(t testing.TB, verifier *approvalCaptureVerifier, result policyengine.DecisionResult) {
	t.Helper()
	bindings := verifier.Bindings()
	if len(bindings) != 1 {
		t.Fatalf("approval verifier bindings = %d", len(bindings))
	}
	got, ok := bindings[0].AuthorizationDigest()
	if !ok || got != mustApprovalDigest(t, result) {
		t.Fatal("approval verifier/result binding mismatch")
	}
}

type delegationVerifierFunc func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error)

func (f delegationVerifierFunc) VerifyDelegation(ctx context.Context, request policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
	return f(ctx, request)
}

type invalidRevisionStore struct{ store.RevisionStore }

func (s *invalidRevisionStore) GetRevision(context.Context, policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	return store.RevisionRecord{}, nil
}

type errorRevisionStore struct {
	store.RevisionStore
	err error
}

func (s *errorRevisionStore) GetRevision(context.Context, policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	return store.RevisionRecord{}, s.err
}

type manufacturingAsError struct {
	called       atomic.Bool
	manufactured *policyengine.EngineError
}

func (*manufacturingAsError) Error() string { return "secret dependency diagnostic" }

func (e *manufacturingAsError) As(target any) bool {
	e.called.Store(true)
	if destination, ok := target.(**policyengine.EngineError); ok {
		*destination = e.manufactured
		return true
	}
	return false
}

type panickingUnwrapError struct{ called atomic.Bool }

func (*panickingUnwrapError) Error() string { return "secret dependency diagnostic" }

func (e *panickingUnwrapError) Unwrap() error {
	e.called.Store(true)
	panic("hostile Unwrap invoked")
}

func checkWithoutPanic(service *app.AuthorizationService, request policyengine.CheckRequest, t testing.TB) (response policyengine.CheckResponse, err error, panicValue any) {
	t.Helper()
	defer func() { panicValue = recover() }()
	response, err = service.Check(context.Background(), mustCaller(t), request)
	return response, err, nil
}

type failingDataReader struct {
	store.DataReader
	openErr  error
	queryErr error
}

func (r *failingDataReader) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	if r.openErr != nil {
		return nil, r.openErr
	}
	snapshot, err := r.DataReader.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	return &failingSnapshot{Snapshot: snapshot, queryErr: r.queryErr}, nil
}

type failingSnapshot struct {
	store.Snapshot
	queryErr error
}

type pausingOpenDataReader struct {
	store.DataReader
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	opened  *trackingSnapshot
}

func newPausingOpenDataReader(reader store.DataReader) *pausingOpenDataReader {
	return &pausingOpenDataReader{DataReader: reader, entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *pausingOpenDataReader) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	close(r.entered)
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	snapshot, err := r.DataReader.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	tracked := &trackingSnapshot{Snapshot: snapshot}
	r.mu.Lock()
	r.opened = tracked
	r.mu.Unlock()
	return tracked, nil
}

func (r *pausingOpenDataReader) waitUntilOpen(t testing.TB) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenSnapshot was not called")
	}
}

func (r *pausingOpenDataReader) resumeOpen() { close(r.release) }

func (r *pausingOpenDataReader) openedSnapshot() *trackingSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened
}

type trackingSnapshot struct {
	store.Snapshot
	closeCalls atomic.Int32
}

func (s *trackingSnapshot) Close() error {
	s.closeCalls.Add(1)
	return s.Snapshot.Close()
}

func (s *failingSnapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	if s.queryErr != nil {
		return store.TupleResult{}, s.queryErr
	}
	return s.Snapshot.QueryTuples(ctx, query)
}

type recordingDecisionSink struct {
	calls int
	event policyengine.CompletedDecisionEvent
}

func (s *recordingDecisionSink) RecordDecision(_ context.Context, event policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
	s.calls++
	s.event = event
	delivery, _ := policyengine.NewDecisionDelivery(policyengine.DecisionDeliveryFailed, "DELIVERY_FAILED")
	return delivery
}

func mustEngineError(t testing.TB, category policyengine.ErrorCategory) error {
	t.Helper()
	err, constructorErr := policyengine.NewEngineError(category)
	requireNoError(t, constructorErr)
	return err
}

type pausingRevisionStore struct {
	store.RevisionStore
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
}

func newPausingRevisionStore(revisions store.RevisionStore) *pausingRevisionStore {
	return &pausingRevisionStore{RevisionStore: revisions}
}

func (s *pausingRevisionStore) pauseNextGet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered = make(chan struct{})
	s.release = make(chan struct{})
}

func (s *pausingRevisionStore) GetRevision(ctx context.Context, request policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	s.mu.Lock()
	entered, release := s.entered, s.release
	s.mu.Unlock()
	if entered != nil {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return store.RevisionRecord{}, ctx.Err()
		}
	}
	return s.RevisionStore.GetRevision(ctx, request)
}

func (s *pausingRevisionStore) waitUntilGet(t testing.TB) {
	t.Helper()
	s.mu.Lock()
	entered := s.entered
	s.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revision load did not start")
	}
}

func (s *pausingRevisionStore) resumeGet() {
	s.mu.Lock()
	release := s.release
	s.entered = nil
	s.release = nil
	s.mu.Unlock()
	close(release)
}
