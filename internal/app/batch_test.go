package app_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestBatchCheckUsesOneRevisionAndGeneration(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	request := fixture.batchRequest(t, 3)

	response, err := fixture.service.BatchCheck(context.Background(), mustCaller(t), request)
	requireNoError(t, err)

	results := response.Results()
	for index := 1; index < len(results); index++ {
		if results[index].RevisionID() != results[0].RevisionID() ||
			results[index].DataGeneration() != results[0].DataGeneration() {
			t.Fatalf("batch item %d used a different snapshot", index)
		}
	}
}

func TestBatchCheckRejectsEmptyAndOverMaximumBatches(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	check := fixture.checkRequest(t)
	_, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(),
	})
	requireCategory(t, err, policyengine.ErrorInvalidArgument)

	item, err := policyengine.NewBatchCheckItem(check.Subject(), check.Resource(), check.Action(), check.Arguments())
	requireNoError(t, err)
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems+1)
	for index := range items {
		items[index] = item
	}
	_, err = policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items,
	})
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
}

func TestBatchCheckAcceptsMaximumItemCount(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	response, err := fixture.service.BatchCheck(context.Background(), mustCaller(t), fixture.batchRequest(t, policyengine.MaxBatchItems))
	requireNoError(t, err)
	if len(response.Results()) != policyengine.MaxBatchItems {
		t.Fatalf("results = %d, want %d", len(response.Results()), policyengine.MaxBatchItems)
	}
}

func TestBatchCheckReturnsNoPartialResponseOnItemEngineError(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	request := fixture.batchRequestWithActions(t, "view", "missing", "view")
	response, err := fixture.service.BatchCheck(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorFailedPrecondition)
	if len(response.Results()) != 0 {
		t.Fatalf("engine error returned %d authoritative partial results", len(response.Results()))
	}
}

func TestBatchCheckCancellationDuringIterationClosesSnapshot(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	ctx, cancel := context.WithCancel(context.Background())
	data := &cancelingDataReader{DataReader: fixture.adapter, cancel: cancel, cancelAt: 2}
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), data)
	response, err := service.BatchCheck(ctx, mustCaller(t), fixture.batchRequest(t, 3))
	requireCategory(t, err, policyengine.ErrorCanceled)
	if len(response.Results()) != 0 {
		t.Fatalf("cancellation returned %d authoritative partial results", len(response.Results()))
	}
	if data.opened == nil || data.opened.closeCalls.Load() != 1 {
		t.Fatal("batch snapshot was not closed exactly once")
	}
}

func TestBatchCheckRetainsSnapshotAcrossConcurrentSlotAndDataWrites(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	data := newPausingQueryDataReader(fixture.adapter)
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), data)
	results := make(chan policyengine.BatchCheckResponse, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := service.BatchCheck(context.Background(), mustCaller(t), fixture.batchRequest(t, 3))
		if err != nil {
			failures <- err
			return
		}
		results <- response
	}()

	data.waitUntilQuery(t)
	fixture.activate(t, fixture.denyRevision)
	write, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "tenant-a", ValidationRevisionID: fixture.allowRevision,
		ExpectedGeneration: 0, IdempotencyKey: "batch-concurrent-write",
		TupleWrites: []policyengine.RelationshipTuple{viewerTuple(t, "bob", "doc-2")},
	})
	requireNoError(t, err)
	_, err = fixture.adapter.WriteData(context.Background(), write)
	requireNoError(t, err)
	data.resumeQuery()

	select {
	case err := <-failures:
		t.Fatal(err)
	case response := <-results:
		for index, result := range response.Results() {
			if result.RevisionID() != fixture.allowRevision || result.DataGeneration() != 0 {
				t.Fatalf("item %d escaped original snapshot", index)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BatchCheck did not complete")
	}
}

func TestBatchCheckDelegationUsesOneCompleteOrderedBatchBinding(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	var calls atomic.Int32
	var firstFingerprint [32]byte
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(_ context.Context, request policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		if calls.Add(1) == 1 {
			firstFingerprint = request.Binding().Fingerprint().Bytes()
		}
		contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{viewerContextualTuple(t)}, nil)
		if err != nil {
			return policyengine.DelegationVerificationResult{}, err
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	request := fixture.batchRequestWithDelegation(t, []byte("delegation"), "doc-1", "doc-2")
	_, err := service.BatchCheck(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
	if calls.Load() != 1 {
		t.Fatalf("delegation verifier calls = %d, want 1 complete-batch verification", calls.Load())
	}

	var reorderedFingerprint [32]byte
	reorderedService := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(_ context.Context, request policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		reorderedFingerprint = request.Binding().Fingerprint().Bytes()
		contextual, contextualErr := policyengine.NewContextualData([]policyengine.RelationshipTuple{viewerContextualTuple(t)}, nil)
		if contextualErr != nil {
			return policyengine.DelegationVerificationResult{}, contextualErr
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	_, err = reorderedService.BatchCheck(context.Background(), mustCaller(t), fixture.batchRequestWithDelegation(t, []byte("delegation"), "doc-2", "doc-1"))
	requireNoError(t, err)
	if firstFingerprint == reorderedFingerprint {
		t.Fatal("ordered batch fingerprint did not change after item reorder")
	}
}

func TestBatchCheckAdditivelyMergesValidDirectAndDelegatedContextualData(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		delegated, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "doc-2"}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "user", ID: "alice"},
		}, nil)
		if err != nil {
			return policyengine.DelegationVerificationResult{}, err
		}
		contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{delegated}, nil)
		if err != nil {
			return policyengine.DelegationVerificationResult{}, err
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	}), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	base := fixture.batchRequestWithDelegation(t, []byte("delegation"), "doc-1", "doc-2")
	direct, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{viewerContextualTuple(t)}, nil)
	requireNoError(t, err)
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: base.Namespace(), Selector: base.Selector(), Items: base.Items(),
		ContextualData: direct, DelegationEvidence: base.DelegationEvidence(),
	})
	requireNoError(t, err)

	response, err := service.BatchCheck(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
	for index, result := range response.Results() {
		if result.Decision() != policyengine.DecisionAllow || !result.UsedContextualData() || !result.UsedDelegation() {
			t.Fatalf("result %d = %#v, want allow using direct and delegated contextual data", index, result)
		}
	}
}

func TestBatchCheckEnforcesAggregateGraphWorkBudget(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	tuples := make([]policyengine.RelationshipTuple, 101)
	for index := range tuples {
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "doc-1"}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "user", ID: fmt.Sprintf("user-%03d", index)},
		}, nil)
		requireNoError(t, err)
		tuples[index] = tuple
	}
	contextual, err := policyengine.NewContextualData(tuples, nil)
	requireNoError(t, err)
	check := fixture.checkRequest(t)
	item, err := policyengine.NewBatchCheckItem(check.Subject(), check.Resource(), check.Action(), nil)
	requireNoError(t, err)
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems)
	for index := range items {
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items, ContextualData: contextual,
	})
	requireNoError(t, err)
	response, err := fixture.service.BatchCheck(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
	if len(response.Results()) != 0 {
		t.Fatal("graph budget exhaustion returned authoritative partial results")
	}
}

func TestBatchCheckEnforcesAggregateVerifierWorkBudget(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	revision := publishSource(context.Background(), t, fixture.policyService, mustCaller(t), "batch-approval.cdr", `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view {
    require_approval finance when arguments.flag == true
    require_approval legal when arguments.flag == true
    allow otherwise
}
`).Revision().ID()
	fixture.activate(t, revision)
	service := fixture.newService(t, approvalVerifierFunc(func(_ context.Context, _ policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
		return policyengine.NewApprovalVerificationResult([]string{"finance", "legal"})
	}), policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), fixture.adapter)
	flag := policyengine.NewBooleanValue(true)
	check := fixture.checkRequest(t)
	item, err := policyengine.NewBatchCheckItem(check.Subject(), check.Resource(), check.Action(), map[string]policyengine.Value{"flag": flag})
	requireNoError(t, err)
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems)
	for index := range items {
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items,
		ContextualData: check.ContextualData(), ApprovalEvidence: []byte("approval"),
	})
	requireNoError(t, err)
	response, err := service.BatchCheck(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
	if len(response.Results()) != 0 {
		t.Fatal("verifier budget exhaustion returned authoritative partial results")
	}
}

func (f *authorizationFixture) batchRequest(t testing.TB, count int) policyengine.BatchCheckRequest {
	t.Helper()
	check := f.checkRequest(t)
	items := make([]policyengine.BatchCheckItem, count)
	for index := range items {
		item, err := policyengine.NewBatchCheckItem(check.Subject(), check.Resource(), check.Action(), check.Arguments())
		requireNoError(t, err)
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items,
		ContextualData: check.ContextualData(), MinimumGeneration: check.MinimumGeneration(),
	})
	requireNoError(t, err)
	return request
}

func (f *authorizationFixture) batchRequestWithActions(t testing.TB, actions ...string) policyengine.BatchCheckRequest {
	t.Helper()
	check := f.checkRequest(t)
	items := make([]policyengine.BatchCheckItem, len(actions))
	for index, action := range actions {
		item, err := policyengine.NewBatchCheckItem(check.Subject(), check.Resource(), action, check.Arguments())
		requireNoError(t, err)
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items, ContextualData: check.ContextualData(),
	})
	requireNoError(t, err)
	return request
}

func (f *authorizationFixture) batchRequestWithDelegation(t testing.TB, evidence []byte, resourceIDs ...string) policyengine.BatchCheckRequest {
	t.Helper()
	check := f.checkRequest(t)
	items := make([]policyengine.BatchCheckItem, len(resourceIDs))
	for index, resourceID := range resourceIDs {
		resource := check.Resource()
		resource.ID = resourceID
		item, err := policyengine.NewBatchCheckItem(check.Subject(), resource, check.Action(), check.Arguments())
		requireNoError(t, err)
		items[index] = item
	}
	request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Items: items,
		DelegationEvidence: evidence,
	})
	requireNoError(t, err)
	return request
}

type cancelingDataReader struct {
	store.DataReader
	cancel   context.CancelFunc
	cancelAt int32
	opened   *cancelingSnapshot
}

func (r *cancelingDataReader) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	snapshot, err := r.DataReader.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	r.opened = &cancelingSnapshot{Snapshot: snapshot, cancel: r.cancel, cancelAt: r.cancelAt}
	return r.opened, nil
}

type cancelingSnapshot struct {
	store.Snapshot
	cancel     context.CancelFunc
	cancelAt   int32
	queryCalls atomic.Int32
	closeCalls atomic.Int32
}

func (s *cancelingSnapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	if s.queryCalls.Add(1) == s.cancelAt {
		s.cancel()
	}
	return s.Snapshot.QueryTuples(ctx, query)
}

func (s *cancelingSnapshot) Close() error {
	s.closeCalls.Add(1)
	return s.Snapshot.Close()
}

type pausingQueryDataReader struct {
	store.DataReader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newPausingQueryDataReader(reader store.DataReader) *pausingQueryDataReader {
	return &pausingQueryDataReader{DataReader: reader, entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *pausingQueryDataReader) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	snapshot, err := r.DataReader.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	return &pausingQuerySnapshot{Snapshot: snapshot, parent: r}, nil
}

func (r *pausingQueryDataReader) waitUntilQuery(t testing.TB) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("batch tuple query did not start")
	}
}

func (r *pausingQueryDataReader) resumeQuery() { close(r.release) }

type pausingQuerySnapshot struct {
	store.Snapshot
	parent *pausingQueryDataReader
}

func (s *pausingQuerySnapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	s.parent.once.Do(func() { close(s.parent.entered) })
	select {
	case <-s.parent.release:
	case <-ctx.Done():
		return store.TupleResult{}, ctx.Err()
	}
	return s.Snapshot.QueryTuples(ctx, query)
}
