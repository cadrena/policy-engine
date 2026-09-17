package app_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	"github.com/cadrena/policy-engine/store"
)

const resourcePolicyPrefix = `entity user {} entity document { relation viewer @user action view = viewer } `

func resourceFixture(t *testing.T, guard string) (*authorizationFixture, string) {
	t.Helper()
	f := newAuthorizationFixture(t)
	revision := publishSource(context.Background(), t, f.policyService, mustCaller(t), "resource.cdr", resourcePolicyPrefix+guard).Revision().ID()
	f.activate(t, revision)
	return f, revision
}
func writeResource(t *testing.T, f *authorizationFixture, revision string, generation uint64, key string, attrs []pe.Attribute) {
	t.Helper()
	service, err := app.NewDataService(f.adapter, f.adapter, f.adapter, allowAuthorizer{})
	requireNoError(t, err)
	request, err := pe.NewWriteDataRequest(pe.WriteDataRequestInput{Namespace: "tenant-a", ValidationRevisionID: revision, ExpectedGeneration: generation, IdempotencyKey: key, AttributeWrites: attrs})
	requireNoError(t, err)
	_, err = service.WriteData(context.Background(), dataWriterCaller(t), request)
	requireNoError(t, err)
}
func resourceAttribute(t *testing.T, path []string, value pe.Value) pe.Attribute {
	t.Helper()
	attribute, err := pe.NewAttributePath(dsl.EntityRef{Type: "document", ID: "doc-1"}, path, value)
	requireNoError(t, err)
	return attribute
}
func resourceRequest(t *testing.T, f *authorizationFixture, attributes []pe.Attribute) pe.CheckRequest {
	t.Helper()
	base := f.checkRequest(t)
	contextual, err := pe.NewContextualData(base.ContextualData().Tuples(), attributes)
	requireNoError(t, err)
	request, err := pe.NewCheckRequest(pe.CheckRequestInput{Namespace: base.Namespace(), Selector: base.Selector(), Subject: base.Subject(), Resource: base.Resource(), Action: base.Action(), ContextualData: contextual})
	requireNoError(t, err)
	return request
}
func TestResourceAttributesReachCheckBatchAndExplain(t *testing.T) {
	public, err := pe.NewStringValue("public")
	requireNoError(t, err)
	restricted, err := pe.NewStringValue("restricted")
	requireNoError(t, err)
	for _, test := range []struct {
		name, guard string
		path        []string
		value       pe.Value
		present     bool
		want        pe.Decision
	}{
		{"nested string", `guard document.view { allow when resource.metadata.classification == "public" }`, []string{"metadata", "classification"}, public, true, pe.DecisionAllow},
		{"restricted deny", `guard document.view { deny when resource.classification == "restricted" allow otherwise }`, []string{"classification"}, restricted, true, pe.DecisionDeny},
		{"integer", `guard document.view { allow when resource.amount == 7 }`, []string{"amount"}, pe.NewIntegerValue(7), true, pe.DecisionAllow},
		{"boolean", `guard document.view { allow when resource.enabled == false }`, []string{"enabled"}, pe.NewBooleanValue(false), true, pe.DecisionAllow},
		{"explicit null", `guard document.view { allow when resource.metadata.optional == null }`, []string{"metadata", "optional"}, pe.NewNullValue(), true, pe.DecisionAllow},
		{"missing differs from null", `guard document.view { allow when resource.metadata.optional == null }`, []string{"metadata", "optional"}, pe.NewNullValue(), false, pe.DecisionDeny},
	} {
		for _, stored := range []bool{false, true} {
			name := test.name + " contextual"
			if stored {
				name = test.name + " stored"
			}
			t.Run(name, func(t *testing.T) {
				f, revision := resourceFixture(t, test.guard)
				var attributes []pe.Attribute
				if test.present {
					attributes = []pe.Attribute{resourceAttribute(t, test.path, test.value)}
				}
				generation := uint64(0)
				if stored && test.present {
					writeResource(t, f, revision, 0, "initial", attributes)
					attributes = nil
					generation = 1
				}
				request := resourceRequest(t, f, attributes)
				response, err := f.service.Check(context.Background(), mustCaller(t), request)
				requireNoError(t, err)
				assertResourceDecision(t, response.Result(), test.want, generation)
				item, err := pe.NewBatchCheckItem(request.Subject(), request.Resource(), request.Action(), nil)
				requireNoError(t, err)
				batch, err := pe.NewBatchCheckRequest(pe.BatchCheckRequestInput{Namespace: request.Namespace(), Selector: request.Selector(), Items: []pe.BatchCheckItem{item, item}, ContextualData: request.ContextualData()})
				requireNoError(t, err)
				batchResponse, err := f.service.BatchCheck(context.Background(), mustCaller(t), batch)
				requireNoError(t, err)
				for _, result := range batchResponse.Results() {
					assertResourceDecision(t, result, test.want, generation)
				}
				explain, err := pe.NewExplainRequest(request)
				requireNoError(t, err)
				explained, err := f.service.Explain(context.Background(), mustCaller(t), explain)
				requireNoError(t, err)
				assertResourceDecision(t, explained.Result(), test.want, generation)
			})
		}
	}
}
func assertResourceDecision(t *testing.T, result pe.DecisionResult, want pe.Decision, generation uint64) {
	t.Helper()
	if result.Decision() != want || result.DataGeneration() != generation {
		t.Fatalf("decision=%s generation=%d want=%s/%d", result.Decision(), result.DataGeneration(), want, generation)
	}
}

type attributeReader struct {
	store.DataReader
	get    func(context.Context, store.Snapshot, pe.AttributeKey) (store.AttributeResult, error)
	closed atomic.Int32
	reads  atomic.Int32
}
type attributeSnapshot struct {
	store.Snapshot
	owner *attributeReader
}

func (r *attributeReader) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	s, err := r.DataReader.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	return &attributeSnapshot{Snapshot: s, owner: r}, nil
}
func (s *attributeSnapshot) GetAttribute(ctx context.Context, key pe.AttributeKey) (store.AttributeResult, error) {
	s.owner.reads.Add(1)
	return s.owner.get(ctx, s.Snapshot, key)
}
func (s *attributeSnapshot) Close() error { s.owner.closed.Add(1); return s.Snapshot.Close() }
func TestResourceAttributeReadsStayOnPinnedSnapshot(t *testing.T) {
	f, revision := resourceFixture(t, `guard document.view { deny when resource.classification == "restricted" allow otherwise }`)
	public, err := pe.NewStringValue("public")
	requireNoError(t, err)
	restricted, err := pe.NewStringValue("restricted")
	requireNoError(t, err)
	writeResource(t, f, revision, 0, "initial", []pe.Attribute{resourceAttribute(t, []string{"classification"}, public)})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	reader := &attributeReader{DataReader: f.adapter}
	reader.get = func(ctx context.Context, snapshot store.Snapshot, key pe.AttributeKey) (store.AttributeResult, error) {
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		return snapshot.GetAttribute(ctx, key)
	}
	service := f.newService(t, pe.DefaultApprovalVerifier(), pe.DefaultDelegationVerifier(), pe.DefaultDecisionEventSink(), reader)
	request := resourceRequest(t, f, nil)
	caller := mustCaller(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan pe.CheckResponse, 1)
	failure := make(chan error, 1)
	go func() {
		r, err := service.Check(ctx, caller, request)
		if err != nil {
			failure <- err
			return
		}
		result <- r
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("attribute lookup not reached")
	}
	writeResource(t, f, revision, 1, "changed", []pe.Attribute{resourceAttribute(t, []string{"classification"}, restricted)})
	close(release)
	select {
	case err := <-failure:
		t.Fatal(err)
	case r := <-result:
		assertResourceDecision(t, r.Result(), pe.DecisionAllow, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("pinned check stalled")
	}
	r, err := service.Check(context.Background(), caller, request)
	requireNoError(t, err)
	assertResourceDecision(t, r.Result(), pe.DecisionDeny, 2)
	if reader.closed.Load() != 2 {
		t.Fatal("attribute snapshot not closed")
	}
}
func TestResourceAttributeErrorsAndCancellationDoNotBecomeDecisions(t *testing.T) {
	for _, test := range []struct {
		name     string
		get      func(context.Context, store.Snapshot, pe.AttributeKey) (store.AttributeResult, error)
		category pe.ErrorCategory
	}{
		{"storage failure", func(context.Context, store.Snapshot, pe.AttributeKey) (store.AttributeResult, error) {
			return store.AttributeResult{}, errors.New("private storage failure")
		}, pe.ErrorUnavailable},
		{"invalid result", func(context.Context, store.Snapshot, pe.AttributeKey) (store.AttributeResult, error) {
			return store.AttributeResult{}, nil
		}, pe.ErrorIntegrity},
		{"wrong key", func(_ context.Context, _ store.Snapshot, _ pe.AttributeKey) (store.AttributeResult, error) {
			key, err := pe.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "other"}, "classification")
			if err != nil {
				return store.AttributeResult{}, err
			}
			return store.NewAttributeResult(key, pe.NewNullValue(), true)
		}, pe.ErrorIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := resourceFixture(t, `guard document.view { deny when resource.classification == "restricted" allow otherwise }`)
			reader := &attributeReader{DataReader: f.adapter, get: test.get}
			service := f.newService(t, pe.DefaultApprovalVerifier(), pe.DefaultDelegationVerifier(), pe.DefaultDecisionEventSink(), reader)
			_, err := service.Check(context.Background(), mustCaller(t), resourceRequest(t, f, nil))
			requireCategory(t, err, test.category)
			if reader.closed.Load() != 1 {
				t.Fatal("failed attribute read leaked snapshot")
			}
		})
	}
	f, _ := resourceFixture(t, `guard document.view { allow when resource.classification == "public" }`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &attributeReader{DataReader: f.adapter, get: func(ctx context.Context, _ store.Snapshot, _ pe.AttributeKey) (store.AttributeResult, error) {
		cancel()
		return store.AttributeResult{}, ctx.Err()
	}}
	service := f.newService(t, pe.DefaultApprovalVerifier(), pe.DefaultDelegationVerifier(), pe.DefaultDecisionEventSink(), reader)
	_, err := service.Check(ctx, mustCaller(t), resourceRequest(t, f, nil))
	requireCategory(t, err, pe.ErrorCanceled)
	if reader.closed.Load() != 1 {
		t.Fatal("canceled attribute read leaked snapshot")
	}
}
func TestResourceAttributeBatchByteBudgetIsShared(t *testing.T) {
	f, revision := resourceFixture(t, `guard document.view { allow when resource.classification != "restricted" }`)
	large, err := pe.NewStringValue(strings.Repeat("x", pe.MaxStringValueBytes))
	requireNoError(t, err)
	writeResource(t, f, revision, 0, "large", []pe.Attribute{resourceAttribute(t, []string{"classification"}, large)})
	request := resourceRequest(t, f, nil)
	item, err := pe.NewBatchCheckItem(request.Subject(), request.Resource(), request.Action(), nil)
	requireNoError(t, err)
	items := make([]pe.BatchCheckItem, 70)
	for i := range items {
		items[i] = item
	}
	batch, err := pe.NewBatchCheckRequest(pe.BatchCheckRequestInput{Namespace: request.Namespace(), Selector: request.Selector(), Items: items, ContextualData: request.ContextualData()})
	requireNoError(t, err)
	response, err := f.service.BatchCheck(context.Background(), mustCaller(t), batch)
	requireCategory(t, err, pe.ErrorResourceExhausted)
	if len(response.Results()) != 0 {
		t.Fatal("attribute budget failure exposed partial results")
	}
}

func TestResourceAttributePrefixCollisionFailsClosed(t *testing.T) {
	f, _ := resourceFixture(t, `guard document.view { allow when resource.metadata == "flat" or resource.metadata.classification == "public" allow otherwise }`)
	value, err := pe.NewStringValue("public")
	requireNoError(t, err)
	reader := &attributeReader{DataReader: f.adapter, get: func(_ context.Context, _ store.Snapshot, key pe.AttributeKey) (store.AttributeResult, error) {
		return store.NewAttributeResult(key, value, true)
	}}
	service := f.newService(t, pe.DefaultApprovalVerifier(), pe.DefaultDelegationVerifier(), pe.DefaultDecisionEventSink(), reader)
	_, err = service.Check(context.Background(), mustCaller(t), resourceRequest(t, f, nil))
	requireCategory(t, err, pe.ErrorIntegrity)
	if reader.closed.Load() != 1 {
		t.Fatal("prefix conflict leaked snapshot")
	}
}
func TestResourceAttributesReadOnlySelectedAction(t *testing.T) {
	f := newAuthorizationFixture(t)
	source := `entity user {} entity document { relation viewer @user action view = viewer action edit = viewer }
 guard document.view { allow otherwise }
 guard document.edit { deny when resource.private == true allow otherwise }`
	revision := publishSource(context.Background(), t, f.policyService, mustCaller(t), "actions.cdr", source).Revision().ID()
	f.activate(t, revision)
	reader := &attributeReader{DataReader: f.adapter, get: func(context.Context, store.Snapshot, pe.AttributeKey) (store.AttributeResult, error) {
		return store.AttributeResult{}, errors.New("unselected action field must not be read")
	}}
	service := f.newService(t, pe.DefaultApprovalVerifier(), pe.DefaultDelegationVerifier(), pe.DefaultDecisionEventSink(), reader)
	response, err := service.Check(context.Background(), mustCaller(t), resourceRequest(t, f, nil))
	requireNoError(t, err)
	if response.Result().Decision() != pe.DecisionAllow || reader.reads.Load() != 0 {
		t.Fatal("check read another action's guard fields")
	}
}
