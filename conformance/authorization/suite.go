// Package authorization provides reusable black-box conformance for complete
// embedded policy engines.
package authorization

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// PinningController supplies deterministic pause points after authoritative
// revision selection and after a data snapshot has been opened. Conformance
// factories must return an Engine that also implements this interface.
type PinningController interface {
	PauseNextRevisionLoad() (entered <-chan struct{}, resume func())
	PauseNextSnapshotOpen() (entered <-chan struct{}, resume func())
}

// ApprovalBindingObserver exposes the bindings consumed by a conformance
// approval verifier. It is a conformance-only fixture hook.
type ApprovalBindingObserver interface {
	ApprovalBindings() []policyengine.EvidenceBinding
}

var caseNames = [...]string{
	"allow-and-deny-are-policy-decisions",
	"approval-is-a-decision-requirement",
	"approval-binding-digest-presence-and-redaction",
	"approval-binding-digest-retry-stability",
	"approval-binding-digest-item-substitution-resistance",
	"approval-binding-verifier-result-equality",
	"check-retains-revision-pinned-before-concurrent-slot-change",
	"batch-retains-snapshot-pinned-before-concurrent-data-write",
	"contextual-data-is-used-and-reported",
	"dynamic-identifiers-remain-redacted",
	"caller-capabilities-fail-closed",
}

const (
	// AuthorizedCallerID identifies the caller a conformance factory must map to
	// exactly the capabilities requested by each operation.
	AuthorizedCallerID = "conformance-authorized"
	// DeniedCallerID identifies the caller a conformance factory must reject.
	DeniedCallerID  = "conformance-denied"
	policyNamespace = "conformance"
)

const allowSource = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { allow otherwise }
`

const denySource = `
entity user {}
entity document {
    relation viewer @user
    relation editor @user
    action view = editor
}
guard document.view { allow otherwise }
`

const approvalSource = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { require_approval finance otherwise }
`

// CaseNames returns a defensive copy of the stable conformance case manifest.
func CaseNames() []string { return append([]string(nil), caseNames[:]...) }

// Run exercises policy allow/deny, approval requirements, revision pinning,
// contextual data, redaction, and caller capability enforcement.
func Run(t *testing.T, factory func(t *testing.T) policyengine.Engine) {
	t.Helper()
	t.Run(caseNames[0], func(t *testing.T) {
		engine := factory(t)
		allowRevision := publish(t, engine, "allow.cdr", allowSource)
		activate(t, engine, allowRevision)
		allowed, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		if allowed.Result().Decision() != policyengine.DecisionAllow {
			t.Fatalf("allow decision mismatch")
		}

		engine = factory(t)
		denyRevision := publish(t, engine, "deny.cdr", denySource)
		activate(t, engine, denyRevision)
		denied, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		if denied.Result().Decision() != policyengine.DecisionDeny {
			t.Fatalf("deny decision mismatch")
		}
	})

	t.Run(caseNames[1], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "approval.cdr", approvalSource)
		activate(t, engine, revision)
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		result := response.Result()
		if result.Decision() != policyengine.DecisionRequireApproval || len(result.Requirements()) != 1 || result.Requirements()[0] != "finance" {
			t.Fatalf("approval requirement mismatch")
		}
	})

	t.Run(caseNames[2], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "approval.cdr", approvalSource)
		activate(t, engine, revision)
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		digest, ok := response.Result().ApprovalBindingDigest()
		if response.Result().Decision() != policyengine.DecisionRequireApproval || !ok || digest == ([32]byte{}) {
			t.Fatal("require-approval result did not expose a non-zero approval binding digest")
		}
		canaries := []string{fmt.Sprintf("%x", digest), fmt.Sprintf("%v", digest)}
		for _, formatted := range []string{fmt.Sprintf("%v", response.Result()), fmt.Sprintf("%+v", response.Result()), fmt.Sprintf("%#v", response.Result())} {
			for _, canary := range canaries {
				if strings.Contains(formatted, canary) {
					t.Fatalf("approval digest escaped result formatting: %q", formatted)
				}
			}
		}
		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("decision", "result", response.Result())
		for _, canary := range canaries {
			if strings.Contains(logs.String(), canary) {
				t.Fatalf("approval digest escaped slog output: %q", logs.String())
			}
		}
		for _, source := range []string{allowSource, denySource} {
			ordinary := factory(t)
			ordinaryRevision := publish(t, ordinary, "ordinary.cdr", source)
			activate(t, ordinary, ordinaryRevision)
			result, resultErr := ordinary.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
			requireNoError(t, resultErr)
			if result.Result().Decision() == policyengine.DecisionRequireApproval {
				t.Fatal("ordinary policy unexpectedly required approval")
			}
			if _, ok := result.Result().ApprovalBindingDigest(); ok {
				t.Fatalf("%v result exposed an approval digest", result.Result().Decision())
			}
		}
	})

	t.Run(caseNames[3], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "approval.cdr", approvalSource)
		activate(t, engine, revision)
		request := check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1"))
		first, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), request)
		requireNoError(t, err)
		retry, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), request)
		requireNoError(t, err)
		if got, want := mustApprovalDigest(t, retry.Result()), mustApprovalDigest(t, first.Result()); got != want {
			t.Fatalf("retry digest = %x, want %x", got, want)
		}
	})

	t.Run(caseNames[4], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "approval.cdr", approvalSource)
		activate(t, engine, revision)
		first := approvalBatchItem(t, "document-1")
		second := approvalBatchItem(t, "document-2")
		request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
			Namespace: policyNamespace, Selector: selector(t, "stable", ""), Items: []policyengine.BatchCheckItem{first, second}, ContextualData: approvalBatchContextual(t),
		})
		requireNoError(t, err)
		response, err := engine.BatchCheck(context.Background(), caller(t, AuthorizedCallerID), request)
		requireNoError(t, err)
		results := response.Results()
		if len(results) != 2 {
			t.Fatalf("results = %d, want 2", len(results))
		}
		firstDigest := mustApprovalDigest(t, results[0])
		if firstDigest == mustApprovalDigest(t, results[1]) {
			t.Fatal("batch item substitution did not change the approval digest")
		}
		changedNeighbor, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
			Namespace: policyNamespace, Selector: selector(t, "stable", ""), Items: []policyengine.BatchCheckItem{first, approvalBatchItem(t, "document-3")}, ContextualData: approvalBatchContextual(t),
		})
		requireNoError(t, err)
		retry, err := engine.BatchCheck(context.Background(), caller(t, AuthorizedCallerID), changedNeighbor)
		requireNoError(t, err)
		if got := mustApprovalDigest(t, retry.Results()[0]); got != firstDigest {
			t.Fatalf("neighbor substitution changed first item digest = %x, want %x", got, firstDigest)
		}
	})

	t.Run(caseNames[5], func(t *testing.T) {
		engine := factory(t)
		observer, ok := engine.(ApprovalBindingObserver)
		if !ok || observer == nil {
			t.Fatal("conformance factory engine does not implement ApprovalBindingObserver")
		}
		revision := publish(t, engine, "approval.cdr", approvalSource)
		activate(t, engine, revision)
		request := withApprovalEvidence(t, check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")), []byte("conformance-approval"))
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), request)
		requireNoError(t, err)
		bindings := observer.ApprovalBindings()
		if len(bindings) != 1 {
			t.Fatalf("approval verifier bindings = %d, want 1", len(bindings))
		}
		got, ok := bindings[0].AuthorizationDigest()
		if !ok || got != mustApprovalDigest(t, response.Result()) {
			t.Fatal("approval verifier and returned result used different bindings")
		}
	})

	t.Run(caseNames[6], func(t *testing.T) {
		engine := factory(t)
		controller := pinningController(t, engine)
		allowRevision := publish(t, engine, "allow.cdr", allowSource)
		activate(t, engine, allowRevision)
		denyRevision := publish(t, engine, "deny.cdr", denySource)
		request := check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1"))
		actor := caller(t, AuthorizedCallerID)
		entered, resume := controller.PauseNextRevisionLoad()
		responses := make(chan policyengine.CheckResponse, 1)
		failures := make(chan error, 1)
		go func() {
			response, err := engine.Check(context.Background(), actor, request)
			if err != nil {
				failures <- err
				return
			}
			responses <- response
		}()
		awaitSignal(t, entered, "revision load")
		activateFrom(t, engine, allowRevision, denyRevision)
		resume()
		response := awaitCheck(t, responses, failures)
		if response.Result().RevisionID() != allowRevision || response.Result().Decision() != policyengine.DecisionAllow {
			t.Fatalf("check switched away from the revision pinned before activation")
		}
	})

	t.Run(caseNames[7], func(t *testing.T) {
		engine := factory(t)
		controller := pinningController(t, engine)
		revision := publish(t, engine, "snapshot.cdr", allowSource)
		activate(t, engine, revision)
		writeViewers(t, engine, revision, "initial-snapshot-data", 0, "alice", "document-1", "document-2")
		selector, err := policyengine.NewSelector("stable", "")
		requireNoError(t, err)
		first, err := policyengine.NewBatchCheckItem(
			dsl.EntityRef{Type: "user", ID: "alice"},
			dsl.EntityRef{Type: "document", ID: "document-1"}, "view", nil,
		)
		requireNoError(t, err)
		second, err := policyengine.NewBatchCheckItem(
			dsl.EntityRef{Type: "user", ID: "alice"},
			dsl.EntityRef{Type: "document", ID: "document-2"}, "view", nil,
		)
		requireNoError(t, err)
		request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
			Namespace: policyNamespace, Selector: selector,
			Items: []policyengine.BatchCheckItem{first, second},
		})
		requireNoError(t, err)
		actor := caller(t, AuthorizedCallerID)
		entered, resume := controller.PauseNextSnapshotOpen()
		responses := make(chan policyengine.BatchCheckResponse, 1)
		failures := make(chan error, 1)
		go func() {
			response, err := engine.BatchCheck(context.Background(), actor, request)
			if err != nil {
				failures <- err
				return
			}
			responses <- response
		}()
		awaitSignal(t, entered, "data snapshot")
		deleteViewer(t, engine, revision, "concurrent-conformance-delete", 1, "alice", "document-2")
		resume()
		response := awaitBatch(t, responses, failures)
		results := response.Results()
		if len(results) != 2 || results[0].DataGeneration() != 1 || results[1].DataGeneration() != 1 ||
			results[0].RevisionID() != revision || results[1].RevisionID() != revision ||
			results[0].Decision() != policyengine.DecisionAllow || results[1].Decision() != policyengine.DecisionAllow {
			t.Fatal("batch did not retain the policy and generation pinned before the write")
		}
		headRequest, err := policyengine.NewGetDataGenerationRequest(policyNamespace)
		requireNoError(t, err)
		head, err := engine.GetDataGeneration(context.Background(), caller(t, AuthorizedCallerID), headRequest)
		requireNoError(t, err)
		if head.Generation() != 2 {
			t.Fatalf("concurrent write generation = %d, want 2", head.Generation())
		}
	})

	t.Run(caseNames[8], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "contextual.cdr", allowSource)
		activate(t, engine, revision)
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		if response.Result().Decision() != policyengine.DecisionAllow || !response.Result().UsedContextualData() {
			t.Fatalf("contextual data behavior mismatch")
		}
	})

	t.Run(caseNames[9], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "redaction.cdr", allowSource)
		activate(t, engine, revision)
		const canary = "secret-resource-canary-7e13"
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", canary, contextualViewer(t, "alice", canary)))
		requireNoError(t, err)
		if strings.Contains(fmt.Sprintf("%#v", response), canary) || strings.Contains(fmt.Sprint(response), canary) {
			t.Fatal("dynamic identifier escaped response formatting")
		}
	})

	t.Run(caseNames[10], func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "capabilities.cdr", allowSource)
		activate(t, engine, revision)
		_, err := engine.Check(context.Background(), caller(t, DeniedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireCategory(t, err, policyengine.ErrorPermissionDenied)
	})
}

func publish(t testing.TB, engine policyengine.Engine, name, source string) string {
	t.Helper()
	request, err := policyengine.NewPublishRequest(policyNamespace, name, []byte(source))
	requireNoError(t, err)
	response, err := engine.Publish(context.Background(), caller(t, AuthorizedCallerID), request)
	requireNoError(t, err)
	return response.Revision().ID()
}

func activate(t testing.TB, engine policyengine.Engine, revision string) {
	t.Helper()
	request, err := policyengine.NewActivateRequest(policyNamespace, "stable", revision, policyengine.NewUnsetSlotExpectation())
	requireNoError(t, err)
	_, err = engine.Activate(context.Background(), caller(t, AuthorizedCallerID), request)
	requireNoError(t, err)
}

func activateFrom(t testing.TB, engine policyengine.Engine, current, target string) {
	t.Helper()
	expectation, err := policyengine.NewActiveSlotExpectation(current, 1)
	requireNoError(t, err)
	request, err := policyengine.NewActivateRequest(policyNamespace, "stable", target, expectation)
	requireNoError(t, err)
	_, err = engine.Activate(context.Background(), caller(t, AuthorizedCallerID), request)
	requireNoError(t, err)
}

func check(t testing.TB, slot, revision, subjectID, resourceID string, contextual policyengine.ContextualData) policyengine.CheckRequest {
	t.Helper()
	selector := selector(t, slot, revision)
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: policyNamespace, Selector: selector,
		Subject: dsl.EntityRef{Type: "user", ID: subjectID}, Resource: dsl.EntityRef{Type: "document", ID: resourceID},
		Action: "view", ContextualData: contextual,
	})
	requireNoError(t, err)
	return request
}

func selector(t testing.TB, slot, revision string) policyengine.Selector {
	t.Helper()
	result, err := policyengine.NewSelector(slot, revision)
	requireNoError(t, err)
	return result
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

func approvalBatchItem(t testing.TB, resourceID string) policyengine.BatchCheckItem {
	t.Helper()
	item, err := policyengine.NewBatchCheckItem(
		dsl.EntityRef{Type: "user", ID: "alice"},
		dsl.EntityRef{Type: "document", ID: resourceID},
		"view", nil,
	)
	requireNoError(t, err)
	return item
}

func approvalBatchContextual(t testing.TB) policyengine.ContextualData {
	t.Helper()
	tuples := make([]policyengine.RelationshipTuple, 0, 3)
	for _, resourceID := range []string{"document-1", "document-2", "document-3"} {
		tuples = append(tuples, contextualViewer(t, "alice", resourceID).Tuples()...)
	}
	contextual, err := policyengine.NewContextualData(tuples, nil)
	requireNoError(t, err)
	return contextual
}

func mustApprovalDigest(t testing.TB, result policyengine.DecisionResult) [32]byte {
	t.Helper()
	digest, ok := result.ApprovalBindingDigest()
	if !ok || digest == ([32]byte{}) {
		t.Fatal("require-approval result has no approval binding digest")
	}
	return digest
}

func contextualViewer(t testing.TB, subjectID, resourceID string) policyengine.ContextualData {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: resourceID}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: subjectID},
	}, nil)
	requireNoError(t, err)
	result, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, nil)
	requireNoError(t, err)
	return result
}

func caller(t testing.TB, id string) policyengine.Caller {
	t.Helper()
	result, err := policyengine.NewCaller(id, nil)
	requireNoError(t, err)
	return result
}

func pinningController(t testing.TB, engine policyengine.Engine) PinningController {
	t.Helper()
	controller, ok := engine.(PinningController)
	if !ok || controller == nil {
		t.Fatal("conformance factory engine does not implement PinningController")
	}
	return controller
}

func writeViewers(t testing.TB, engine policyengine.Engine, revision, idempotencyKey string, expected uint64, subjectID string, resourceIDs ...string) {
	t.Helper()
	tuples := make([]policyengine.RelationshipTuple, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: resourceID}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "user", ID: subjectID},
		}, nil)
		requireNoError(t, err)
		tuples = append(tuples, tuple)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: policyNamespace, ValidationRevisionID: revision,
		ExpectedGeneration: expected, IdempotencyKey: idempotencyKey, TupleWrites: tuples,
	})
	requireNoError(t, err)
	_, err = engine.WriteData(context.Background(), caller(t, AuthorizedCallerID), request)
	requireNoError(t, err)
}

func deleteViewer(t testing.TB, engine policyengine.Engine, revision, idempotencyKey string, expected uint64, subjectID, resourceID string) {
	t.Helper()
	key, err := policyengine.NewTupleKey(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: resourceID}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: subjectID},
	})
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: policyNamespace, ValidationRevisionID: revision,
		ExpectedGeneration: expected, IdempotencyKey: idempotencyKey,
		TupleDeletes: []policyengine.TupleKey{key},
	})
	requireNoError(t, err)
	_, err = engine.WriteData(context.Background(), caller(t, AuthorizedCallerID), request)
	requireNoError(t, err)
}

func awaitSignal(t testing.TB, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s pause", name)
	}
}

func awaitCheck(t testing.TB, responses <-chan policyengine.CheckResponse, failures <-chan error) policyengine.CheckResponse {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for concurrent check")
	}
	return policyengine.CheckResponse{}
}

func awaitBatch(t testing.TB, responses <-chan policyengine.BatchCheckResponse, failures <-chan error) policyengine.BatchCheckResponse {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for concurrent batch")
	}
	return policyengine.BatchCheckResponse{}
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
