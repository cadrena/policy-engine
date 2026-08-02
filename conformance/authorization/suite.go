// Package authorization provides reusable black-box conformance for complete
// embedded policy engines.
package authorization

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

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

// Run exercises policy allow/deny, approval requirements, revision pinning,
// contextual data, redaction, and caller capability enforcement.
func Run(t *testing.T, factory func(t *testing.T) policyengine.Engine) {
	t.Helper()
	t.Run("allow and deny are policy decisions", func(t *testing.T) {
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

	t.Run("approval is a decision requirement", func(t *testing.T) {
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

	t.Run("exact revision remains pinned after slot change", func(t *testing.T) {
		engine := factory(t)
		allowRevision := publish(t, engine, "allow.cdr", allowSource)
		activate(t, engine, allowRevision)
		denyRevision := publish(t, engine, "deny.cdr", denySource)
		activateFrom(t, engine, allowRevision, denyRevision)
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "", allowRevision, "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		if response.Result().RevisionID() != allowRevision || response.Result().Decision() != policyengine.DecisionAllow {
			t.Fatalf("exact revision was not retained")
		}
	})

	t.Run("batch pins one data snapshot", func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "snapshot.cdr", allowSource)
		activate(t, engine, revision)
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
		contextual := contextualViewers(t, "alice", "document-1", "document-2")
		request, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
			Namespace: policyNamespace, Selector: selector,
			Items: []policyengine.BatchCheckItem{first, second}, ContextualData: contextual,
		})
		requireNoError(t, err)
		response, err := engine.BatchCheck(context.Background(), caller(t, AuthorizedCallerID), request)
		requireNoError(t, err)
		results := response.Results()
		if len(results) != 2 || results[0].DataGeneration() != results[1].DataGeneration() ||
			results[0].RevisionID() != results[1].RevisionID() {
			t.Fatal("batch items did not share one pinned policy and data snapshot")
		}
	})

	t.Run("contextual data is used and reported", func(t *testing.T) {
		engine := factory(t)
		revision := publish(t, engine, "contextual.cdr", allowSource)
		activate(t, engine, revision)
		response, err := engine.Check(context.Background(), caller(t, AuthorizedCallerID), check(t, "stable", "", "alice", "document-1", contextualViewer(t, "alice", "document-1")))
		requireNoError(t, err)
		if response.Result().Decision() != policyengine.DecisionAllow || !response.Result().UsedContextualData() {
			t.Fatalf("contextual data behavior mismatch")
		}
	})

	t.Run("dynamic identifiers remain redacted", func(t *testing.T) {
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

	t.Run("caller capabilities fail closed", func(t *testing.T) {
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
	selector, err := policyengine.NewSelector(slot, revision)
	requireNoError(t, err)
	request, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: policyNamespace, Selector: selector,
		Subject: dsl.EntityRef{Type: "user", ID: subjectID}, Resource: dsl.EntityRef{Type: "document", ID: resourceID},
		Action: "view", ContextualData: contextual,
	})
	requireNoError(t, err)
	return request
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

func contextualViewers(t testing.TB, subjectID string, resourceIDs ...string) policyengine.ContextualData {
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
	result, err := policyengine.NewContextualData(tuples, nil)
	requireNoError(t, err)
	return result
}

func caller(t testing.TB, id string) policyengine.Caller {
	t.Helper()
	result, err := policyengine.NewCaller(id, nil)
	requireNoError(t, err)
	return result
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
