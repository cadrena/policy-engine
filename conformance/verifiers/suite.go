// Package verifiers provides reusable black-box conformance for approval and
// delegation verifier implementations.
package verifiers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

const approvalRequirement = "conformance-approval"

// RunApproval verifies canonical approval and cancellation behavior through
// the public invocation boundary.
func RunApproval(t *testing.T, factory func(t *testing.T) policyengine.ApprovalVerifier) {
	t.Helper()
	t.Run("approves canonical requested evidence", func(t *testing.T) {
		verifier := factory(t)
		request, err := policyengine.NewApprovalVerificationRequest(
			binding(t), []string{approvalRequirement}, []byte("conformance-evidence"),
		)
		requireNoError(t, err)
		result, err := policyengine.InvokeApprovalVerifier(context.Background(), verifier, request)
		requireNoError(t, err)
		approved := result.SatisfiedRequirementIDs()
		if len(approved) != 1 || approved[0] != approvalRequirement {
			t.Fatalf("approved requirements do not match the canonical request")
		}
	})
	t.Run("observes canceled invocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request, err := policyengine.NewApprovalVerificationRequest(
			binding(t), []string{approvalRequirement}, []byte("conformance-evidence"),
		)
		requireNoError(t, err)
		_, err = policyengine.InvokeApprovalVerifier(ctx, factory(t), request)
		requireCategory(t, err, policyengine.ErrorCanceled)
	})
}

// RunDelegation verifies canonical delegated contextual data and cancellation
// behavior through the public invocation boundary.
func RunDelegation(t *testing.T, factory func(t *testing.T) policyengine.DelegationVerifier) {
	t.Helper()
	t.Run("returns canonical delegated facts", func(t *testing.T) {
		request, err := policyengine.NewDelegationVerificationRequest(binding(t), []byte("conformance-evidence"))
		requireNoError(t, err)
		result, err := policyengine.InvokeDelegationVerifier(context.Background(), factory(t), request)
		requireNoError(t, err)
		if got := len(result.ContextualData().Tuples()); got != 1 {
			t.Fatalf("delegated tuple count = %d, want 1", got)
		}
	})
	t.Run("observes canceled invocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request, err := policyengine.NewDelegationVerificationRequest(binding(t), []byte("conformance-evidence"))
		requireNoError(t, err)
		_, err = policyengine.InvokeDelegationVerifier(ctx, factory(t), request)
		requireCategory(t, err, policyengine.ErrorCanceled)
	})
}

func binding(t testing.TB) policyengine.EvidenceBinding {
	t.Helper()
	caller, err := policyengine.NewCaller("conformance-caller", nil)
	requireNoError(t, err)
	selector, err := policyengine.NewSelector("", strings.Repeat("a", 64))
	requireNoError(t, err)
	result, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller:         caller.Binding(),
		Namespace:      "conformance",
		Selector:       selector,
		RevisionID:     strings.Repeat("a", 64),
		DataGeneration: 1,
		EvaluatedAt:    time.Unix(100, 0).UTC(),
		Fingerprint:    policyengine.NewEvidenceFingerprint([32]byte{1}),
	})
	requireNoError(t, err)
	return result
}

// DelegatedContextualData returns the canonical delegated fact expected by
// RunDelegation and is useful to adapter conformance fixtures.
func DelegatedContextualData(t testing.TB) policyengine.ContextualData {
	t.Helper()
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "conformance-document"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "conformance-user"},
	}, nil)
	requireNoError(t, err)
	result, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, nil)
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
