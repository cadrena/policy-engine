package verifiers_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/conformance/verifiers"
)

func TestApprovalSuite(t *testing.T) {
	var cancellationCalls atomic.Int32
	verifiers.RunApproval(t, func(*testing.T) policyengine.ApprovalVerifier {
		return newApprovalVerifier(&cancellationCalls)
	})
	if cancellationCalls.Load() == 0 {
		t.Fatal("approval suite never entered a verifier before cancellation")
	}
}

func TestDelegationSuite(t *testing.T) {
	var cancellationCalls atomic.Int32
	verifiers.RunDelegation(t, func(*testing.T) policyengine.DelegationVerifier {
		return newDelegationVerifier(t, &cancellationCalls)
	})
	if cancellationCalls.Load() == 0 {
		t.Fatal("delegation suite never entered a verifier before cancellation")
	}
}

type approvalVerifier struct {
	entered chan struct{}
	once    sync.Once
	calls   *atomic.Int32
}

func newApprovalVerifier(calls *atomic.Int32) *approvalVerifier {
	return &approvalVerifier{entered: make(chan struct{}), calls: calls}
}

func (v *approvalVerifier) InvocationEntered() <-chan struct{} { return v.entered }

func (v *approvalVerifier) VerifyApproval(
	ctx context.Context,
	request policyengine.ApprovalVerificationRequest,
) (policyengine.ApprovalVerificationResult, error) {
	if string(request.Evidence()) == "conformance-cancellation" {
		v.once.Do(func() { close(v.entered) })
		v.calls.Add(1)
		<-ctx.Done()
		return policyengine.ApprovalVerificationResult{}, ctx.Err()
	}
	return policyengine.NewApprovalVerificationResult(request.RequirementIDs())
}

type delegationVerifier struct {
	t       testing.TB
	entered chan struct{}
	once    sync.Once
	calls   *atomic.Int32
}

func newDelegationVerifier(t testing.TB, calls *atomic.Int32) *delegationVerifier {
	return &delegationVerifier{t: t, entered: make(chan struct{}), calls: calls}
}

func (v *delegationVerifier) InvocationEntered() <-chan struct{} { return v.entered }

func (v *delegationVerifier) VerifyDelegation(
	ctx context.Context,
	request policyengine.DelegationVerificationRequest,
) (policyengine.DelegationVerificationResult, error) {
	if string(request.Evidence()) == "conformance-cancellation" {
		v.once.Do(func() { close(v.entered) })
		v.calls.Add(1)
		<-ctx.Done()
		return policyengine.DelegationVerificationResult{}, ctx.Err()
	}
	return policyengine.NewDelegationVerificationResult(verifiers.DelegatedContextualData(v.t))
}
