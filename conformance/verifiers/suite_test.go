package verifiers_test

import (
	"context"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/conformance/verifiers"
)

func TestApprovalSuite(t *testing.T) {
	verifiers.RunApproval(t, func(*testing.T) policyengine.ApprovalVerifier {
		return approvalVerifier{}
	})
}

func TestDelegationSuite(t *testing.T) {
	verifiers.RunDelegation(t, func(*testing.T) policyengine.DelegationVerifier {
		return delegationVerifier{t: t}
	})
}

type approvalVerifier struct{}

func (approvalVerifier) VerifyApproval(
	_ context.Context,
	request policyengine.ApprovalVerificationRequest,
) (policyengine.ApprovalVerificationResult, error) {
	return policyengine.NewApprovalVerificationResult(request.RequirementIDs())
}

type delegationVerifier struct{ t testing.TB }

func (v delegationVerifier) VerifyDelegation(
	context.Context,
	policyengine.DelegationVerificationRequest,
) (policyengine.DelegationVerificationResult, error) {
	return policyengine.NewDelegationVerificationResult(verifiers.DelegatedContextualData(v.t))
}
