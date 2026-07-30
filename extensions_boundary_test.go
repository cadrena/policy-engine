package policyengine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

var testTime = time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)

type nilAuthorizer struct{}

func (*nilAuthorizer) Authorize(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	return policyengine.CallerAuthorization{}, nil
}

type nilApprovalVerifier struct{}

func (*nilApprovalVerifier) VerifyApproval(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	return policyengine.ApprovalVerificationResult{}, nil
}

type nilDelegationVerifier struct{}

func (*nilDelegationVerifier) VerifyDelegation(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
	return policyengine.DelegationVerificationResult{}, nil
}

type nilDecisionSink struct{}

func (*nilDecisionSink) RecordDecision(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
	return policyengine.DecisionDelivery{}
}

type authorizerFunc func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error)

func (f authorizerFunc) Authorize(ctx context.Context, caller policyengine.Caller, namespace string, required []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	return f(ctx, caller, namespace, required)
}

type approvalVerifierFunc func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error)

func (f approvalVerifierFunc) VerifyApproval(ctx context.Context, request policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	return f(ctx, request)
}

type delegationVerifierFunc func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error)

func (f delegationVerifierFunc) VerifyDelegation(ctx context.Context, request policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
	return f(ctx, request)
}

type sinkFunc func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery

func (f sinkFunc) RecordDecision(ctx context.Context, event policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
	return f(ctx, event)
}

type panicAsError struct{}

func (panicAsError) Error() string { return "attacker text" }
func (panicAsError) As(any) bool   { panic("malicious As") }

func TestTask5ExtensionOptionsRejectTypedNilPorts(t *testing.T) {
	t.Parallel()

	var authorizer *nilAuthorizer
	var approval *nilApprovalVerifier
	var delegation *nilDelegationVerifier
	var sink *nilDecisionSink
	for name, option := range map[string]policyengine.Option{
		"authorizer": policyengine.WithCallerAuthorizer(authorizer),
		"approval":   policyengine.WithApprovalVerifier(approval),
		"delegation": policyengine.WithDelegationVerifier(delegation),
		"sink":       policyengine.WithDecisionEventSink(sink),
	} {
		if _, err := policyengine.NewOptions(option); !isCategory(err, policyengine.ErrorInvalidArgument) {
			t.Errorf("NewOptions(%s typed nil) error = %#v", name, err)
		}
	}
}

func TestTask5SafeExtensionInvocationFailsClosed(t *testing.T) {
	t.Parallel()

	caller, err := policyengine.NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := policyengine.NewGrant("acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err = policyengine.AuthorizeCaller(ctx, authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
		called = true
		return authorization, nil
	}), caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
	if called || !isCategory(err, policyengine.ErrorCanceled) {
		t.Fatalf("pre-canceled authorizer called=%v error=%#v", called, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	err = policyengine.AuthorizeCaller(ctx, authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
		cancel()
		return authorization, nil
	}), caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
	if !isCategory(err, policyengine.ErrorCanceled) {
		t.Fatalf("canceled-during-call error = %#v", err)
	}

	for name, adapter := range map[string]policyengine.CallerAuthorizer{
		"panic": authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
			panic("secret panic")
		}),
		"malicious-error": authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
			return policyengine.CallerAuthorization{}, panicAsError{}
		}),
	} {
		err := policyengine.AuthorizeCaller(context.Background(), adapter, caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
		if !isCategory(err, policyengine.ErrorInternal) && !isCategory(err, policyengine.ErrorUnavailable) {
			t.Errorf("%s authorizer error = %#v", name, err)
		}
	}

	approvalRequest, err := policyengine.NewApprovalVerificationRequest(mustEvidenceBinding(t), []string{"admin"}, []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.InvokeApprovalVerifier(context.Background(), approvalVerifierFunc(func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
		panic("secret")
	}), approvalRequest); !isCategory(err, policyengine.ErrorInternal) {
		t.Fatalf("panic approval verifier error = %#v", err)
	}
	if _, err := policyengine.InvokeApprovalVerifier(context.Background(), approvalVerifierFunc(func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
		return policyengine.ApprovalVerificationResult{}, nil
	}), approvalRequest); !isCategory(err, policyengine.ErrorInternal) {
		t.Fatalf("malformed approval output error = %#v", err)
	}

	delegationRequest, err := policyengine.NewDelegationVerificationRequest(mustEvidenceBinding(t), []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := policyengine.InvokeDelegationVerifier(ctx, delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		cancel()
		return policyengine.NewDelegationVerificationResult(mustContextualData(t))
	}), delegationRequest); !isCategory(err, policyengine.ErrorCanceled) {
		t.Fatalf("canceled delegation verifier error = %#v", err)
	}

	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision: policyengine.DecisionAllow, ReasonCode: "GRAPH_ALLOWED",
		RevisionID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CompletedAt: testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, sink := range map[string]policyengine.DecisionEventSink{
		"panic": sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			panic("secret")
		}),
		"malformed": sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			return policyengine.DecisionDelivery{}
		}),
	} {
		delivery := policyengine.DeliverDecisionEvent(context.Background(), sink, event)
		if delivery.Status() != policyengine.DecisionDeliveryFailed {
			t.Errorf("%s sink delivery status = %v", name, delivery.Status())
		}
	}
}

func isCategory(err error, want policyengine.ErrorCategory) bool {
	var typed *policyengine.EngineError
	return errors.As(err, &typed) && typed.Category() == want
}
