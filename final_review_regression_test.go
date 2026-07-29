package policyengine_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	policyengine "github.com/conductera/policy-engine"
)

type blockingAsError struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (e blockingAsError) Error() string { return "hostile extension error" }
func (e blockingAsError) As(any) bool {
	e.started <- struct{}{}
	<-e.release
	return false
}

type blockingUnwrapError struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (e blockingUnwrapError) Error() string { return "hostile extension error" }
func (e blockingUnwrapError) Unwrap() error {
	e.started <- struct{}{}
	<-e.release
	return nil
}

func TestFinalReviewAuthorizerRejectsOversizedAndOverBroadCapabilities(t *testing.T) {
	t.Parallel()

	caller, err := policyengine.NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkGrant, err := policyengine.NewGrant("acme", []policyengine.Capability{
		policyengine.CapabilityAuthorizationCheck,
		policyengine.CapabilityPolicyActivate,
	})
	if err != nil {
		t.Fatal(err)
	}
	overBroad, err := policyengine.NewCallerAuthorization([]policyengine.Grant{checkGrant})
	if err != nil {
		t.Fatal(err)
	}
	if err := policyengine.AuthorizeCaller(context.Background(), authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
		return overBroad, nil
	}), caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck}); !isCategory(err, policyengine.ErrorInternal) {
		t.Fatalf("over-broad authorizer error = %#v, want INTERNAL", err)
	}

	var called atomic.Bool
	required := make([]policyengine.Capability, policyengine.MaxCapabilitiesPerGrant+1)
	for index := range required {
		required[index] = policyengine.CapabilityAuthorizationCheck
	}
	err = policyengine.AuthorizeCaller(context.Background(), authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
		called.Store(true)
		return overBroad, nil
	}), caller, "acme", required)
	if !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("oversized required capabilities error = %#v, want RESOURCE_EXHAUSTED", err)
	}
	if called.Load() {
		t.Fatal("authorizer was invoked for oversized required capabilities")
	}
}

func TestFinalReviewNonCooperativeExtensionsRespectDeadline(t *testing.T) {
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
	approvalRequest, err := policyengine.NewApprovalVerificationRequest(mustEvidenceBinding(t), []string{"admin"}, []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	approvalResult, err := policyengine.NewApprovalVerificationResult([]string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	delegationRequest, err := policyengine.NewDelegationVerificationRequest(mustEvidenceBinding(t), []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	delegationResult, err := policyengine.NewDelegationVerificationResult(mustContextualData(t))
	if err != nil {
		t.Fatal(err)
	}
	event := completedDecisionForSink(t)

	tests := []struct {
		name string
		call func(context.Context) error
	}{
		{"authorizer", func(ctx context.Context) error {
			return policyengine.AuthorizeCaller(ctx, authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
				time.Sleep(150 * time.Millisecond)
				return authorization, nil
			}), caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
		}},
		{"approval", func(ctx context.Context) error {
			_, err := policyengine.InvokeApprovalVerifier(ctx, approvalVerifierFunc(func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
				time.Sleep(150 * time.Millisecond)
				return approvalResult, nil
			}), approvalRequest)
			return err
		}},
		{"delegation", func(ctx context.Context) error {
			_, err := policyengine.InvokeDelegationVerifier(ctx, delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
				time.Sleep(150 * time.Millisecond)
				return delegationResult, nil
			}), delegationRequest)
			return err
		}},
		{"sink", func(ctx context.Context) error {
			delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
				time.Sleep(150 * time.Millisecond)
				value, _ := policyengine.NewDecisionDelivery(policyengine.DecisionDeliveryAccepted, "ACCEPTED")
				return value
			}), event)
			if delivery.Status() != policyengine.DecisionDeliveryFailed || delivery.ReasonCode() != "DEADLINE_EXCEEDED" {
				return fmt.Errorf("delivery = %v/%s", delivery.Status(), delivery.ReasonCode())
			}
			return nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := test.call(ctx)
			elapsed := time.Since(started)
			if test.name != "sink" && !isCategory(err, policyengine.ErrorDeadlineExceeded) {
				t.Fatalf("error = %#v, want DEADLINE_EXCEEDED", err)
			}
			if test.name == "sink" && err != nil {
				t.Fatal(err)
			}
			if elapsed >= 100*time.Millisecond {
				t.Fatalf("extension returned after %s, want before 100ms", elapsed)
			}
		})
	}
	// Allow deliberately non-cooperative workers to finish and release their
	// bounded invocation slots before subsequent package tests run.
	time.Sleep(160 * time.Millisecond)
}

func TestFinalReviewDigestLeafValuesRedactFormattingAndSlog(t *testing.T) {
	t.Parallel()
	caller, err := policyengine.NewCaller("digest-caller-canary", nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := caller.Binding()
	fingerprint := policyengine.NewEvidenceFingerprint([32]byte{1, 2, 3, 4, 5, 6, 7, 8})
	for name, test := range map[string]struct {
		value any
		raw   [32]byte
	}{
		"caller binding": {binding, binding.Bytes()},
		"fingerprint":    {fingerprint, fingerprint.Bytes()},
	} {
		t.Run(name, func(t *testing.T) {
			rawHex := fmt.Sprintf("%x", test.raw)
			rawDecimal := fmt.Sprintf("%v", test.raw)
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p"} {
				output := fmt.Sprintf(format, test.value)
				if strings.Contains(output, rawHex) || strings.Contains(output, rawDecimal) {
					t.Fatalf("format %s leaked digest in %q", format, output)
				}
			}
			if _, ok := test.value.(fmt.Stringer); !ok {
				t.Fatalf("%T does not implement fmt.Stringer", test.value)
			}
			if _, ok := test.value.(fmt.GoStringer); !ok {
				t.Fatalf("%T does not implement fmt.GoStringer", test.value)
			}
			var buffer bytes.Buffer
			slog.New(slog.NewTextHandler(&buffer, nil)).Info("digest", "value", test.value)
			if strings.Contains(buffer.String(), rawHex) || strings.Contains(buffer.String(), rawDecimal) {
				t.Fatalf("slog leaked digest in %q", buffer.String())
			}
		})
	}
}

func TestFinalReviewExtensionErrorsCannotBlockSanitization(t *testing.T) {
	caller, err := policyengine.NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := policyengine.NewApprovalVerificationRequest(mustEvidenceBinding(t), []string{"admin"}, []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	delegationRequest, err := policyengine.NewDelegationVerificationRequest(mustEvidenceBinding(t), []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	ports := []struct {
		name string
		want policyengine.ErrorCategory
		call func(context.Context, error) error
	}{
		{"authorizer", policyengine.ErrorUnavailable, func(ctx context.Context, hostile error) error {
			return policyengine.AuthorizeCaller(ctx, authorizerFunc(func(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
				return policyengine.CallerAuthorization{}, hostile
			}), caller, "acme", []policyengine.Capability{policyengine.CapabilityAuthorizationCheck})
		}},
		{"approval", policyengine.ErrorUnavailable, func(ctx context.Context, hostile error) error {
			_, err := policyengine.InvokeApprovalVerifier(ctx, approvalVerifierFunc(func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
				return policyengine.ApprovalVerificationResult{}, hostile
			}), approvalRequest)
			return err
		}},
		{"delegation", policyengine.ErrorUnavailable, func(ctx context.Context, hostile error) error {
			_, err := policyengine.InvokeDelegationVerifier(ctx, delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
				return policyengine.DelegationVerificationResult{}, hostile
			}), delegationRequest)
			return err
		}},
	}
	for _, port := range ports {
		for _, kind := range []string{"As", "Unwrap"} {
			t.Run(port.name+"/"+kind, func(t *testing.T) {
				started := make(chan struct{}, 1)
				release := make(chan struct{})
				var hostile error = blockingAsError{started: started, release: release}
				if kind == "Unwrap" {
					hostile = blockingUnwrapError{started: started, release: release}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- port.call(ctx, hostile) }()
				select {
				case callErr := <-done:
					close(release)
					if !isCategory(callErr, port.want) {
						t.Fatalf("error = %#v, want %s", callErr, port.want)
					}
				case <-started:
					close(release)
					<-done
					t.Fatal("extension-controlled error method was invoked")
				case <-time.After(80 * time.Millisecond):
					close(release)
					<-done
					t.Fatal("extension error sanitization blocked past deadline")
				}
			})
		}
	}
}
