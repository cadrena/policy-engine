package embedded

import (
	"context"
	"errors"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestNewRejectsMissingRequiredDependencies(t *testing.T) {
	storage, err := memory.New()
	requireNoError(t, err)

	for name, options := range map[string][]Option{
		"store":      {WithCallerAuthorizer(testAuthorizer{})},
		"authorizer": {WithStore(storage)},
	} {
		t.Run(name, func(t *testing.T) {
			engine, err := New(options...)
			if engine != nil {
				t.Fatal("New returned an engine with a missing dependency")
			}
			requireCategory(t, err, policyengine.ErrorInvalidArgument)
		})
	}
}

func TestNewRejectsTypedNilPorts(t *testing.T) {
	storage, err := memory.New()
	requireNoError(t, err)
	var nilStore *memory.Store
	var nilAuthorizer *testAuthorizer
	var nilApproval *testApprovalVerifier
	var nilDelegation *testDelegationVerifier
	var nilSink *testDecisionSink

	for name, option := range map[string]Option{
		"store":               WithStore(nilStore),
		"caller authorizer":   WithCallerAuthorizer(nilAuthorizer),
		"approval verifier":   WithApprovalVerifier(nilApproval),
		"delegation verifier": WithDelegationVerifier(nilDelegation),
		"decision sink":       WithDecisionEventSink(nilSink),
	} {
		t.Run(name, func(t *testing.T) {
			options := []Option{WithStore(storage), WithCallerAuthorizer(testAuthorizer{}), option}
			if name == "store" {
				options = []Option{WithCallerAuthorizer(testAuthorizer{}), option}
			}
			_, err := New(options...)
			requireCategory(t, err, policyengine.ErrorInvalidArgument)
		})
	}
}

func TestNewContainsInvalidPanickingAndMalformedOptions(t *testing.T) {
	storage, err := memory.New()
	requireNoError(t, err)
	base := []Option{WithStore(storage), WithCallerAuthorizer(testAuthorizer{})}

	tests := map[string]struct {
		option Option
		want   policyengine.ErrorCategory
	}{
		"zero": {option: Option{}, want: policyengine.ErrorInvalidArgument},
		"panic": {option: Option{apply: func(*configuration) error {
			panic("secret-option-panic")
		}}, want: policyengine.ErrorInternal},
		"hostile error": {option: Option{apply: func(*configuration) error {
			return hostileOptionError{}
		}}, want: policyengine.ErrorInternal},
		"malformed result": {option: Option{apply: func(configuration *configuration) error {
			configuration.approvalVerifier = nil
			return nil
		}}, want: policyengine.ErrorInvalidArgument},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(append(base, test.option)...)
			requireCategory(t, err, test.want)
			if errors.Is(err, hostileOptionError{}) {
				t.Fatal("hostile option error escaped the construction boundary")
			}
		})
	}
}

type testAuthorizer struct{}

func (testAuthorizer) Authorize(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	return policyengine.CallerAuthorization{}, nil
}

type testApprovalVerifier struct{}

func (*testApprovalVerifier) VerifyApproval(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	return policyengine.ApprovalVerificationResult{}, nil
}

type testDelegationVerifier struct{}

func (*testDelegationVerifier) VerifyDelegation(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
	return policyengine.DelegationVerificationResult{}, nil
}

type testDecisionSink struct{}

func (*testDecisionSink) RecordDecision(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
	return policyengine.DecisionDelivery{}
}

type hostileOptionError struct{}

func (hostileOptionError) Error() string { panic("hostile option error formatted") }

var _ store.Store = (*memory.Store)(nil)

func requireCategory(t testing.TB, err error, want policyengine.ErrorCategory) {
	t.Helper()
	typed, ok := err.(*policyengine.EngineError)
	if !ok || typed == nil || typed.Category() != want {
		t.Fatalf("error category mismatch")
	}
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
