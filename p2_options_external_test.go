package policyengine_test

import (
	"context"
	"reflect"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

type optionAuthorizer struct{}

func (optionAuthorizer) Authorize(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	return policyengine.CallerAuthorization{}, nil
}

type optionApprovalVerifier struct{}

func (optionApprovalVerifier) VerifyApproval(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
	return policyengine.ApprovalVerificationResult{}, nil
}

type optionDelegationVerifier struct{}

func (optionDelegationVerifier) VerifyDelegation(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
	return policyengine.DelegationVerificationResult{}, nil
}

type optionDecisionSink struct{}

func (optionDecisionSink) RecordDecision(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
	return policyengine.DecisionDelivery{}
}

func TestSealedBuiltInOptionsConfigureExtensionPorts(t *testing.T) {
	t.Parallel()

	authorizer := optionAuthorizer{}
	approval := optionApprovalVerifier{}
	delegation := optionDelegationVerifier{}
	sink := optionDecisionSink{}
	options, err := policyengine.NewOptions(
		policyengine.WithCallerAuthorizer(authorizer),
		policyengine.WithApprovalVerifier(approval),
		policyengine.WithDelegationVerifier(delegation),
		policyengine.WithDecisionEventSink(sink),
	)
	if err != nil {
		t.Fatalf("NewOptions(built-ins) error = %v", err)
	}
	if reflect.TypeOf(options.CallerAuthorizer()) != reflect.TypeOf(authorizer) ||
		reflect.TypeOf(options.ApprovalVerifier()) != reflect.TypeOf(approval) ||
		reflect.TypeOf(options.DelegationVerifier()) != reflect.TypeOf(delegation) ||
		reflect.TypeOf(options.DecisionEventSink()) != reflect.TypeOf(sink) {
		t.Fatal("built-in options did not retain configured extension ports")
	}
}

func TestSealedOptionRejectsZeroAndHasNoExternalCallbackShape(t *testing.T) {
	t.Parallel()

	var zero policyengine.Option
	if _, err := policyengine.NewOptions(zero); !isCategory(err, policyengine.ErrorInvalidArgument) {
		t.Fatalf("NewOptions(zero Option) error = %#v, want INVALID_ARGUMENT", err)
	}

	optionType := reflect.TypeOf(zero)
	if optionType.Kind() != reflect.Struct {
		t.Fatalf("Option kind = %s, want sealed struct value", optionType.Kind())
	}
	for index := 0; index < optionType.NumField(); index++ {
		if optionType.Field(index).IsExported() {
			t.Fatalf("Option exports construction field %q", optionType.Field(index).Name)
		}
	}
	callbackType := reflect.TypeOf((func(*policyengine.Options) error)(nil))
	if callbackType.AssignableTo(optionType) || callbackType.ConvertibleTo(optionType) {
		t.Fatal("external callback remains assignable or convertible to Option")
	}
}
