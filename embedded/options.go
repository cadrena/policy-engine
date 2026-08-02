package embedded

import (
	"reflect"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// Option is a sealed embedded-engine configuration value. Its zero value is
// invalid; meaningful options are produced by this package's With* functions.
type Option struct {
	apply func(*configuration) error
}

type configuration struct {
	store              store.Store
	callerAuthorizer   policyengine.CallerAuthorizer
	approvalVerifier   policyengine.ApprovalVerifier
	delegationVerifier policyengine.DelegationVerifier
	decisionEventSink  policyengine.DecisionEventSink
}

func defaultConfiguration() configuration {
	return configuration{
		approvalVerifier:   policyengine.DefaultApprovalVerifier(),
		delegationVerifier: policyengine.DefaultDelegationVerifier(),
		decisionEventSink:  policyengine.DefaultDecisionEventSink(),
	}
}

// WithStore configures the authoritative local policy, data, and event store.
func WithStore(storage store.Store) Option {
	return Option{apply: func(configuration *configuration) error {
		configuration.store = storage
		return nil
	}}
}

// WithCallerAuthorizer configures the mandatory trusted caller authorizer.
func WithCallerAuthorizer(authorizer policyengine.CallerAuthorizer) Option {
	return Option{apply: func(configuration *configuration) error {
		configuration.callerAuthorizer = authorizer
		return nil
	}}
}

// WithApprovalVerifier configures approval evidence verification.
func WithApprovalVerifier(verifier policyengine.ApprovalVerifier) Option {
	return Option{apply: func(configuration *configuration) error {
		configuration.approvalVerifier = verifier
		return nil
	}}
}

// WithDelegationVerifier configures delegation evidence verification.
func WithDelegationVerifier(verifier policyengine.DelegationVerifier) Option {
	return Option{apply: func(configuration *configuration) error {
		configuration.delegationVerifier = verifier
		return nil
	}}
}

// WithDecisionEventSink configures best-effort decision metadata delivery.
func WithDecisionEventSink(sink policyengine.DecisionEventSink) Option {
	return Option{apply: func(configuration *configuration) error {
		configuration.decisionEventSink = sink
		return nil
	}}
}

func applyOption(option Option, configured *configuration) (err error) {
	defer func() {
		if recover() != nil {
			err = newError(policyengine.ErrorInternal)
		}
	}()
	if option.apply == nil {
		return newError(policyengine.ErrorInvalidArgument)
	}
	if err := option.apply(configured); err != nil {
		if typed, ok := err.(*policyengine.EngineError); ok && typed != nil {
			return newError(typed.Category())
		}
		return newError(policyengine.ErrorInternal)
	}
	return nil
}

func validateConfiguration(configured configuration) error {
	if nilInterface(configured.store) || nilInterface(configured.callerAuthorizer) {
		return newError(policyengine.ErrorInvalidArgument)
	}
	if nilInterface(configured.approvalVerifier) || nilInterface(configured.delegationVerifier) ||
		nilInterface(configured.decisionEventSink) {
		return newError(policyengine.ErrorInvalidArgument)
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func newError(category policyengine.ErrorCategory) error {
	result, err := policyengine.NewEngineError(category)
	if err == nil {
		return result
	}
	fallback, _ := policyengine.NewEngineError(policyengine.ErrorInternal)
	return fallback
}
