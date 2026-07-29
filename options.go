package policyengine

import "reflect"

// Option is a sealed configuration value. Its zero value is invalid; meaningful
// options are available only through the package's With* constructors.
type Option struct {
	apply func(*Options) error
}

// Options composes public extension ports and their fail-closed defaults.
// Authoritative store composition is deliberately deferred to the store API.
type Options struct {
	callerAuthorizer   CallerAuthorizer
	approvalVerifier   ApprovalVerifier
	delegationVerifier DelegationVerifier
	decisionEventSink  DecisionEventSink
}

// NewOptions applies sealed extension options over the public safe defaults.
// Zero or invalid options and nil or typed-nil ports are rejected.
func NewOptions(options ...Option) (Options, error) {
	configured := Options{
		callerAuthorizer:   DefaultCallerAuthorizer(),
		approvalVerifier:   DefaultApprovalVerifier(),
		delegationVerifier: DefaultDelegationVerifier(),
		decisionEventSink:  DefaultDecisionEventSink(),
	}
	for _, option := range options {
		if option.apply == nil {
			return Options{}, invalidArgument("extension option is invalid")
		}
		if err := applyOption(option, &configured); err != nil {
			return Options{}, err
		}
	}
	return configured, nil
}

func applyOption(option Option, configured *Options) (err error) {
	defer func() {
		if recover() != nil {
			err = engineError(ErrorInternal)
		}
	}()
	if err := option.apply(configured); err != nil {
		return sanitizedExtensionError(err, ErrorInternal)
	}
	return nil
}

// WithCallerAuthorizer explicitly configures caller authorization.
func WithCallerAuthorizer(authorizer CallerAuthorizer) Option {
	return Option{apply: func(options *Options) error {
		if isNilInterface(authorizer) {
			return invalidArgument("caller authorizer is nil")
		}
		options.callerAuthorizer = authorizer
		return nil
	}}
}

// WithApprovalVerifier explicitly configures approval evidence verification.
func WithApprovalVerifier(verifier ApprovalVerifier) Option {
	return Option{apply: func(options *Options) error {
		if isNilInterface(verifier) {
			return invalidArgument("approval verifier is nil")
		}
		options.approvalVerifier = verifier
		return nil
	}}
}

// WithDelegationVerifier explicitly configures delegation evidence verification.
func WithDelegationVerifier(verifier DelegationVerifier) Option {
	return Option{apply: func(options *Options) error {
		if isNilInterface(verifier) {
			return invalidArgument("delegation verifier is nil")
		}
		options.delegationVerifier = verifier
		return nil
	}}
}

// WithDecisionEventSink explicitly configures best-effort decision metadata delivery.
func WithDecisionEventSink(sink DecisionEventSink) Option {
	return Option{apply: func(options *Options) error {
		if isNilInterface(sink) {
			return invalidArgument("decision event sink is nil")
		}
		options.decisionEventSink = sink
		return nil
	}}
}

// CallerAuthorizer returns the configured authorizer or the reject-all default.
func (o Options) CallerAuthorizer() CallerAuthorizer {
	if isNilInterface(o.callerAuthorizer) {
		return DefaultCallerAuthorizer()
	}
	return o.callerAuthorizer
}

// ApprovalVerifier returns the configured verifier or the reject-evidence default.
func (o Options) ApprovalVerifier() ApprovalVerifier {
	if isNilInterface(o.approvalVerifier) {
		return DefaultApprovalVerifier()
	}
	return o.approvalVerifier
}

// DelegationVerifier returns the configured verifier or the reject-evidence default.
func (o Options) DelegationVerifier() DelegationVerifier {
	if isNilInterface(o.delegationVerifier) {
		return DefaultDelegationVerifier()
	}
	return o.delegationVerifier
}

// DecisionEventSink returns the configured sink or the best-effort no-op default.
func (o Options) DecisionEventSink() DecisionEventSink {
	if isNilInterface(o.decisionEventSink) {
		return DefaultDecisionEventSink()
	}
	return o.decisionEventSink
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}
