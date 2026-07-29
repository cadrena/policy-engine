package policyengine

import "context"

const (
	maxConcurrentExtensionCalls        = 64
	maxConcurrentExtensionCallsPerPort = maxConcurrentExtensionCalls / 4
)

var (
	authorizerCallSlots = make(chan struct{}, maxConcurrentExtensionCallsPerPort)
	approvalCallSlots   = make(chan struct{}, maxConcurrentExtensionCallsPerPort)
	delegationCallSlots = make(chan struct{}, maxConcurrentExtensionCallsPerPort)
	sinkCallSlots       = make(chan struct{}, maxConcurrentExtensionCallsPerPort)
)

type extensionCallResult[T any] struct {
	value T
	err   error
}

func invokeExtension[T any](ctx context.Context, slots chan struct{}, call func() (T, error)) (zero T, err error) {
	if err := contextEngineError(ctx); err != nil {
		return zero, err
	}
	select {
	case slots <- struct{}{}:
	default:
		return zero, engineError(ErrorResourceExhausted)
	}
	completed := make(chan extensionCallResult[T], 1)
	go func() {
		result := extensionCallResult[T]{}
		defer func() {
			if recover() != nil {
				result = extensionCallResult[T]{err: engineError(ErrorInternal)}
			}
			<-slots
			completed <- result
		}()
		result.value, result.err = call()
	}()
	select {
	case <-ctx.Done():
		return zero, contextEngineError(ctx)
	case result := <-completed:
		return result.value, result.err
	}
}

func contextEngineError(ctx context.Context) error {
	if ctx == nil {
		return engineError(ErrorInvalidArgument)
	}
	switch ctx.Err() {
	case nil:
		return nil
	case context.Canceled:
		return engineError(ErrorCanceled)
	case context.DeadlineExceeded:
		return engineError(ErrorDeadlineExceeded)
	default:
		return engineError(ErrorInternal)
	}
}

func sanitizedExtensionError(err error, fallback ErrorCategory) error {
	if err == nil {
		return nil
	}
	if typed, ok := err.(*EngineError); ok && typed != nil {
		category := typed.Category()
		if category.valid() {
			return engineError(category)
		}
	}
	return engineError(fallback)
}

func callAuthorizer(ctx context.Context, authorizer CallerAuthorizer, caller Caller, namespace string, required []Capability) (CallerAuthorization, error) {
	required = cloneSlice(required)
	return invokeExtension(ctx, authorizerCallSlots, func() (CallerAuthorization, error) {
		return authorizer.Authorize(ctx, caller, namespace, required)
	})
}

// InvokeApprovalVerifier is the mandatory fail-closed approval extension boundary.
func InvokeApprovalVerifier(ctx context.Context, verifier ApprovalVerifier, request ApprovalVerificationRequest) (result ApprovalVerificationResult, err error) {
	if err := contextEngineError(ctx); err != nil {
		return ApprovalVerificationResult{}, err
	}
	if isNilInterface(verifier) || !request.valid() {
		return ApprovalVerificationResult{}, engineError(ErrorInvalidArgument)
	}
	result, callErr := invokeExtension(ctx, approvalCallSlots, func() (ApprovalVerificationResult, error) {
		return verifier.VerifyApproval(ctx, request)
	})
	if err := contextEngineError(ctx); err != nil {
		return ApprovalVerificationResult{}, err
	}
	if callErr != nil {
		return ApprovalVerificationResult{}, sanitizedExtensionError(callErr, ErrorUnavailable)
	}
	if !result.valid() {
		return ApprovalVerificationResult{}, engineError(ErrorInternal)
	}
	requested := request.requirementIDs
	requestedIndex := 0
	for _, satisfied := range result.satisfiedRequirementIDs {
		for requestedIndex < len(requested) && requested[requestedIndex] < satisfied {
			requestedIndex++
		}
		if requestedIndex == len(requested) || requested[requestedIndex] != satisfied {
			return ApprovalVerificationResult{}, engineError(ErrorInternal)
		}
	}
	return result, nil
}

// InvokeDelegationVerifier is the mandatory fail-closed delegation boundary.
func InvokeDelegationVerifier(ctx context.Context, verifier DelegationVerifier, request DelegationVerificationRequest) (result DelegationVerificationResult, err error) {
	if err := contextEngineError(ctx); err != nil {
		return DelegationVerificationResult{}, err
	}
	if isNilInterface(verifier) || !request.valid() {
		return DelegationVerificationResult{}, engineError(ErrorInvalidArgument)
	}
	result, callErr := invokeExtension(ctx, delegationCallSlots, func() (DelegationVerificationResult, error) {
		return verifier.VerifyDelegation(ctx, request)
	})
	if err := contextEngineError(ctx); err != nil {
		return DelegationVerificationResult{}, err
	}
	if callErr != nil {
		return DelegationVerificationResult{}, sanitizedExtensionError(callErr, ErrorUnavailable)
	}
	if !result.valid() {
		return DelegationVerificationResult{}, engineError(ErrorInternal)
	}
	return result, nil
}

// DeliverDecisionEvent contains sink panics and malformed output. Delivery is
// best effort and this helper never changes or returns the completed decision.
func DeliverDecisionEvent(ctx context.Context, sink DecisionEventSink, event CompletedDecisionEvent) (delivery DecisionDelivery) {
	failed := func(reason string) DecisionDelivery {
		value, _ := NewDecisionDelivery(DecisionDeliveryFailed, reason)
		return value
	}
	if err := contextEngineError(ctx); err != nil {
		if isEngineCategory(err, ErrorDeadlineExceeded) {
			return failed("DEADLINE_EXCEEDED")
		}
		return failed("CANCELED")
	}
	if isNilInterface(sink) || !event.valid() {
		return failed("INVALID_SINK_INPUT")
	}
	delivery, callErr := invokeExtension(ctx, sinkCallSlots, func() (DecisionDelivery, error) {
		return sink.RecordDecision(ctx, event), nil
	})
	if err := contextEngineError(ctx); err != nil {
		if isEngineCategory(err, ErrorDeadlineExceeded) {
			return failed("DEADLINE_EXCEEDED")
		}
		return failed("CANCELED")
	}
	if callErr != nil {
		if isEngineCategory(callErr, ErrorDeadlineExceeded) {
			return failed("DEADLINE_EXCEEDED")
		}
		if isEngineCategory(callErr, ErrorCanceled) {
			return failed("CANCELED")
		}
		if isEngineCategory(callErr, ErrorResourceExhausted) {
			return failed("RESOURCE_EXHAUSTED")
		}
		return failed("SINK_PANIC")
	}
	if !delivery.valid() {
		return failed("INVALID_SINK_OUTPUT")
	}
	return delivery
}

func isEngineCategory(err error, category ErrorCategory) bool {
	typed, ok := err.(*EngineError)
	return ok && typed != nil && typed.Category() == category
}
