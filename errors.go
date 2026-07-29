package policyengine

// ErrorCategory is a stable non-OK engine failure category.
type ErrorCategory string

const (
	// ErrorInvalidArgument reports malformed or structurally invalid input.
	ErrorInvalidArgument ErrorCategory = "INVALID_ARGUMENT"
	// ErrorPermissionDenied reports a fail-closed authorization or evidence rejection.
	ErrorPermissionDenied ErrorCategory = "PERMISSION_DENIED"
	// ErrorNotFound reports authorized absence of requested local state.
	ErrorNotFound ErrorCategory = "NOT_FOUND"
	// ErrorConflict reports stale compare-and-swap or idempotency conflict.
	ErrorConflict ErrorCategory = "CONFLICT"
	// ErrorFailedPrecondition reports an unmet operation precondition.
	ErrorFailedPrecondition ErrorCategory = "FAILED_PRECONDITION"
	// ErrorResourceExhausted reports a bounded work or size limit.
	ErrorResourceExhausted ErrorCategory = "RESOURCE_EXHAUSTED"
	// ErrorCanceled reports request cancellation.
	ErrorCanceled ErrorCategory = "CANCELED"
	// ErrorDeadlineExceeded reports an expired request deadline.
	ErrorDeadlineExceeded ErrorCategory = "DEADLINE_EXCEEDED"
	// ErrorUnavailable reports a temporarily unavailable dependency or extension.
	ErrorUnavailable ErrorCategory = "UNAVAILABLE"
	// ErrorUnsupportedArtifact reports incompatible DSL artifact semantics.
	ErrorUnsupportedArtifact ErrorCategory = "UNSUPPORTED_ARTIFACT"
	// ErrorCursorExpired reports an event cursor outside bounded retention.
	ErrorCursorExpired ErrorCategory = "CURSOR_EXPIRED"
	// ErrorIntegrity reports corrupt or digest-conflicting authoritative state.
	ErrorIntegrity ErrorCategory = "INTEGRITY_ERROR"
	// ErrorInternal reports a sanitized unexpected engine failure.
	ErrorInternal ErrorCategory = "INTERNAL"
)

// String returns the stable uppercase category name, or INVALID for an unknown value.
func (c ErrorCategory) String() string {
	if c.valid() {
		return string(c)
	}
	return "INVALID"
}

func (c ErrorCategory) valid() bool {
	switch c {
	case ErrorInvalidArgument,
		ErrorPermissionDenied,
		ErrorNotFound,
		ErrorConflict,
		ErrorFailedPrecondition,
		ErrorResourceExhausted,
		ErrorCanceled,
		ErrorDeadlineExceeded,
		ErrorUnavailable,
		ErrorUnsupportedArtifact,
		ErrorCursorExpired,
		ErrorIntegrity,
		ErrorInternal:
		return true
	default:
		return false
	}
}

// EngineError is a sanitized typed non-OK result.
//
// EngineError intentionally carries only a stable category. It contains no
// dynamic identifiers, evidence, store values, or partial policy decision.
type EngineError struct {
	category ErrorCategory
}

// NewEngineError validates and constructs a sanitized typed engine error.
func NewEngineError(category ErrorCategory) (*EngineError, error) {
	if !category.valid() {
		return nil, engineError(ErrorInvalidArgument)
	}
	return &EngineError{category: category}, nil
}

// Error returns only the stable sanitized engine error category.
func (e *EngineError) Error() string {
	if e == nil || !e.category.valid() {
		return ErrorInternal.String()
	}
	return e.category.String()
}

// Category returns the stable non-OK engine failure category.
func (e *EngineError) Category() ErrorCategory {
	if e == nil || !e.category.valid() {
		return ErrorInternal
	}
	return e.category
}

func engineError(category ErrorCategory) error {
	return &EngineError{category: category}
}

func invalidArgument(_ string) error {
	return engineError(ErrorInvalidArgument)
}
