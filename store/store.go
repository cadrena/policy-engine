// Package store defines adapter-independent local policy storage contracts.
//
// Store adapters are trusted correctness boundaries. They must reject malformed
// values, preserve namespace isolation, observe contexts, and return only
// direct sanitized *policyengine.EngineError values. Adapter wrappers and
// custom As or Unwrap chains are outside this contract.
//
// Dependency direction is intentionally one-way: store may use immutable public
// policyengine values, while the module-root policyengine package must never
// import store. A later composition package (for example localruntime) owns
// application wiring; module-root options must not depend on Store.
package store

import (
	"context"

	policyengine "github.com/conductera/policy-engine"
)

// Store composes the local storage capabilities required by the runtime.
// Additional capabilities are added by their defining files.
type Store interface {
	RevisionStore
	SlotStore
	DataStore
	EventStore
}

// ContextError maps an unusable operation context to a sanitized engine error.
// Adapters should call it before accessing context or allocating request-sized
// state. A nil result means the context is currently usable.
func ContextError(ctx context.Context) error {
	if ctx == nil {
		return newError(policyengine.ErrorInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return newError(policyengine.ErrorDeadlineExceeded)
		}
		return newError(policyengine.ErrorCanceled)
	}
	return nil
}

func newError(category policyengine.ErrorCategory) error {
	engineErr, err := policyengine.NewEngineError(category)
	if err == nil {
		return engineErr
	}
	fallback, fallbackErr := policyengine.NewEngineError(policyengine.ErrorInternal)
	if fallbackErr == nil {
		return fallback
	}
	return err
}
