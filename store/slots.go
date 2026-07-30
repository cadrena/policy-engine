package store

import (
	"context"

	policyengine "github.com/cadrena/policy-engine"
)

// SlotStore provides optional local ABA-safe slot selection. Implementations
// must verify the target revision in the same namespace, advance a monotonic
// per-slot generation only on successful CAS, and append bounded history and a
// state event in the same atomic commit.
type SlotStore interface {
	Activate(context.Context, policyengine.ActivateRequest) (policyengine.ActivateResponse, error)
	Resolve(context.Context, policyengine.ResolveRequest) (policyengine.ResolveResponse, error)
	ListActivationHistory(context.Context, policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error)
}
