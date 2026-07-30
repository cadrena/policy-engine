package domain

import policyengine "github.com/conductera/policy-engine"

// Slot is one validated namespace-scoped local slot lookup.
type Slot struct {
	request policyengine.ResolveRequest
}

// NewSlot validates a public slot-resolution request at the application boundary.
func NewSlot(request policyengine.ResolveRequest) (Slot, error) {
	validated, err := policyengine.NewResolveRequest(request.Namespace(), request.Slot())
	if err != nil {
		return Slot{}, err
	}
	return Slot{request: validated}, nil
}

// ResolveRequest returns the validated public store request.
func (s Slot) ResolveRequest() policyengine.ResolveRequest { return s.request }

// ValidateActivationHistoryRequest reconstructs a validated bounded slot-history request.
func ValidateActivationHistoryRequest(
	request policyengine.ListActivationHistoryRequest,
) (policyengine.ListActivationHistoryRequest, error) {
	return policyengine.NewListActivationHistoryRequest(
		request.Namespace(),
		request.Slot(),
		request.Cursor(),
		request.Limit(),
	)
}
