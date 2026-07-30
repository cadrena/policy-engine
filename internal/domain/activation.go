package domain

import policyengine "github.com/conductera/policy-engine"

// Activation is one validated local ABA-safe slot mutation.
type Activation struct {
	request policyengine.ActivateRequest
}

// NewActivation validates a public activation request at the application boundary.
func NewActivation(request policyengine.ActivateRequest) (Activation, error) {
	validated, err := policyengine.NewActivateRequest(
		request.Namespace(),
		request.Slot(),
		request.TargetRevisionID(),
		request.Expectation(),
	)
	if err != nil {
		return Activation{}, err
	}
	return Activation{request: validated}, nil
}

// Request returns the validated public store request.
func (a Activation) Request() policyengine.ActivateRequest { return a.request }
