package app

import (
	"context"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/internal/domain"
)

// Activate performs one authorized namespace-local ABA-safe slot CAS.
func (s *PolicyService) Activate(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ActivateRequest,
) (policyengine.ActivateResponse, error) {
	activation, err := domain.NewActivation(request)
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	validated := activation.Request()
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.ActivateResponse{}, err
	}
	return s.store.Activate(ctx, validated)
}

// Resolve returns one authorized namespace-local slot pin.
func (s *PolicyService) Resolve(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ResolveRequest,
) (policyengine.ResolveResponse, error) {
	slot, err := domain.NewSlot(request)
	if err != nil {
		return policyengine.ResolveResponse{}, err
	}
	validated := slot.ResolveRequest()
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	return s.store.Resolve(ctx, validated)
}

// ListActivationHistory returns retained authorized local slot history.
func (s *PolicyService) ListActivationHistory(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ListActivationHistoryRequest,
) (policyengine.ListActivationHistoryResponse, error) {
	validated, err := domain.ValidateActivationHistoryRequest(request)
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	return s.store.ListActivationHistory(ctx, validated)
}
