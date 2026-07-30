package app

import (
	"context"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/domain"
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
	response, err := s.store.Activate(ctx, validated)
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	storedActivation := response.Activation()
	if storedActivation.Namespace() != validated.Namespace() ||
		storedActivation.Slot() != validated.Slot() ||
		storedActivation.RevisionID() != validated.TargetRevisionID() {
		return policyengine.ActivateResponse{}, appError(policyengine.ErrorIntegrity)
	}
	bound, err := policyengine.NewActivateResponse(storedActivation)
	if err != nil {
		return policyengine.ActivateResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return bound, nil
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
	response, err := s.store.Resolve(ctx, validated)
	if err != nil {
		return policyengine.ResolveResponse{}, err
	}
	activation := response.Activation()
	if activation.Namespace() != validated.Namespace() ||
		activation.Slot() != validated.Slot() {
		return policyengine.ResolveResponse{}, appError(policyengine.ErrorIntegrity)
	}
	bound, err := policyengine.NewResolveResponse(activation)
	if err != nil {
		return policyengine.ResolveResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return bound, nil
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
	response, err := s.store.ListActivationHistory(ctx, validated)
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	bound, err := policyengine.NewListActivationHistoryResponse(
		validated,
		response.Activations(),
		response.NextCursor(),
	)
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return bound, nil
}
