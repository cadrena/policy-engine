package app

import (
	"context"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/cache"
)

type resolvedRevision struct {
	namespace      string
	revisionID     string
	slotGeneration uint64
}

func (s *AuthorizationService) resolveRevision(
	ctx context.Context,
	request policyengine.CheckRequest,
) (resolvedRevision, error) {
	if revisionID, exact := request.Selector().ExactRevision(); exact {
		return resolvedRevision{namespace: request.Namespace(), revisionID: revisionID}, nil
	}
	slot, ok := request.Selector().Slot()
	if !ok {
		return resolvedRevision{}, appError(policyengine.ErrorInvalidArgument)
	}
	resolveRequest, err := policyengine.NewResolveRequest(request.Namespace(), slot)
	if err != nil {
		return resolvedRevision{}, err
	}
	response, err := s.dependencies.Slots.Resolve(ctx, resolveRequest)
	if err != nil {
		return resolvedRevision{}, sanitizeRuntimeError(err, policyengine.ErrorUnavailable)
	}
	activation := response.Activation()
	if activation.Namespace() != request.Namespace() || activation.Slot() != slot ||
		activation.RevisionID() == "" || activation.Generation() == 0 {
		return resolvedRevision{}, appError(policyengine.ErrorIntegrity)
	}

	// The authoritative response above is the request pin. The pointer cache is
	// updated only as an optimization and is never re-read here: a concurrent
	// activation must not replace the already selected revision.
	key, keyErr := cache.NewSlotKey(request.Namespace(), slot)
	pointer, pointerErr := cache.NewSlotPointer(activation.RevisionID(), activation.Generation())
	if keyErr == nil && pointerErr == nil {
		_ = s.dependencies.PointerCache.UpdateCommitted(key, pointer)
	}
	return resolvedRevision{
		namespace: request.Namespace(), revisionID: activation.RevisionID(),
		slotGeneration: activation.Generation(),
	}, nil
}
