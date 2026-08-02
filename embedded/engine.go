// Package embedded composes the public transport-neutral policy engine over
// caller-supplied local stores and extension ports.
package embedded

import (
	"context"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	"github.com/cadrena/policy-engine/internal/cache"
	"github.com/cadrena/policy-engine/store"
)

const (
	defaultRevisionCacheEntries = 128
	defaultRevisionCacheBytes   = 32 << 20
	defaultPointerCacheEntries  = 1024
)

type engine struct {
	*app.PolicyService
	*app.AuthorizationService
	*app.DataService
	store      store.Store
	authorizer policyengine.CallerAuthorizer
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// New validates sealed options and composes one embedded policy engine.
func New(options ...Option) (policyengine.Engine, error) {
	configured := defaultConfiguration()
	for _, option := range options {
		if err := applyOption(option, &configured); err != nil {
			return nil, err
		}
	}
	if err := validateConfiguration(configured); err != nil {
		return nil, err
	}

	policyService, err := app.NewPolicyService(configured.store, configured.callerAuthorizer, systemClock{})
	if err != nil {
		return nil, newError(policyengine.ErrorInternal)
	}
	dataService, err := app.NewDataService(
		configured.store, configured.store, configured.store, configured.callerAuthorizer,
	)
	if err != nil {
		return nil, newError(policyengine.ErrorInternal)
	}
	revisionCache, err := cache.NewRevisionCache(cache.RevisionLimits{
		MaxEntries: defaultRevisionCacheEntries,
		MaxBytes:   defaultRevisionCacheBytes,
	})
	if err != nil {
		return nil, newError(policyengine.ErrorInternal)
	}
	pointerCache, err := cache.NewPointerCache(defaultPointerCacheEntries)
	if err != nil {
		return nil, newError(policyengine.ErrorInternal)
	}
	authorizationService, err := app.NewAuthorizationService(app.AuthorizationDependencies{
		Revisions:          configured.store,
		Slots:              configured.store,
		Data:               configured.store,
		RevisionCache:      revisionCache,
		PointerCache:       pointerCache,
		CallerAuthorizer:   configured.callerAuthorizer,
		ApprovalVerifier:   configured.approvalVerifier,
		DelegationVerifier: configured.delegationVerifier,
		DecisionSink:       configured.decisionEventSink,
		Clock:              func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, newError(policyengine.ErrorInternal)
	}
	return &engine{
		PolicyService:        policyService,
		AuthorizationService: authorizationService,
		DataService:          dataService,
		store:                configured.store,
		authorizer:           configured.callerAuthorizer,
	}, nil
}

func (e *engine) ListEvents(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ListEventsRequest,
) (policyengine.ListEventsResponse, error) {
	validated, err := policyengine.NewListEventsRequest(request.Namespace(), request.AfterCursor(), request.Limit())
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx, e.authorizer, caller, validated.Namespace(), validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	response, err := e.store.ListEvents(ctx, validated)
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	canonical, err := policyengine.NewListEventsResponse(validated, response.Events(), response.NextCursor())
	if err != nil {
		return policyengine.ListEventsResponse{}, newError(policyengine.ErrorIntegrity)
	}
	return canonical, nil
}

func (e *engine) Status(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.StatusRequest,
) (policyengine.StatusResponse, error) {
	validated, err := policyengine.NewStatusRequest(request.AuthorizationNamespace())
	if err != nil {
		return policyengine.StatusResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx, e.authorizer, caller, validated.AuthorizationNamespace(), validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.StatusResponse{}, err
	}
	components := make([]policyengine.ComponentStatus, 0, 2)
	for _, name := range []string{"evaluator", "store"} {
		component, componentErr := policyengine.NewComponentStatus(name, policyengine.ComponentReady, "READY")
		if componentErr != nil {
			return policyengine.StatusResponse{}, newError(policyengine.ErrorInternal)
		}
		components = append(components, component)
	}
	response, err := policyengine.NewStatusResponse(true, components)
	if err != nil {
		return policyengine.StatusResponse{}, newError(policyengine.ErrorInternal)
	}
	return response, nil
}

var _ policyengine.Engine = (*engine)(nil)
