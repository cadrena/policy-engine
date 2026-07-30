// Package app implements the transport-neutral local application services.
package app

import (
	"context"
	"reflect"
	"time"

	policyengine "github.com/conductera/policy-engine"
	artifactloader "github.com/conductera/policy-engine/internal/artifact"
	"github.com/conductera/policy-engine/internal/domain"
	"github.com/conductera/policy-engine/store"
)

// Clock supplies local immutable revision publication timestamps.
type Clock interface {
	Now() time.Time
}

// PolicyService implements local immutable policy publication and slot lifecycle.
type PolicyService struct {
	store      store.Store
	authorizer policyengine.CallerAuthorizer
	clock      Clock
	loader     artifactloader.Loader
}

// NewPolicyService constructs a local policy lifecycle service.
func NewPolicyService(
	storage store.Store,
	authorizer policyengine.CallerAuthorizer,
	clock Clock,
) (*PolicyService, error) {
	if nilDependency(storage) || nilDependency(authorizer) || nilDependency(clock) {
		return nil, appError(policyengine.ErrorInvalidArgument)
	}
	return &PolicyService{
		store:      storage,
		authorizer: authorizer,
		clock:      clock,
		loader:     artifactloader.NewLoader(),
	}, nil
}

// Publish validates and compiles local source without changing any active slot.
func (s *PolicyService) Publish(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.PublishRequest,
) (policyengine.PublishResponse, error) {
	validated, err := policyengine.NewPublishRequest(
		request.Namespace(),
		request.SourceName(),
		request.Source(),
	)
	if err != nil {
		return policyengine.PublishResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.PublishResponse{}, err
	}
	compiled, err := s.loader.Compile(validated.SourceName(), validated.Source())
	if err != nil {
		return policyengine.PublishResponse{}, err
	}
	publishedAt, err := s.publicationTime()
	if err != nil {
		return policyengine.PublishResponse{}, err
	}
	revision, err := domain.NewRevision(validated, compiled, publishedAt)
	if err != nil {
		return policyengine.PublishResponse{}, err
	}
	result, err := s.store.PutRevision(ctx, revision.Write())
	if err != nil {
		return policyengine.PublishResponse{}, err
	}
	if !result.Valid() || !revision.Matches(result.Record(), result.Created()) {
		return policyengine.PublishResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return policyengine.NewPublishResponse(result.Record().Metadata(), result.Created())
}

// GetRevision returns authorized metadata for one exact namespace-local revision.
func (s *PolicyService) GetRevision(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.GetRevisionRequest,
) (policyengine.GetRevisionResponse, error) {
	validated, err := policyengine.NewGetRevisionRequest(
		request.Namespace(),
		request.RevisionID(),
	)
	if err != nil {
		return policyengine.GetRevisionResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.GetRevisionResponse{}, err
	}
	record, err := s.store.GetRevision(ctx, validated)
	if err != nil {
		return policyengine.GetRevisionResponse{}, err
	}
	metadata := record.Metadata()
	if !record.Valid() ||
		metadata.Namespace() != validated.Namespace() ||
		metadata.ID() != validated.RevisionID() {
		return policyengine.GetRevisionResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return policyengine.NewGetRevisionResponse(metadata)
}

// ListRevisions returns an authorized bounded page of namespace-local metadata.
func (s *PolicyService) ListRevisions(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ListRevisionsRequest,
) (policyengine.ListRevisionsResponse, error) {
	validated, err := policyengine.NewListRevisionsRequest(
		request.Namespace(),
		request.Cursor(),
		request.Limit(),
	)
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	response, err := s.store.ListRevisions(ctx, validated)
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	bound, err := policyengine.NewListRevisionsResponse(
		validated,
		response.Revisions(),
		response.NextCursor(),
	)
	if err != nil {
		return policyengine.ListRevisionsResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return bound, nil
}

func appError(category policyengine.ErrorCategory) error {
	err, constructorErr := policyengine.NewEngineError(category)
	if constructorErr == nil {
		return err
	}
	fallback, fallbackErr := policyengine.NewEngineError(policyengine.ErrorInternal)
	if fallbackErr == nil {
		return fallback
	}
	return constructorErr
}

var _ policyengine.PolicyService = (*PolicyService)(nil)

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (s *PolicyService) publicationTime() (value time.Time, err error) {
	defer func() {
		if recover() != nil {
			value = time.Time{}
			err = appError(policyengine.ErrorInternal)
		}
	}()
	value = s.clock.Now()
	if value.IsZero() {
		return time.Time{}, appError(policyengine.ErrorInternal)
	}
	return value, nil
}
