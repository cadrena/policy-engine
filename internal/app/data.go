package app

import (
	"context"

	policyengine "github.com/cadrena/policy-engine"
	artifactloader "github.com/cadrena/policy-engine/internal/artifact"
	"github.com/cadrena/policy-engine/internal/domain"
	"github.com/cadrena/policy-engine/store"
)

// DataService implements authorized data-head reads and atomic authorization
// data writes.
type DataService struct {
	revisions  store.RevisionStore
	dataReader store.DataReader
	dataWriter store.IdempotencyStore
	authorizer policyengine.CallerAuthorizer
}

// NewDataService constructs an authorization-data application service.
func NewDataService(
	revisions store.RevisionStore,
	dataReader store.DataReader,
	dataWriter store.IdempotencyStore,
	authorizer policyengine.CallerAuthorizer,
) (*DataService, error) {
	if nilDependency(revisions) || nilDependency(dataReader) ||
		nilDependency(dataWriter) || nilDependency(authorizer) {
		return nil, appError(policyengine.ErrorInvalidArgument)
	}
	return &DataService{
		revisions:  revisions,
		dataReader: dataReader,
		dataWriter: dataWriter,
		authorizer: authorizer,
	}, nil
}

// GetDataGeneration returns the authorized authoritative namespace head.
func (s *DataService) GetDataGeneration(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.GetDataGenerationRequest,
) (policyengine.GetDataGenerationResponse, error) {
	validated, err := domain.ValidateGetDataGenerationRequest(request)
	if err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	response, err := s.dataReader.GetDataGeneration(ctx, validated)
	if err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	if !response.Valid() {
		return policyengine.GetDataGenerationResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return response, nil
}

// WriteData validates one request against its exact namespace-local revision,
// then delegates one immutable mutation to the authoritative atomic store.
func (s *DataService) WriteData(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.WriteDataRequest,
) (policyengine.WriteDataResponse, error) {
	validated, err := domain.ValidateWriteDataRequest(request)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(
		ctx,
		s.authorizer,
		caller,
		validated.Namespace(),
		validated.RequiredCapabilities(),
	); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	revisionRequest, err := policyengine.NewGetRevisionRequest(
		validated.Namespace(),
		validated.ValidationRevisionID(),
	)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	record, err := s.revisions.GetRevision(ctx, revisionRequest)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	metadata := record.Metadata()
	if metadata.Namespace() != validated.Namespace() ||
		metadata.ID() != validated.ValidationRevisionID() {
		return policyengine.WriteDataResponse{}, appError(policyengine.ErrorNotFound)
	}
	if !record.Valid() {
		return policyengine.WriteDataResponse{}, appError(policyengine.ErrorIntegrity)
	}
	artifact, err := artifactloader.NewLoader().Decode(record.Artifact())
	if err != nil {
		return policyengine.WriteDataResponse{}, appError(policyengine.ErrorIntegrity)
	}
	schema, err := domain.NewDataSchema(artifact)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if err := schema.ValidateTuplePaths(validated); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if err := schema.ValidateAttributePaths(validated); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	response, err := s.dataWriter.WriteData(ctx, validated)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if response.Generation() == 0 {
		return policyengine.WriteDataResponse{}, appError(policyengine.ErrorIntegrity)
	}
	return response, nil
}

var _ policyengine.DataService = (*DataService)(nil)
