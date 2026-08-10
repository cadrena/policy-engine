package sqlite

import (
	"context"
	"database/sql"
	"errors"

	policyengine "github.com/cadrena/policy-engine"
)

// GetDataGeneration returns the exact currently committed namespace data head.
func (s *Store) GetDataGeneration(ctx context.Context, request policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	if _, err := policyengine.NewGetDataGenerationRequest(request.Namespace()); err != nil {
		return policyengine.GetDataGenerationResponse{}, mapError(ctx, err)
	}
	if s == nil || s.db == nil {
		return policyengine.GetDataGenerationResponse{}, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	var generation uint64
	err := s.read(ctx, func(database *sql.DB) error {
		head, err := readNamespaceHead(ctx, database, request.Namespace())
		if errors.Is(err, sql.ErrNoRows) {
			generation = 0
			return nil
		}
		if err != nil {
			return err
		}
		generation = uint64(head.dataGeneration)
		return nil
	})
	if err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	return policyengine.NewGetDataGenerationResponse(generation)
}
