package domain

import (
	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// DataSchema is the bounded authorization-data shape derived from one decoded
// canonical artifact.
type DataSchema struct {
	entities      map[string]dataEntity
	resourcePaths map[actionKey][][]string
}

type actionKey struct{ entity, action string }

type dataEntity struct {
	relations      map[string][]dsl.RelationTarget
	attributePaths *attributePathTrie
}

// NewDataSchema derives tuple and persistent-attribute validation indexes from
// a decoded canonical artifact.
func NewDataSchema(artifact *dsl.Artifact) (DataSchema, error) {
	if artifact == nil {
		return DataSchema{}, domainError(policyengine.ErrorIntegrity)
	}
	schema, err := dsl.Parse("artifact.cdr", artifact.CanonicalSource())
	if err != nil {
		return DataSchema{}, domainError(policyengine.ErrorIntegrity)
	}
	result := DataSchema{entities: make(map[string]dataEntity, len(schema.Entities)), resourcePaths: make(map[actionKey][][]string, len(schema.Guards))}
	for _, entity := range schema.Entities {
		indexed := dataEntity{
			relations:      make(map[string][]dsl.RelationTarget, len(entity.Relations)),
			attributePaths: newAttributePathTrie(),
		}
		for _, relation := range entity.Relations {
			indexed.relations[relation.Name] = append([]dsl.RelationTarget(nil), relation.Targets...)
		}
		result.entities[entity.Name] = indexed
	}
	for _, guard := range schema.Guards {
		entity, ok := result.entities[guard.Entity]
		if !ok {
			return DataSchema{}, domainError(policyengine.ErrorIntegrity)
		}
		paths := newAttributePathTrie()
		for _, rule := range guard.Rules {
			collectResourcePaths(entity.attributePaths, rule.Condition)
			collectResourcePaths(paths, rule.Condition)
		}
		result.resourcePaths[actionKey{guard.Entity, guard.Action}] = paths.paths(nil)
		result.entities[guard.Entity] = entity
	}
	return result, nil
}

// ValidateGetDataGenerationRequest reconstructs the immutable public request.
func ValidateGetDataGenerationRequest(
	request policyengine.GetDataGenerationRequest,
) (policyengine.GetDataGenerationRequest, error) {
	return policyengine.NewGetDataGenerationRequest(request.Namespace())
}

// ValidateWriteDataRequest reconstructs the immutable public request.
func ValidateWriteDataRequest(
	request policyengine.WriteDataRequest,
) (policyengine.WriteDataRequest, error) {
	return policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            request.Namespace(),
		ValidationRevisionID: request.ValidationRevisionID(),
		ExpectedGeneration:   request.ExpectedGeneration(),
		IdempotencyKey:       request.IdempotencyKey(),
		TupleWrites:          request.TupleWrites(),
		TupleDeletes:         request.TupleDeletes(),
		AttributeWrites:      request.AttributeWrites(),
		AttributeDeletes:     request.AttributeDeletes(),
	})
}

func domainError(category policyengine.ErrorCategory) error {
	err, constructorErr := policyengine.NewEngineError(category)
	if constructorErr == nil {
		return err
	}
	return constructorErr
}

// ResourcePaths returns a defensive copy of the selected action's guard paths.
func (s DataSchema) ResourcePaths(entity, action string) [][]string {
	stored := s.resourcePaths[actionKey{entity, action}]
	result := make([][]string, len(stored))
	for i, path := range stored {
		result[i] = append([]string(nil), path...)
	}
	return result
}
