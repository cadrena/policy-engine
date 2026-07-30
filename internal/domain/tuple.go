package domain

import (
	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// ValidateTuplePaths requires every tuple mutation to match a relation target
// declared by the decoded artifact.
func (s DataSchema) ValidateTuplePaths(request policyengine.WriteDataRequest) error {
	for _, tuple := range request.TupleWrites() {
		if !s.validTuple(tuple.Tuple()) {
			return domainError(policyengine.ErrorInvalidArgument)
		}
	}
	for _, key := range request.TupleDeletes() {
		if !s.validTuple(key.Tuple()) {
			return domainError(policyengine.ErrorInvalidArgument)
		}
	}
	return nil
}

func (s DataSchema) validTuple(tuple dsl.Tuple) bool {
	entity, ok := s.entities[tuple.Resource.Type]
	if !ok {
		return false
	}
	targets, ok := entity.relations[tuple.Relation]
	if !ok {
		return false
	}
	for _, target := range targets {
		if target.Entity == tuple.Subject.Type && target.Relation == tuple.Subject.Relation {
			return true
		}
	}
	return false
}
