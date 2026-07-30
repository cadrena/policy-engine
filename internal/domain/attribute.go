package domain

import (
	"context"
	"strings"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// ValidateAttributePaths requires every persistent attribute mutation to name
// a resource path used by a guard on the same artifact entity.
func (s DataSchema) ValidateAttributePaths(request policyengine.WriteDataRequest) error {
	for _, attribute := range request.AttributeWrites() {
		if !s.validAttributePath(attribute.Entity(), attribute.Path()) {
			return domainError(policyengine.ErrorInvalidArgument)
		}
	}
	for _, key := range request.AttributeDeletes() {
		if !s.validAttributePath(key.Entity(), key.Path()) {
			return domainError(policyengine.ErrorInvalidArgument)
		}
	}
	return nil
}

func (s DataSchema) validAttributePath(entity dsl.EntityRef, path []string) bool {
	indexed, ok := s.entities[entity.Type]
	if !ok {
		return false
	}
	_, ok = indexed.attributePaths[strings.Join(path, "\x00")]
	return ok
}

// NormalizeContextualData preserves additive contextual facts while removing
// an attribute already represented by the persistent snapshot. A different
// value at the same entity path would be an override and is rejected.
func NormalizeContextualData(
	ctx context.Context,
	snapshot store.Snapshot,
	contextual policyengine.ContextualData,
) (policyengine.ContextualData, error) {
	validated, err := policyengine.NewContextualData(
		contextual.Tuples(),
		contextual.Attributes(),
	)
	if err != nil {
		return policyengine.ContextualData{}, err
	}
	if ctx == nil || snapshot == nil {
		return policyengine.ContextualData{}, domainError(policyengine.ErrorInvalidArgument)
	}
	additive := make([]policyengine.Attribute, 0, len(validated.Attributes()))
	for _, attribute := range validated.Attributes() {
		key, err := policyengine.NewAttributeKeyPath(attribute.Entity(), attribute.Path())
		if err != nil {
			return policyengine.ContextualData{}, err
		}
		persistent, err := snapshot.GetAttribute(ctx, key)
		if err != nil {
			return policyengine.ContextualData{}, err
		}
		value, found := persistent.Value()
		if !found {
			additive = append(additive, attribute)
			continue
		}
		if !equalValue(value, attribute.Value()) {
			return policyengine.ContextualData{}, domainError(policyengine.ErrorInvalidArgument)
		}
	}
	return policyengine.NewContextualData(validated.Tuples(), additive)
}

func equalValue(left, right policyengine.Value) bool {
	if left.Kind() != right.Kind() {
		return false
	}
	switch left.Kind() {
	case policyengine.ValueKindString:
		leftValue, leftOK := left.StringValue()
		rightValue, rightOK := right.StringValue()
		return leftOK && rightOK && leftValue == rightValue
	case policyengine.ValueKindInteger:
		leftValue, leftOK := left.Integer()
		rightValue, rightOK := right.Integer()
		return leftOK && rightOK && leftValue == rightValue
	case policyengine.ValueKindBoolean:
		leftValue, leftOK := left.Boolean()
		rightValue, rightOK := right.Boolean()
		return leftOK && rightOK && leftValue == rightValue
	case policyengine.ValueKindNull:
		return left.IsNull() && right.IsNull()
	default:
		return false
	}
}

func collectResourcePaths(paths map[string]struct{}, condition dsl.ConditionExpression) {
	switch value := condition.(type) {
	case dsl.ComparisonExpression:
		if len(value.Field) > 1 && value.Field[0] == "resource" {
			paths[strings.Join(value.Field[1:], "\x00")] = struct{}{}
		}
	case *dsl.ComparisonExpression:
		if value != nil {
			collectResourcePaths(paths, *value)
		}
	case dsl.LogicalCondition:
		collectResourcePaths(paths, value.Left)
		collectResourcePaths(paths, value.Right)
	case *dsl.LogicalCondition:
		if value != nil {
			collectResourcePaths(paths, *value)
		}
	}
}
