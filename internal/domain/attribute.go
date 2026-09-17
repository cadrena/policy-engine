package domain

import (
	"context"
	"sort"

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
	return indexed.attributePaths.contains(path)
}

// NormalizeContextualData preserves additive contextual facts while removing
// an attribute already represented by the persistent snapshot. A different
// value at the same entity path, or any occupied strict prefix/descendant,
// would be an override and is rejected.
func (s DataSchema) NormalizeContextualData(
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
		entity, ok := s.entities[attribute.Entity().Type]
		if !ok || !entity.attributePaths.contains(attribute.Path()) {
			return policyengine.ContextualData{}, domainError(policyengine.ErrorInvalidArgument)
		}
		exactDuplicate := false
		attributePath := attribute.Path()
		for length := 1; length <= len(attributePath); length++ {
			path := attributePath[:length]
			key, err := policyengine.NewAttributeKeyPath(attribute.Entity(), path)
			if err != nil {
				return policyengine.ContextualData{}, err
			}
			persistent, err := snapshot.GetAttribute(ctx, key)
			if err != nil {
				return policyengine.ContextualData{}, err
			}
			if !persistent.Valid() || !sameAttributeKey(persistent.Key(), key) {
				return policyengine.ContextualData{}, domainError(policyengine.ErrorIntegrity)
			}
			value, found := persistent.Value()
			if !found {
				continue
			}
			if length != len(attributePath) ||
				!equalValue(value, attribute.Value()) {
				return policyengine.ContextualData{}, domainError(policyengine.ErrorInvalidArgument)
			}
			exactDuplicate = true
		}
		key, err := policyengine.NewAttributeKeyPath(attribute.Entity(), attributePath)
		if err != nil {
			return policyengine.ContextualData{}, err
		}
		hasDescendant, err := snapshot.HasAttributeDescendant(ctx, key)
		if err != nil {
			return policyengine.ContextualData{}, err
		}
		if hasDescendant {
			return policyengine.ContextualData{}, domainError(policyengine.ErrorInvalidArgument)
		}
		if !exactDuplicate {
			additive = append(additive, attribute)
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

type attributePathTrie struct {
	terminal bool
	children map[string]*attributePathTrie
}

func newAttributePathTrie() *attributePathTrie {
	return &attributePathTrie{children: make(map[string]*attributePathTrie)}
}

func (t *attributePathTrie) insert(path []string) {
	current := t
	for _, segment := range path {
		next := current.children[segment]
		if next == nil {
			next = newAttributePathTrie()
			current.children[segment] = next
		}
		current = next
	}
	current.terminal = true
}

func (t *attributePathTrie) contains(path []string) bool {
	current := t
	for _, segment := range path {
		if current == nil {
			return false
		}
		current = current.children[segment]
	}
	return current != nil && current.terminal
}

func sameAttributeKey(left, right policyengine.AttributeKey) bool {
	return left.Entity() == right.Entity() && equalPath(left.Path(), right.Path())
}

func equalPath(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func collectResourcePaths(paths *attributePathTrie, condition dsl.ConditionExpression) {
	switch value := condition.(type) {
	case dsl.ComparisonExpression:
		if len(value.Field) > 1 && value.Field[0] == "resource" {
			paths.insert(value.Field[1:])
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

func (t *attributePathTrie) paths(prefix []string) [][]string {
	var result [][]string
	if t.terminal {
		result = append(result, append([]string(nil), prefix...))
	}
	names := make([]string, 0, len(t.children))
	for name := range t.children {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, t.children[name].paths(append(prefix, name))...)
	}
	return result
}
