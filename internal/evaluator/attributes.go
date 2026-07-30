package evaluator

import (
	"context"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// ResolveArguments converts the engine's closed typed value set into the only
// primitive values consumed by dsl.Request.Arguments. It intentionally never
// stringifies unknown values.
func ResolveArguments(arguments map[string]policyengine.Value) (map[string]any, error) {
	resolved := make(map[string]any, len(arguments))
	for name, value := range arguments {
		converted, err := resolveValue(value)
		if err != nil {
			return nil, err
		}
		resolved[name] = converted
	}
	return resolved, nil
}

// ResolveAttribute returns a scalar suitable for one dsl.Request resource
// field. Contextual values take precedence only when they agree with any exact
// persistent value; differing values fail closed with INVALID_ARGUMENT.
func (r *SnapshotReader) ResolveAttribute(
	ctx context.Context,
	entity dsl.EntityRef,
	path []string,
) (any, bool, error) {
	if err := store.ContextError(ctx); err != nil {
		return nil, false, err
	}
	if r == nil || nilSnapshot(r.snapshot) {
		return nil, false, invalidArgument()
	}
	key, err := policyengine.NewAttributeKeyPath(entity, path)
	if err != nil {
		return nil, false, invalidArgument()
	}

	var contextual policyengine.Value
	contextualFound := false
	for index, attribute := range r.contextualAttributes {
		if index%64 == 0 {
			if err := store.ContextError(ctx); err != nil {
				return nil, false, err
			}
		}
		if attribute.Entity() == entity && samePath(attribute.Path(), path) {
			contextual = attribute.Value()
			contextualFound = true
			break
		}
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, false, err
	}

	persistent, err := r.snapshot.GetAttribute(ctx, key)
	if err != nil {
		return nil, false, err
	}
	persistentValue, persistentFound := persistent.Value()
	if contextualFound && persistentFound && contextual != persistentValue {
		return nil, false, invalidArgument()
	}
	if contextualFound {
		if err := r.rejectPersistentPathConflict(ctx, entity, path, key); err != nil {
			return nil, false, err
		}
		converted, err := resolveValue(contextual)
		if err != nil {
			return nil, false, err
		}
		return converted, true, nil
	}
	if !persistentFound {
		return nil, false, nil
	}
	converted, err := resolveValue(persistentValue)
	if err != nil {
		return nil, false, err
	}
	return converted, true, nil
}

func (r *SnapshotReader) rejectPersistentPathConflict(
	ctx context.Context,
	entity dsl.EntityRef,
	path []string,
	key policyengine.AttributeKey,
) error {
	descendant, err := r.snapshot.HasAttributeDescendant(ctx, key)
	if err != nil {
		return err
	}
	if descendant {
		return invalidArgument()
	}
	for index := 1; index < len(path); index++ {
		if err := store.ContextError(ctx); err != nil {
			return err
		}
		ancestor, err := policyengine.NewAttributeKeyPath(entity, path[:index])
		if err != nil {
			return invalidArgument()
		}
		result, err := r.snapshot.GetAttribute(ctx, ancestor)
		if err != nil {
			return err
		}
		if result.Found() {
			return invalidArgument()
		}
	}
	return store.ContextError(ctx)
}

func resolveValue(value policyengine.Value) (any, error) {
	switch value.Kind() {
	case policyengine.ValueKindString:
		text, ok := value.StringValue()
		if !ok {
			return nil, invalidArgument()
		}
		return text, nil
	case policyengine.ValueKindInteger:
		integer, ok := value.Integer()
		if !ok {
			return nil, invalidArgument()
		}
		return integer, nil
	case policyengine.ValueKindBoolean:
		boolean, ok := value.Boolean()
		if !ok {
			return nil, invalidArgument()
		}
		return boolean, nil
	case policyengine.ValueKindNull:
		if !value.IsNull() {
			return nil, invalidArgument()
		}
		return nil, nil
	default:
		return nil, invalidArgument()
	}
}

func samePath(left, right []string) bool {
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

func invalidArgument() error {
	err, _ := policyengine.NewEngineError(policyengine.ErrorInvalidArgument)
	return err
}

func resourceExhausted() error {
	err, _ := policyengine.NewEngineError(policyengine.ErrorResourceExhausted)
	return err
}
