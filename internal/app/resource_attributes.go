package app

import (
	"context"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// Resolve only declared fields for this action through the already pinned reader.
// The budget belongs to the session and therefore spans every item of a batch.
func resolveResourceAttributes(ctx context.Context, session evaluationSession, resource dsl.EntityRef, action string) (map[string]any, error) {
	attributes := make(map[string]any)
	for _, path := range session.schema.ResourcePaths(resource.Type, action) {
		if err := sanitizeRuntimeError(ctx.Err(), policyengine.ErrorInternal); err != nil {
			return nil, err
		}
		size := 8 * len(path)
		for _, part := range path {
			size += len(part)
		}
		// One exact read, plus the descendant/ancestor checks for contextual leaves.
		if err := session.attributeBudget.add(len(path)+2, size); err != nil {
			return nil, err
		}
		value, found, err := session.reader.ResolveAttribute(ctx, resource, path)
		if err != nil {
			return nil, sanitizeRuntimeError(err, policyengine.ErrorUnavailable)
		}
		if !found {
			continue
		}
		size = 8
		if text, ok := value.(string); ok {
			size += len(text)
		}
		if err = session.attributeBudget.add(0, size); err != nil {
			return nil, err
		}
		if err = insertResourceAttribute(attributes, path, value); err != nil {
			return nil, err
		}
	}
	return attributes, nil
}
func insertResourceAttribute(root map[string]any, path []string, value any) error {
	if len(path) == 0 {
		return appError(policyengine.ErrorIntegrity)
	}
	current := root
	for _, part := range path[:len(path)-1] {
		child, exists := current[part]
		if !exists {
			next := make(map[string]any)
			current[part] = next
			current = next
			continue
		}
		next, ok := child.(map[string]any)
		if !ok {
			return appError(policyengine.ErrorIntegrity)
		}
		current = next
	}
	leaf := path[len(path)-1]
	if _, exists := current[leaf]; exists {
		return appError(policyengine.ErrorIntegrity)
	}
	current[leaf] = value
	return nil
}
