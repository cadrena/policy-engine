// Package evaluator adapts one pinned authorization-data snapshot to the DSL
// evaluator's tuple-reader boundary.
package evaluator

import (
	"context"
	"reflect"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// SnapshotReader exposes one exact store snapshot as a DSL tuple reader. It
// never reads a mutable data head; every read goes through the supplied pinned
// snapshot and therefore observes its exact generation and ReadAt instant.
type SnapshotReader struct {
	snapshot             store.Snapshot
	contextualTuples     []policyengine.RelationshipTuple
	contextualAttributes []policyengine.Attribute
}

// NewSnapshotReader constructs a DSL tuple reader over one already-open,
// pinned snapshot and trusted request-scoped additive facts.
func NewSnapshotReader(snapshot store.Snapshot, contextual policyengine.ContextualData) (*SnapshotReader, error) {
	if nilSnapshot(snapshot) {
		return nil, invalidArgument()
	}
	return &SnapshotReader{
		snapshot:             snapshot,
		contextualTuples:     contextual.Tuples(),
		contextualAttributes: contextual.Attributes(),
	}, nil
}

// ReadTuples implements dsl.TupleReader. Contextual tuples are examined before
// the pinned persistent bucket. The complete result is then sorted and
// deduplicated into the DSL's canonical subject order.
func (r *SnapshotReader) ReadTuples(ctx context.Context, resource dsl.EntityRef, relation string) ([]dsl.SubjectRef, error) {
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	if r == nil || nilSnapshot(r.snapshot) {
		return nil, invalidArgument()
	}
	query, err := store.NewTupleQuery(resource, relation, policyengine.MaxAggregateWorkItems)
	if err != nil {
		return nil, invalidArgument()
	}

	subjects := make([]dsl.SubjectRef, 0, len(r.contextualTuples))
	for index, tuple := range r.contextualTuples {
		if index%64 == 0 {
			if err := store.ContextError(ctx); err != nil {
				return nil, err
			}
		}
		value := tuple.Tuple()
		if value.Resource != resource || value.Relation != relation {
			continue
		}
		if expiresAt, expires := tuple.ExpiresAt(); expires && !expiresAt.After(r.snapshot.ReadAt()) {
			continue
		}
		subjects = append(subjects, value.Subject)
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}

	result, err := r.snapshot.QueryTuples(ctx, query)
	if err != nil {
		return nil, err
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	persistent := result.Subjects()
	if len(persistent) > policyengine.MaxAggregateWorkItems-len(subjects) {
		return nil, resourceExhausted()
	}
	subjects, err = canonicalSubjects(ctx, subjects, persistent)
	if err != nil {
		return nil, err
	}
	if len(subjects) > policyengine.MaxAggregateWorkItems {
		return nil, resourceExhausted()
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	return subjects, nil
}

func canonicalSubjects(ctx context.Context, contextual, persistent []dsl.SubjectRef) ([]dsl.SubjectRef, error) {
	canonical := make([]dsl.SubjectRef, 0, len(contextual)+len(persistent))
	appendSubject := func(subject dsl.SubjectRef) {
		if len(canonical) == 0 || canonical[len(canonical)-1] != subject {
			canonical = append(canonical, subject)
		}
	}
	contextualIndex := 0
	persistentIndex := 0
	for contextualIndex < len(contextual) || persistentIndex < len(persistent) {
		if (contextualIndex+persistentIndex)%64 == 0 {
			if err := store.ContextError(ctx); err != nil {
				return nil, err
			}
		}
		if contextualIndex == len(contextual) {
			appendSubject(persistent[persistentIndex])
			persistentIndex++
			continue
		}
		if persistentIndex == len(persistent) {
			appendSubject(contextual[contextualIndex])
			contextualIndex++
			continue
		}
		switch compareSubjects(contextual[contextualIndex], persistent[persistentIndex]) {
		case -1:
			appendSubject(contextual[contextualIndex])
			contextualIndex++
		case 0:
			appendSubject(contextual[contextualIndex])
			contextualIndex++
			persistentIndex++
		case 1:
			appendSubject(persistent[persistentIndex])
			persistentIndex++
		}
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	return canonical, nil
}

func compareSubjects(left, right dsl.SubjectRef) int {
	if left.Type < right.Type {
		return -1
	}
	if left.Type > right.Type {
		return 1
	}
	if left.ID < right.ID {
		return -1
	}
	if left.ID > right.ID {
		return 1
	}
	if left.Relation < right.Relation {
		return -1
	}
	if left.Relation > right.Relation {
		return 1
	}
	return 0
}

func nilSnapshot(snapshot store.Snapshot) bool {
	if snapshot == nil {
		return true
	}
	value := reflect.ValueOf(snapshot)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
