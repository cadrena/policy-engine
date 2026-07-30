// Package evaluator adapts one pinned authorization-data snapshot to the DSL
// evaluator's tuple-reader boundary.
package evaluator

import (
	"context"
	"reflect"
	"sort"

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
	subjects = append(subjects, result.Subjects()...)
	if len(subjects) > policyengine.MaxAggregateWorkItems+policyengine.MaxContextualTuples {
		return nil, resourceExhausted()
	}
	subjects = canonicalSubjects(subjects)
	if len(subjects) > policyengine.MaxAggregateWorkItems {
		return nil, resourceExhausted()
	}
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	return subjects, nil
}

func canonicalSubjects(subjects []dsl.SubjectRef) []dsl.SubjectRef {
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Type != subjects[j].Type {
			return subjects[i].Type < subjects[j].Type
		}
		if subjects[i].ID != subjects[j].ID {
			return subjects[i].ID < subjects[j].ID
		}
		return subjects[i].Relation < subjects[j].Relation
	})
	write := 0
	for _, subject := range subjects {
		if write > 0 && subject == subjects[write-1] {
			continue
		}
		subjects[write] = subject
		write++
	}
	for index := write; index < len(subjects); index++ {
		subjects[index] = dsl.SubjectRef{}
	}
	return subjects[:write]
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
