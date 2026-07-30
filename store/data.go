package store

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

const (
	aggregateFieldMetadataBytes      = 8
	aggregateCollectionMetadataBytes = 8
	aggregateValueMetadataBytes      = 9
	aggregateUint64Bytes             = 8
	aggregateBoolBytes               = 1
)

// DataStore composes exact pinned snapshot reads with atomic idempotent writes.
// Data generations are assigned at authoritative atomic commit, never at call
// or transaction start.
type DataStore interface {
	DataReader
	IdempotencyStore
}

// DataReader reads authorization-data heads and opens exact pinned snapshots.
type DataReader interface {
	GetDataGeneration(context.Context, policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error)
	OpenSnapshot(context.Context, SnapshotRequest) (Snapshot, error)
}

// SnapshotRequest asks an adapter to wait for MinimumGeneration and then
// atomically pin the current exact committed namespace view. ReadAt is captured
// by the caller once and is retained independently of the acquisition context.
type SnapshotRequest struct {
	namespace         string
	minimumGeneration uint64
	readAt            time.Time
}

// NewSnapshotRequest constructs an immutable pinned-view acquisition request.
func NewSnapshotRequest(namespace string, minimumGeneration uint64, readAt time.Time) (SnapshotRequest, error) {
	if _, err := policyengine.NewGetDataGenerationRequest(namespace); err != nil {
		return SnapshotRequest{}, err
	}
	if readAt.IsZero() {
		return SnapshotRequest{}, newError(policyengine.ErrorInvalidArgument)
	}
	return SnapshotRequest{
		namespace:         namespace,
		minimumGeneration: minimumGeneration,
		readAt:            readAt,
	}, nil
}

// Namespace returns the exact opaque isolation scope.
func (r SnapshotRequest) Namespace() string { return r.namespace }

// MinimumGeneration returns the requested lower bound, including initial zero.
func (r SnapshotRequest) MinimumGeneration() uint64 { return r.minimumGeneration }

// ReadAt returns the single caller-captured expiry instant.
func (r SnapshotRequest) ReadAt() time.Time { return r.readAt }

// Valid reports whether this request was constructed with valid scope and time.
func (r SnapshotRequest) Valid() bool {
	candidate, err := NewSnapshotRequest(r.namespace, r.minimumGeneration, r.readAt)
	return err == nil && candidate == r
}

// Snapshot is a lifetime-bearing immutable view at one exact committed
// generation. OpenSnapshot resolves the current head and pins its view
// atomically after satisfying the request's lower bound. Every operation must
// observe its own context before and after adapter work. Tuple expiry is exact:
// an expiring tuple is active only when expires_at > ReadAt().
//
// QueryTuples returns every active match or RESOURCE_EXHAUSTED, never a partial
// result. GetAttribute is an exact typed point lookup. After Close, both query
// methods return FAILED_PRECONDITION. A read admitted before Close begins owns
// its pinned resource until it returns; Close waits for every such read and
// must not abort it. Reads arriving after Close begins fail with
// FAILED_PRECONDITION. Concurrent Close calls are idempotent, wait for the same
// admitted reads, and release transaction-compatible resources exactly once.
type Snapshot interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	slog.LogValuer
	Namespace() string
	Generation() uint64
	MinimumGeneration() uint64
	ReadAt() time.Time
	QueryTuples(context.Context, TupleQuery) (TupleResult, error)
	GetAttribute(context.Context, policyengine.AttributeKey) (AttributeResult, error)
	Close() error
}

// TupleQuery is one bounded exact resource-and-relation lookup. Limit is the
// maximum complete result cardinality, not a truncation instruction.
type TupleQuery struct {
	resource dsl.EntityRef
	relation string
	limit    int
}

// NewTupleQuery validates and constructs an immutable bounded tuple query.
func NewTupleQuery(resource dsl.EntityRef, relation string, limit int) (TupleQuery, error) {
	if limit <= 0 {
		return TupleQuery{}, newError(policyengine.ErrorInvalidArgument)
	}
	if limit > policyengine.MaxAggregateWorkItems {
		return TupleQuery{}, newError(policyengine.ErrorResourceExhausted)
	}
	if _, err := policyengine.NewTupleKey(dsl.Tuple{
		Resource: resource,
		Relation: relation,
		Subject:  dsl.SubjectRef{Type: "query", ID: "validation"},
	}); err != nil {
		return TupleQuery{}, err
	}
	return TupleQuery{resource: resource, relation: relation, limit: limit}, nil
}

// Resource returns the exact resource filter.
func (q TupleQuery) Resource() dsl.EntityRef { return q.resource }

// Relation returns the exact relation filter.
func (q TupleQuery) Relation() string { return q.relation }

// Limit returns the positive all-or-error result ceiling.
func (q TupleQuery) Limit() int { return q.limit }

// Valid reports whether the query satisfies stable public work limits.
func (q TupleQuery) Valid() bool {
	candidate, err := NewTupleQuery(q.resource, q.relation, q.limit)
	return err == nil && candidate == q
}

// TupleResult is an immutable deterministic complete result for one exact
// TupleQuery. Subjects are ordered and exact duplicates are deduplicated.
type TupleResult struct {
	query    TupleQuery
	subjects []dsl.SubjectRef
}

// NewTupleResult validates, bounds, orders, deduplicates, and copies adapter
// output. Input beyond the query ceiling fails with RESOURCE_EXHAUSTED before
// cloning or sorting; it is never truncated.
func NewTupleResult(query TupleQuery, subjects []dsl.SubjectRef) (TupleResult, error) {
	if !query.Valid() {
		return TupleResult{}, newError(policyengine.ErrorInvalidArgument)
	}
	if len(subjects) > query.limit || len(subjects) > policyengine.MaxAggregateWorkItems {
		return TupleResult{}, newError(policyengine.ErrorResourceExhausted)
	}
	if err := validateTupleResultBytes(query, subjects); err != nil {
		return TupleResult{}, err
	}
	for _, subject := range subjects {
		if _, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: query.resource,
			Relation: query.relation,
			Subject:  subject,
		}, nil); err != nil {
			return TupleResult{}, newError(policyengine.ErrorIntegrity)
		}
	}
	ordered := append([]dsl.SubjectRef(nil), subjects...)
	sort.Slice(ordered, func(i, j int) bool { return compareSubjectRef(ordered[i], ordered[j]) < 0 })
	write := 0
	for _, subject := range ordered {
		if write > 0 && compareSubjectRef(ordered[write-1], subject) == 0 {
			continue
		}
		ordered[write] = subject
		write++
	}
	return TupleResult{query: query, subjects: ordered[:write]}, nil
}

// Query returns the exact request provenance for this result.
func (r TupleResult) Query() TupleQuery { return r.query }

// Subjects returns a deterministic defensive copy of all matching subjects.
func (r TupleResult) Subjects() []dsl.SubjectRef {
	return append([]dsl.SubjectRef(nil), r.subjects...)
}

// Valid reports whether this is canonical, bounded output for its exact query.
func (r TupleResult) Valid() bool {
	candidate, err := NewTupleResult(r.query, r.subjects)
	if err != nil || candidate.query != r.query || len(candidate.subjects) != len(r.subjects) {
		return false
	}
	for index := range r.subjects {
		if candidate.subjects[index] != r.subjects[index] {
			return false
		}
	}
	return true
}

// AttributeResult is immutable exact-key provenance plus a typed value or an
// explicit missing result.
type AttributeResult struct {
	key   policyengine.AttributeKey
	value policyengine.Value
	found bool
	valid bool
}

// NewAttributeResult validates and constructs exact adapter output. A missing
// result must carry the zero Value; a found result must carry one valid scalar.
func NewAttributeResult(key policyengine.AttributeKey, value policyengine.Value, found bool) (AttributeResult, error) {
	canonicalKey, err := policyengine.NewAttributeKeyPath(key.Entity(), key.Path())
	if err != nil {
		return AttributeResult{}, newError(policyengine.ErrorInvalidArgument)
	}
	if !found {
		if value.Kind() != 0 {
			return AttributeResult{}, newError(policyengine.ErrorIntegrity)
		}
		if err := validateAttributeResultBytes(canonicalKey, value); err != nil {
			return AttributeResult{}, err
		}
		return AttributeResult{key: canonicalKey, valid: true}, nil
	}
	if _, err := policyengine.NewAttributePath(canonicalKey.Entity(), canonicalKey.Path(), value); err != nil {
		return AttributeResult{}, newError(policyengine.ErrorIntegrity)
	}
	if err := validateAttributeResultBytes(canonicalKey, value); err != nil {
		return AttributeResult{}, err
	}
	return AttributeResult{key: canonicalKey, value: value, found: true, valid: true}, nil
}

// Key returns the exact point-lookup provenance.
func (r AttributeResult) Key() policyengine.AttributeKey { return r.key }

// Value returns the typed scalar and whether the exact path exists.
func (r AttributeResult) Value() (policyengine.Value, bool) { return r.value, r.found }

// Found reports whether the exact path exists.
func (r AttributeResult) Found() bool { return r.found }

// Valid reports whether the result is strict and constructor-produced.
func (r AttributeResult) Valid() bool {
	if !r.valid {
		return false
	}
	candidate, err := NewAttributeResult(r.key, r.value, r.found)
	return err == nil && candidate.valid && candidate.found == r.found
}

func validateTupleResultBytes(query TupleQuery, subjects []dsl.SubjectRef) error {
	used := 0
	add := func(size int) bool {
		if size < 0 || size > policyengine.MaxAggregateOutputBytes-used {
			return false
		}
		used += size
		return true
	}
	for _, text := range []string{query.resource.Type, query.resource.ID, query.relation} {
		if !add(aggregateFieldMetadataBytes) || !add(len(text)) {
			return newError(policyengine.ErrorResourceExhausted)
		}
	}
	if !add(aggregateFieldMetadataBytes) || !add(aggregateUint64Bytes) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	if !add(aggregateCollectionMetadataBytes) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	for _, subject := range subjects {
		for _, text := range []string{subject.Type, subject.ID, subject.Relation} {
			if !add(aggregateFieldMetadataBytes) || !add(len(text)) {
				return newError(policyengine.ErrorResourceExhausted)
			}
		}
	}
	return nil
}

func validateAttributeResultBytes(key policyengine.AttributeKey, value policyengine.Value) error {
	used := 0
	add := func(size int) bool {
		if size < 0 || size > policyengine.MaxAggregateOutputBytes-used {
			return false
		}
		used += size
		return true
	}
	if !add(aggregateFieldMetadataBytes) || !add(len(key.Entity().Type)) ||
		!add(aggregateFieldMetadataBytes) || !add(len(key.Entity().ID)) ||
		!add(aggregateCollectionMetadataBytes) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	for _, segment := range key.Path() {
		if !add(aggregateFieldMetadataBytes) || !add(len(segment)) {
			return newError(policyengine.ErrorResourceExhausted)
		}
	}
	if !add(aggregateFieldMetadataBytes) || !add(aggregateBoolBytes) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	if !add(aggregateValueMetadataBytes) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	if text, ok := value.StringValue(); ok && !add(len(text)) {
		return newError(policyengine.ErrorResourceExhausted)
	}
	return nil
}

func compareSubjectRef(left, right dsl.SubjectRef) int {
	for _, pair := range [][2]string{
		{left.Type, right.Type},
		{left.ID, right.ID},
		{left.Relation, right.Relation},
	} {
		if order := cmp.Compare(pair[0], pair[1]); order != 0 {
			return order
		}
	}
	return 0
}

func (SnapshotRequest) String() string { return redactedString("SnapshotRequest") }

// GoString returns a redacted Go-syntax representation.
func (SnapshotRequest) GoString() string { return redactedString("SnapshotRequest") }

// Format writes a redacted representation for every formatting verb.
func (SnapshotRequest) Format(s fmt.State, _ rune) { writeRedacted(s, "SnapshotRequest") }

// LogValue returns privacy-safe structured logging metadata.
func (SnapshotRequest) LogValue() slog.Value { return redactedLogValue("SnapshotRequest") }
func (TupleQuery) String() string            { return redactedString("TupleQuery") }

// GoString returns a redacted Go-syntax representation.
func (TupleQuery) GoString() string { return redactedString("TupleQuery") }

// Format writes a redacted representation for every formatting verb.
func (TupleQuery) Format(s fmt.State, _ rune) { writeRedacted(s, "TupleQuery") }

// LogValue returns privacy-safe structured logging metadata.
func (TupleQuery) LogValue() slog.Value { return redactedLogValue("TupleQuery") }
func (TupleResult) String() string      { return redactedString("TupleResult") }

// GoString returns a redacted Go-syntax representation.
func (TupleResult) GoString() string { return redactedString("TupleResult") }

// Format writes a redacted representation for every formatting verb.
func (TupleResult) Format(s fmt.State, _ rune) { writeRedacted(s, "TupleResult") }

// LogValue returns privacy-safe structured logging metadata.
func (TupleResult) LogValue() slog.Value { return redactedLogValue("TupleResult") }
func (AttributeResult) String() string   { return redactedString("AttributeResult") }

// GoString returns a redacted Go-syntax representation.
func (AttributeResult) GoString() string { return redactedString("AttributeResult") }

// Format writes a redacted representation for every formatting verb.
func (AttributeResult) Format(s fmt.State, _ rune) { writeRedacted(s, "AttributeResult") }

// LogValue returns privacy-safe structured logging metadata.
func (AttributeResult) LogValue() slog.Value { return redactedLogValue("AttributeResult") }
