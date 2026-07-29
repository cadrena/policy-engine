package policyengine

import (
	"cmp"
	"sort"
	"time"

	"github.com/conductera/dsl"
)

// ValueKind identifies one non-coercing authorization attribute value type.
type ValueKind uint8

const (
	// ValueKindString identifies a string value.
	ValueKindString ValueKind = iota + 1
	// ValueKindInteger identifies a signed integer value.
	ValueKindInteger
	// ValueKindBoolean identifies a boolean value.
	ValueKindBoolean
	// ValueKindNull identifies an explicit null value.
	ValueKindNull
)

// Value is an immutable typed authorization value.
type Value struct {
	kind    ValueKind
	text    string
	integer int64
	boolean bool
}

// NewStringValue validates UTF-8 text and constructs an immutable string value.
// Empty strings are valid; oversized or unsafe text is rejected.
func NewStringValue(value string) (Value, error) {
	if err := validateText(value, MaxStringValueBytes, true); err != nil {
		return Value{}, err
	}
	return Value{kind: ValueKindString, text: value}, nil
}

// NewIntegerValue constructs an immutable signed integer value.
func NewIntegerValue(value int64) Value {
	return Value{kind: ValueKindInteger, integer: value}
}

// NewBooleanValue constructs an immutable boolean value.
func NewBooleanValue(value bool) Value {
	return Value{kind: ValueKindBoolean, boolean: value}
}

// NewNullValue constructs an immutable explicit null value.
func NewNullValue() Value {
	return Value{kind: ValueKindNull}
}

// Kind returns the value's non-zero type.
func (v Value) Kind() ValueKind { return v.kind }

// StringValue returns the string and whether this is a string value.
func (v Value) StringValue() (string, bool) { return v.text, v.kind == ValueKindString }

// Integer returns the integer and whether this is an integer value.
func (v Value) Integer() (int64, bool) { return v.integer, v.kind == ValueKindInteger }

// Boolean returns the boolean and whether this is a boolean value.
func (v Value) Boolean() (bool, bool) { return v.boolean, v.kind == ValueKindBoolean }

// IsNull reports whether this is an explicit null value.
func (v Value) IsNull() bool { return v.kind == ValueKindNull }

func (v Value) valid() bool {
	switch v.kind {
	case ValueKindString:
		return v.integer == 0 && !v.boolean && validateText(v.text, MaxStringValueBytes, true) == nil
	case ValueKindInteger:
		return v.text == "" && !v.boolean
	case ValueKindBoolean:
		return v.text == "" && v.integer == 0
	case ValueKindNull:
		return v.text == "" && v.integer == 0 && !v.boolean
	default:
		return false
	}
}

// RelationshipTuple is an immutable relationship fact with optional expiry.
type RelationshipTuple struct {
	tuple     dsl.Tuple
	expiresAt time.Time
	hasExpiry bool
}

// NewRelationshipTuple validates and constructs a relationship fact.
func NewRelationshipTuple(tuple dsl.Tuple, expiresAt *time.Time) (RelationshipTuple, error) {
	if err := validateDSLRelationship(tuple); err != nil {
		return RelationshipTuple{}, err
	}
	result := RelationshipTuple{tuple: tuple}
	if expiresAt != nil {
		if expiresAt.IsZero() {
			return RelationshipTuple{}, invalidArgument("relationship tuple expiry is zero")
		}
		result.expiresAt = *expiresAt
		result.hasExpiry = true
	}
	return result, nil
}

// Tuple returns the immutable tagged DSL relationship tuple.
func (t RelationshipTuple) Tuple() dsl.Tuple { return t.tuple }

// ExpiresAt returns the expiry and whether one was configured.
func (t RelationshipTuple) ExpiresAt() (time.Time, bool) { return t.expiresAt, t.hasExpiry }

func (t RelationshipTuple) valid() bool {
	return validateDSLRelationship(t.tuple) == nil && (!t.hasExpiry || !t.expiresAt.IsZero()) && (t.hasExpiry || t.expiresAt.IsZero())
}

// Attribute is an immutable typed entity attribute.
type Attribute struct {
	entity dsl.EntityRef
	path   []string
	value  Value
}

// NewAttribute validates and constructs an immutable typed entity attribute.
func NewAttribute(entity dsl.EntityRef, name string, value Value) (Attribute, error) {
	return NewAttributePath(entity, []string{name}, value)
}

// NewAttributePath validates and constructs an immutable typed scalar leaf at
// a non-empty DSL resource field path.
func NewAttributePath(entity dsl.EntityRef, path []string, value Value) (Attribute, error) {
	if err := validateEntityRef(entity); err != nil {
		return Attribute{}, err
	}
	if err := validateAttributePath(path); err != nil {
		return Attribute{}, err
	}
	if err := validateValue(value); err != nil {
		return Attribute{}, err
	}
	candidate := Attribute{entity: entity, path: path, value: value}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addAttributeCost(&budget, candidate); err != nil {
		return Attribute{}, err
	}
	return Attribute{entity: entity, path: cloneSlice(path), value: value}, nil
}

// Entity returns the attributed entity.
func (a Attribute) Entity() dsl.EntityRef { return a.entity }

// Name returns the first artifact-declared path segment. Top-level attributes
// have exactly this one segment; use Path for nested resource fields.
func (a Attribute) Name() string {
	if len(a.path) == 0 {
		return ""
	}
	return a.path[0]
}

// Path returns a defensive copy of the non-empty resource field path.
func (a Attribute) Path() []string { return cloneSlice(a.path) }

// Value returns the immutable typed value.
func (a Attribute) Value() Value { return a.value }

func (a Attribute) valid() bool {
	return validateEntityRef(a.entity) == nil && validateAttributePath(a.path) == nil && validateValue(a.value) == nil
}

// ContextualData contains trusted request-scoped additive facts.
type ContextualData struct {
	tuples     []RelationshipTuple
	attributes []Attribute
}

// NewContextualData validates, sorts, and copies additive contextual facts.
func NewContextualData(tuples []RelationshipTuple, attributes []Attribute) (ContextualData, error) {
	if len(tuples) > MaxContextualTuples || len(attributes) > MaxContextualAttributes {
		return ContextualData{}, resourceExhausted()
	}
	raw := ContextualData{tuples: tuples, attributes: attributes}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addContextualDataCost(&byteBudget, raw); err != nil {
		return ContextualData{}, err
	}
	for _, tuple := range tuples {
		if !tuple.valid() {
			return ContextualData{}, invalidArgument("contextual data contains an invalid tuple")
		}
	}
	for _, attribute := range attributes {
		if !attribute.valid() {
			return ContextualData{}, invalidArgument("contextual data contains an invalid attribute")
		}
	}
	clonedTuples, err := canonicalRelationshipTuples(tuples)
	if err != nil {
		return ContextualData{}, err
	}
	clonedAttributes, err := canonicalAttributes(attributes)
	if err != nil {
		return ContextualData{}, err
	}
	return ContextualData{tuples: clonedTuples, attributes: clonedAttributes}, nil
}

// Tuples returns a deterministic defensive copy of contextual tuples.
func (d ContextualData) Tuples() []RelationshipTuple { return cloneSlice(d.tuples) }

// Attributes returns a deterministic defensive copy of contextual attributes.
func (d ContextualData) Attributes() []Attribute { return cloneSlice(d.attributes) }

// Empty reports whether no contextual facts were supplied.
func (d ContextualData) Empty() bool { return len(d.tuples) == 0 && len(d.attributes) == 0 }

func (d ContextualData) valid() bool {
	if len(d.tuples) > MaxContextualTuples || len(d.attributes) > MaxContextualAttributes {
		return false
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if addContextualDataCost(&byteBudget, d) != nil {
		return false
	}
	for index, tuple := range d.tuples {
		if !tuple.valid() {
			return false
		}
		if index > 0 && (compareTuple(d.tuples[index-1].tuple, tuple.tuple) == 0 || compareRelationshipTuple(d.tuples[index-1], tuple) >= 0) {
			return false
		}
	}
	for index, attribute := range d.attributes {
		if !attribute.valid() {
			return false
		}
		if index > 0 && (compareAttributeKey(d.attributes[index-1], attribute) == 0 || compareAttribute(d.attributes[index-1], attribute) >= 0) {
			return false
		}
	}
	return true
}

func compareTuple(left, right dsl.Tuple) int {
	for _, pair := range [][2]string{
		{left.Resource.Type, right.Resource.Type},
		{left.Resource.ID, right.Resource.ID},
		{left.Relation, right.Relation},
		{left.Subject.Type, right.Subject.Type},
		{left.Subject.ID, right.Subject.ID},
		{left.Subject.Relation, right.Subject.Relation},
	} {
		if order := cmp.Compare(pair[0], pair[1]); order != 0 {
			return order
		}
	}
	return 0
}

func compareBool(left, right bool) int {
	if left == right {
		return 0
	}
	if !left {
		return -1
	}
	return 1
}

func compareRelationshipTuple(left, right RelationshipTuple) int {
	if order := compareTuple(left.tuple, right.tuple); order != 0 {
		return order
	}
	if order := compareBool(left.hasExpiry, right.hasExpiry); order != 0 {
		return order
	}
	return left.expiresAt.Compare(right.expiresAt)
}

func canonicalRelationshipTuples(values []RelationshipTuple) ([]RelationshipTuple, error) {
	result := cloneSlice(values)
	sort.Slice(result, func(i, j int) bool { return compareRelationshipTuple(result[i], result[j]) < 0 })
	write := 0
	for _, value := range result {
		if write > 0 && compareTuple(result[write-1].tuple, value.tuple) == 0 {
			if compareRelationshipTuple(result[write-1], value) != 0 {
				return nil, invalidArgument("same tuple has conflicting expiry")
			}
			continue
		}
		result[write] = value
		write++
	}
	return result[:write], nil
}

func compareAttributeKey(left, right Attribute) int {
	for _, pair := range [][2]string{{left.entity.Type, right.entity.Type}, {left.entity.ID, right.entity.ID}} {
		if order := cmp.Compare(pair[0], pair[1]); order != 0 {
			return order
		}
	}
	return compareAttributePath(left.path, right.path)
}

func compareValue(left, right Value) int {
	if order := cmp.Compare(left.kind, right.kind); order != 0 {
		return order
	}
	if order := cmp.Compare(left.text, right.text); order != 0 {
		return order
	}
	if order := cmp.Compare(left.integer, right.integer); order != 0 {
		return order
	}
	return compareBool(left.boolean, right.boolean)
}

func compareAttribute(left, right Attribute) int {
	if order := compareAttributeKey(left, right); order != 0 {
		return order
	}
	return compareValue(left.value, right.value)
}

func canonicalAttributes(values []Attribute) ([]Attribute, error) {
	result := cloneSlice(values)
	sort.Slice(result, func(i, j int) bool { return compareAttribute(result[i], result[j]) < 0 })
	write := 0
	for _, value := range result {
		if write > 0 && compareAttributeKey(result[write-1], value) == 0 {
			if compareValue(result[write-1].value, value.value) != 0 {
				return nil, invalidArgument("same attribute has conflicting typed value")
			}
			continue
		}
		if write > 0 && attributePathPrefixConflict(result[write-1].entity, result[write-1].path, value.entity, value.path) {
			return nil, invalidArgument("same entity has conflicting attribute path prefixes")
		}
		result[write] = value
		write++
	}
	return result[:write], nil
}

// TupleKey identifies a persistent relationship tuple for deletion.
type TupleKey struct {
	tuple dsl.Tuple
}

// NewTupleKey validates and constructs an immutable relationship tuple key.
func NewTupleKey(tuple dsl.Tuple) (TupleKey, error) {
	if err := validateDSLRelationship(tuple); err != nil {
		return TupleKey{}, err
	}
	return TupleKey{tuple: tuple}, nil
}

// Tuple returns the tagged DSL tuple identity.
func (k TupleKey) Tuple() dsl.Tuple { return k.tuple }

func (k TupleKey) valid() bool {
	return validateDSLRelationship(k.tuple) == nil
}

// AttributeKey identifies a persistent typed entity attribute for deletion.
type AttributeKey struct {
	entity dsl.EntityRef
	path   []string
}

// NewAttributeKey validates and constructs an immutable attribute key.
func NewAttributeKey(entity dsl.EntityRef, name string) (AttributeKey, error) {
	return NewAttributeKeyPath(entity, []string{name})
}

// NewAttributeKeyPath validates and constructs an immutable nested attribute
// key with a non-empty DSL resource field path.
func NewAttributeKeyPath(entity dsl.EntityRef, path []string) (AttributeKey, error) {
	if err := validateEntityRef(entity); err != nil {
		return AttributeKey{}, err
	}
	if err := validateAttributePath(path); err != nil {
		return AttributeKey{}, err
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addEntityRefCost(&budget, entity); err != nil {
		return AttributeKey{}, err
	}
	if err := addAttributePathCost(&budget, path); err != nil {
		return AttributeKey{}, err
	}
	return AttributeKey{entity: entity, path: cloneSlice(path)}, nil
}

// Entity returns the attributed entity.
func (k AttributeKey) Entity() dsl.EntityRef { return k.entity }

// Name returns the first artifact-declared path segment. Top-level keys have
// exactly this one segment; use Path for nested resource fields.
func (k AttributeKey) Name() string {
	if len(k.path) == 0 {
		return ""
	}
	return k.path[0]
}

// Path returns a defensive copy of the non-empty resource field path.
func (k AttributeKey) Path() []string { return cloneSlice(k.path) }

func (k AttributeKey) valid() bool {
	return validateEntityRef(k.entity) == nil && validateAttributePath(k.path) == nil
}

// GetDataGenerationRequest reads only the current authorization-data head.
type GetDataGenerationRequest struct {
	namespace string
}

// NewGetDataGenerationRequest constructs a metadata-only data-head request.
func NewGetDataGenerationRequest(namespace string) (GetDataGenerationRequest, error) {
	if err := validateNamespace(namespace); err != nil {
		return GetDataGenerationRequest{}, err
	}
	return GetDataGenerationRequest{namespace: namespace}, nil
}

// Namespace returns the opaque data namespace.
func (r GetDataGenerationRequest) Namespace() string { return r.namespace }

// GetDataGenerationResponse reports the current exact generation without data.
type GetDataGenerationResponse struct {
	validResponse bool
	generation    uint64
}

// NewGetDataGenerationResponse constructs a data head, including initial zero.
func NewGetDataGenerationResponse(generation uint64) (GetDataGenerationResponse, error) {
	return GetDataGenerationResponse{validResponse: true, generation: generation}, nil
}

// Generation returns the current exact authorization-data generation.
func (r GetDataGenerationResponse) Generation() uint64 { return r.generation }

// Valid reports whether the response was produced by its constructor.
func (r GetDataGenerationResponse) Valid() bool { return r.validResponse }

// WriteDataRequestInput contains the atomic mutations copied by NewWriteDataRequest.
type WriteDataRequestInput struct {
	Namespace            string
	ValidationRevisionID string
	ExpectedGeneration   uint64
	IdempotencyKey       string
	TupleWrites          []RelationshipTuple
	TupleDeletes         []TupleKey
	AttributeWrites      []Attribute
	AttributeDeletes     []AttributeKey
}

// WriteDataRequest contains one immutable atomic authorization-data mutation.
type WriteDataRequest struct {
	namespace            string
	validationRevisionID string
	expectedGeneration   uint64
	idempotencyKey       string
	tupleWrites          []RelationshipTuple
	tupleDeletes         []TupleKey
	attributeWrites      []Attribute
	attributeDeletes     []AttributeKey
}

// NewWriteDataRequest validates, sorts, and copies one atomic data mutation.
func NewWriteDataRequest(input WriteDataRequestInput) (WriteDataRequest, error) {
	mutationBudget := budgetCounter{max: MaxMutationItems}
	for _, count := range []int{len(input.TupleWrites), len(input.TupleDeletes), len(input.AttributeWrites), len(input.AttributeDeletes)} {
		if err := mutationBudget.add(count); err != nil {
			return WriteDataRequest{}, err
		}
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addWriteDataRequestCost(&byteBudget, input); err != nil {
		return WriteDataRequest{}, err
	}
	if !validRevisionIDString(input.ValidationRevisionID) || mutationBudget.used == 0 {
		return WriteDataRequest{}, invalidArgument("data write requires namespace, validation revision, idempotency key, and mutations")
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return WriteDataRequest{}, err
	}
	if err := validateIdentifier(input.IdempotencyKey); err != nil {
		return WriteDataRequest{}, err
	}
	for _, value := range input.TupleWrites {
		if !value.valid() {
			return WriteDataRequest{}, invalidArgument("data write contains an invalid tuple")
		}
	}
	for _, value := range input.TupleDeletes {
		if !value.valid() {
			return WriteDataRequest{}, invalidArgument("data write contains an invalid tuple deletion")
		}
	}
	for _, value := range input.AttributeWrites {
		if !value.valid() {
			return WriteDataRequest{}, invalidArgument("data write contains an invalid attribute")
		}
	}
	for _, value := range input.AttributeDeletes {
		if !value.valid() {
			return WriteDataRequest{}, invalidArgument("data write contains an invalid attribute deletion")
		}
	}
	tupleWrites, err := canonicalRelationshipTuples(input.TupleWrites)
	if err != nil {
		return WriteDataRequest{}, err
	}
	tupleDeletes := canonicalTupleKeys(input.TupleDeletes)
	attributeWrites, err := canonicalAttributes(input.AttributeWrites)
	if err != nil {
		return WriteDataRequest{}, err
	}
	attributeDeletes, err := canonicalAttributeKeys(input.AttributeDeletes)
	if err != nil {
		return WriteDataRequest{}, err
	}
	if tupleWriteDeleteConflict(tupleWrites, tupleDeletes) || attributeWriteDeleteConflict(attributeWrites, attributeDeletes) {
		return WriteDataRequest{}, invalidArgument("data write contains a write/delete intersection")
	}
	return WriteDataRequest{
		namespace:            input.Namespace,
		validationRevisionID: input.ValidationRevisionID,
		expectedGeneration:   input.ExpectedGeneration,
		idempotencyKey:       input.IdempotencyKey,
		tupleWrites:          tupleWrites,
		tupleDeletes:         tupleDeletes,
		attributeWrites:      attributeWrites,
		attributeDeletes:     attributeDeletes,
	}, nil
}

// Namespace returns the opaque mutation namespace.
func (r WriteDataRequest) Namespace() string { return r.namespace }

// ValidationRevisionID returns the exact loaded revision used to validate the write.
func (r WriteDataRequest) ValidationRevisionID() string { return r.validationRevisionID }

// ExpectedGeneration returns the exact generation required by compare-and-swap.
func (r WriteDataRequest) ExpectedGeneration() uint64 { return r.expectedGeneration }

// IdempotencyKey returns the caller-provided replay key.
func (r WriteDataRequest) IdempotencyKey() string { return r.idempotencyKey }

// TupleWrites returns a deterministic defensive copy of relationship upserts.
func (r WriteDataRequest) TupleWrites() []RelationshipTuple { return cloneSlice(r.tupleWrites) }

// TupleDeletes returns a deterministic defensive copy of relationship deletions.
func (r WriteDataRequest) TupleDeletes() []TupleKey { return cloneSlice(r.tupleDeletes) }

// AttributeWrites returns a deterministic defensive copy of typed attribute writes.
func (r WriteDataRequest) AttributeWrites() []Attribute { return cloneSlice(r.attributeWrites) }

// AttributeDeletes returns a deterministic defensive copy of typed attribute deletions.
func (r WriteDataRequest) AttributeDeletes() []AttributeKey { return cloneSlice(r.attributeDeletes) }

func (r WriteDataRequest) valid() bool {
	mutationBudget := budgetCounter{max: MaxMutationItems}
	for _, count := range []int{len(r.tupleWrites), len(r.tupleDeletes), len(r.attributeWrites), len(r.attributeDeletes)} {
		if mutationBudget.add(count) != nil {
			return false
		}
	}
	if mutationBudget.used == 0 || !validNamespace(r.namespace) || !validRevisionIDString(r.validationRevisionID) || !validIdentifier(r.idempotencyKey) {
		return false
	}
	input := WriteDataRequestInput{
		Namespace:            r.namespace,
		ValidationRevisionID: r.validationRevisionID,
		ExpectedGeneration:   r.expectedGeneration,
		IdempotencyKey:       r.idempotencyKey,
		TupleWrites:          r.tupleWrites,
		TupleDeletes:         r.tupleDeletes,
		AttributeWrites:      r.attributeWrites,
		AttributeDeletes:     r.attributeDeletes,
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if addWriteDataRequestCost(&byteBudget, input) != nil || !validCanonicalRelationshipTuples(r.tupleWrites) || !validCanonicalTupleKeys(r.tupleDeletes) || !validCanonicalAttributes(r.attributeWrites) || !validCanonicalAttributeKeys(r.attributeDeletes) {
		return false
	}
	return !tupleWriteDeleteConflict(r.tupleWrites, r.tupleDeletes) && !attributeWriteDeleteConflict(r.attributeWrites, r.attributeDeletes)
}

// WriteDataResponse reports the committed authorization-data generation.
type WriteDataResponse struct {
	generation uint64
	replayed   bool
}

// NewWriteDataResponse validates and constructs a successful data-write response.
func NewWriteDataResponse(generation uint64, replayed bool) (WriteDataResponse, error) {
	if generation == 0 {
		return WriteDataResponse{}, invalidArgument("data-write response requires a committed generation")
	}
	return WriteDataResponse{generation: generation, replayed: replayed}, nil
}

// Generation returns the exact committed generation.
func (r WriteDataResponse) Generation() uint64 { return r.generation }

// Replayed reports whether this is the original response to an idempotent replay.
func (r WriteDataResponse) Replayed() bool { return r.replayed }

func validCanonicalRelationshipTuples(values []RelationshipTuple) bool {
	for index, value := range values {
		if !value.valid() {
			return false
		}
		if index > 0 && (compareTuple(values[index-1].tuple, value.tuple) == 0 || compareRelationshipTuple(values[index-1], value) >= 0) {
			return false
		}
	}
	return true
}

func validCanonicalTupleKeys(values []TupleKey) bool {
	for index, value := range values {
		if !value.valid() || (index > 0 && compareTuple(values[index-1].tuple, value.tuple) >= 0) {
			return false
		}
	}
	return true
}

func validCanonicalAttributes(values []Attribute) bool {
	for index, value := range values {
		if !value.valid() {
			return false
		}
		if index > 0 && (compareAttributeKey(values[index-1], value) == 0 || compareAttribute(values[index-1], value) >= 0) {
			return false
		}
		if index > 0 && attributePathPrefixConflict(values[index-1].entity, values[index-1].path, value.entity, value.path) {
			return false
		}
	}
	return true
}

func validCanonicalAttributeKeys(values []AttributeKey) bool {
	for index, value := range values {
		if !value.valid() || (index > 0 && compareAttributeDeleteKey(values[index-1], value) >= 0) {
			return false
		}
		if index > 0 && attributePathPrefixConflict(values[index-1].entity, values[index-1].path, value.entity, value.path) {
			return false
		}
	}
	return true
}

func canonicalTupleKeys(values []TupleKey) []TupleKey {
	result := cloneSlice(values)
	sort.Slice(result, func(i, j int) bool { return compareTuple(result[i].tuple, result[j].tuple) < 0 })
	write := 0
	for _, value := range result {
		if write > 0 && compareTuple(result[write-1].tuple, value.tuple) == 0 {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func compareAttributeDeleteKey(left, right AttributeKey) int {
	for _, pair := range [][2]string{{left.entity.Type, right.entity.Type}, {left.entity.ID, right.entity.ID}} {
		if order := cmp.Compare(pair[0], pair[1]); order != 0 {
			return order
		}
	}
	return compareAttributePath(left.path, right.path)
}

func canonicalAttributeKeys(values []AttributeKey) ([]AttributeKey, error) {
	result := cloneSlice(values)
	sort.Slice(result, func(i, j int) bool { return compareAttributeDeleteKey(result[i], result[j]) < 0 })
	write := 0
	for _, value := range result {
		if write > 0 && compareAttributeDeleteKey(result[write-1], value) == 0 {
			continue
		}
		if write > 0 && attributePathPrefixConflict(result[write-1].entity, result[write-1].path, value.entity, value.path) {
			return nil, invalidArgument("same entity has conflicting attribute path prefixes")
		}
		result[write] = value
		write++
	}
	return result[:write], nil
}

func tupleWriteDeleteConflict(writes []RelationshipTuple, deletes []TupleKey) bool {
	writeIndex, deleteIndex := 0, 0
	for writeIndex < len(writes) && deleteIndex < len(deletes) {
		order := compareTuple(writes[writeIndex].tuple, deletes[deleteIndex].tuple)
		if order == 0 {
			return true
		}
		if order < 0 {
			writeIndex++
		} else {
			deleteIndex++
		}
	}
	return false
}

func attributeWriteDeleteConflict(writes []Attribute, deletes []AttributeKey) bool {
	writeIndex, deleteIndex := 0, 0
	for writeIndex < len(writes) && deleteIndex < len(deletes) {
		left := AttributeKey{entity: writes[writeIndex].entity, path: writes[writeIndex].path}
		order := compareAttributeDeleteKey(left, deletes[deleteIndex])
		if order == 0 || attributePathPrefixConflict(left.entity, left.path, deletes[deleteIndex].entity, deletes[deleteIndex].path) {
			return true
		}
		if order < 0 {
			writeIndex++
		} else {
			deleteIndex++
		}
	}
	return false
}

func compareAttributePath(left, right []string) int {
	for index := 0; index < len(left) && index < len(right); index++ {
		if order := cmp.Compare(left[index], right[index]); order != 0 {
			return order
		}
	}
	return cmp.Compare(len(left), len(right))
}

func attributePathPrefixConflict(leftEntity dsl.EntityRef, leftPath []string, rightEntity dsl.EntityRef, rightPath []string) bool {
	if leftEntity != rightEntity || len(leftPath) == len(rightPath) {
		return false
	}
	shorter, longer := leftPath, rightPath
	if len(shorter) > len(longer) {
		shorter, longer = longer, shorter
	}
	for index := range shorter {
		if shorter[index] != longer[index] {
			return false
		}
	}
	return true
}
