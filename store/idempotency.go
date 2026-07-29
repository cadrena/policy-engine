package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
)

// IdempotencyStore performs data mutations with namespace-and-operation scoped
// replay protection. The mutation, generation, idempotency record, and event
// must commit atomically.
type IdempotencyStore interface {
	WriteData(context.Context, policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error)
}

// IdempotencyOperation is a strict stable local mutation domain.
type IdempotencyOperation uint8

const (
	// IdempotencyWriteData scopes atomic tuple-and-attribute writes.
	IdempotencyWriteData IdempotencyOperation = iota + 1
)

// IdempotencyScope prevents key collisions across namespaces and operations.
type IdempotencyScope struct {
	namespace string
	operation IdempotencyOperation
	key       string
}

// NewIdempotencyScope validates and constructs an exact replay scope.
func NewIdempotencyScope(namespace string, operation IdempotencyOperation, key string) (IdempotencyScope, error) {
	if operation != IdempotencyWriteData {
		return IdempotencyScope{}, newError(policyengine.ErrorInvalidArgument)
	}
	if _, err := policyengine.NewResolveRequest(namespace, key); err != nil {
		return IdempotencyScope{}, err
	}
	return IdempotencyScope{namespace: namespace, operation: operation, key: key}, nil
}

// Namespace returns the exact opaque isolation scope.
func (s IdempotencyScope) Namespace() string { return s.namespace }

// Operation returns the independent mutation domain.
func (s IdempotencyScope) Operation() IdempotencyOperation { return s.operation }

// Key returns the caller-provided replay key.
func (s IdempotencyScope) Key() string { return s.key }

// Valid reports whether all scope dimensions are strict and non-zero.
func (s IdempotencyScope) Valid() bool {
	candidate, err := NewIdempotencyScope(s.namespace, s.operation, s.key)
	return err == nil && candidate == s
}

// IdempotencyFingerprint is a fixed-size canonical request digest. Formatting
// is always redacted; Bytes is the explicit raw access path.
type IdempotencyFingerprint struct {
	digest [sha256.Size]byte
	valid  bool
}

// Bytes returns a defensive copy of the fixed-size digest.
func (f IdempotencyFingerprint) Bytes() []byte {
	if !f.valid {
		return []byte{}
	}
	return append([]byte(nil), f.digest[:]...)
}

// Valid reports whether the fingerprint came from a canonical constructor.
func (f IdempotencyFingerprint) Valid() bool { return f.valid }

// FingerprintWriteData validates and hashes every mutation semantic except the
// idempotency key itself, which is represented by the returned scope.
func FingerprintWriteData(request policyengine.WriteDataRequest) (IdempotencyScope, IdempotencyFingerprint, error) {
	canonical, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            request.Namespace(),
		ValidationRevisionID: request.ValidationRevisionID(),
		ExpectedGeneration:   request.ExpectedGeneration(),
		IdempotencyKey:       request.IdempotencyKey(),
		TupleWrites:          request.TupleWrites(),
		TupleDeletes:         request.TupleDeletes(),
		AttributeWrites:      request.AttributeWrites(),
		AttributeDeletes:     request.AttributeDeletes(),
	})
	if err != nil {
		return IdempotencyScope{}, IdempotencyFingerprint{}, err
	}
	scope, err := NewIdempotencyScope(canonical.Namespace(), IdempotencyWriteData, canonical.IdempotencyKey())
	if err != nil {
		return IdempotencyScope{}, IdempotencyFingerprint{}, err
	}
	h := sha256.New()
	writeString(h, canonical.Namespace())
	writeString(h, canonical.ValidationRevisionID())
	writeUint64(h, canonical.ExpectedGeneration())
	for _, tuple := range canonical.TupleWrites() {
		writeTuple(h, tuple)
	}
	writeByte(h, 0xff)
	for _, key := range canonical.TupleDeletes() {
		writeDSLRelationship(h, key.Tuple())
	}
	writeByte(h, 0xfe)
	for _, attribute := range canonical.AttributeWrites() {
		writeAttribute(h, attribute)
	}
	writeByte(h, 0xfd)
	for _, key := range canonical.AttributeDeletes() {
		writeString(h, key.Entity().Type)
		writeString(h, key.Entity().ID)
		writeStrings(h, key.Path())
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return scope, IdempotencyFingerprint{digest: digest, valid: true}, nil
}

// IdempotencyRecord is the immutable original response retained for replay.
type IdempotencyRecord struct {
	scope       IdempotencyScope
	fingerprint IdempotencyFingerprint
	response    policyengine.WriteDataResponse
}

// NewIdempotencyRecord validates one original successful mutation response.
func NewIdempotencyRecord(
	scope IdempotencyScope,
	fingerprint IdempotencyFingerprint,
	response policyengine.WriteDataResponse,
) (IdempotencyRecord, error) {
	if !scope.Valid() || !fingerprint.Valid() || response.Generation() == 0 || response.Replayed() {
		return IdempotencyRecord{}, newError(policyengine.ErrorInvalidArgument)
	}
	if _, err := policyengine.NewWriteDataResponse(response.Generation(), false); err != nil {
		return IdempotencyRecord{}, err
	}
	return IdempotencyRecord{scope: scope, fingerprint: fingerprint, response: response}, nil
}

// Scope returns the exact namespace, operation, and key dimensions.
func (r IdempotencyRecord) Scope() IdempotencyScope { return r.scope }

// Fingerprint returns the immutable canonical request digest.
func (r IdempotencyRecord) Fingerprint() IdempotencyFingerprint { return r.fingerprint }

// Response returns the original successful mutation response.
func (r IdempotencyRecord) Response() policyengine.WriteDataResponse { return r.response }

// Valid reports whether this is a valid original replay record.
func (r IdempotencyRecord) Valid() bool {
	_, err := NewIdempotencyRecord(r.scope, r.fingerprint, r.response)
	return err == nil
}

func writeByte(h hash.Hash, value byte) {
	_, _ = h.Write([]byte{value})
}

func writeUint64(h hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func writeInt64(h hash.Hash, value int64) { writeUint64(h, uint64(value)) }

func writeString(h hash.Hash, value string) {
	writeUint64(h, uint64(len(value)))
	_, _ = h.Write([]byte(value))
}

func writeStrings(h hash.Hash, values []string) {
	writeUint64(h, uint64(len(values)))
	for _, value := range values {
		writeString(h, value)
	}
}

func writeDSLRelationship(h hash.Hash, tuple dsl.Tuple) {
	writeRelationshipFields(h, tuple.Resource.Type, tuple.Resource.ID, tuple.Relation,
		tuple.Subject.Type, tuple.Subject.ID, tuple.Subject.Relation)
}

func writeTuple(h hash.Hash, tuple policyengine.RelationshipTuple) {
	writeRelationshipFields(h, tuple.Tuple().Resource.Type, tuple.Tuple().Resource.ID, tuple.Tuple().Relation,
		tuple.Tuple().Subject.Type, tuple.Tuple().Subject.ID, tuple.Tuple().Subject.Relation)
	expiresAt, hasExpiry := tuple.ExpiresAt()
	if !hasExpiry {
		writeByte(h, 0)
		return
	}
	writeByte(h, 1)
	writeTime(h, expiresAt)
}

func writeTime(h hash.Hash, value time.Time) {
	encoded, err := value.UTC().MarshalBinary()
	if err != nil {
		// A validated time.Time can always be represented after UTC normalization.
		writeByte(h, 0)
		return
	}
	writeString(h, string(encoded))
}

func writeRelationshipFields(h hash.Hash, resourceType, resourceID, relation, subjectType, subjectID, subjectRelation string) {
	writeString(h, resourceType)
	writeString(h, resourceID)
	writeString(h, relation)
	writeString(h, subjectType)
	writeString(h, subjectID)
	writeString(h, subjectRelation)
}

func writeAttribute(h hash.Hash, attribute policyengine.Attribute) {
	writeString(h, attribute.Entity().Type)
	writeString(h, attribute.Entity().ID)
	writeStrings(h, attribute.Path())
	value := attribute.Value()
	writeByte(h, byte(value.Kind()))
	switch value.Kind() {
	case policyengine.ValueKindString:
		text, _ := value.StringValue()
		writeString(h, text)
	case policyengine.ValueKindInteger:
		integer, _ := value.Integer()
		writeInt64(h, integer)
	case policyengine.ValueKindBoolean:
		boolean, _ := value.Boolean()
		if boolean {
			writeByte(h, 1)
		} else {
			writeByte(h, 0)
		}
	case policyengine.ValueKindNull:
		writeByte(h, 0)
	}
}

func (IdempotencyScope) String() string { return redactedString("IdempotencyScope") }

// GoString returns a redacted Go-syntax representation.
func (IdempotencyScope) GoString() string { return redactedString("IdempotencyScope") }

// Format writes a redacted representation for every formatting verb.
func (IdempotencyScope) Format(s fmt.State, _ rune) { writeRedacted(s, "IdempotencyScope") }

// LogValue returns privacy-safe structured logging metadata.
func (IdempotencyScope) LogValue() slog.Value { return redactedLogValue("IdempotencyScope") }
func (IdempotencyFingerprint) String() string { return redactedString("IdempotencyFingerprint") }

// GoString returns a redacted Go-syntax representation.
func (IdempotencyFingerprint) GoString() string { return redactedString("IdempotencyFingerprint") }

// Format writes a redacted representation for every formatting verb.
func (IdempotencyFingerprint) Format(s fmt.State, _ rune) {
	writeRedacted(s, "IdempotencyFingerprint")
}

// LogValue returns privacy-safe structured logging metadata.
func (IdempotencyFingerprint) LogValue() slog.Value {
	return redactedLogValue("IdempotencyFingerprint")
}
func (IdempotencyRecord) String() string { return redactedString("IdempotencyRecord") }

// GoString returns a redacted Go-syntax representation.
func (IdempotencyRecord) GoString() string { return redactedString("IdempotencyRecord") }

// Format writes a redacted representation for every formatting verb.
func (IdempotencyRecord) Format(s fmt.State, _ rune) { writeRedacted(s, "IdempotencyRecord") }

// LogValue returns privacy-safe structured logging metadata.
func (IdempotencyRecord) LogValue() slog.Value { return redactedLogValue("IdempotencyRecord") }
