package sqlite

import (
	"bytes"
	"database/sql"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// encodeTupleKey stores the relationship identity in a versioned canonical
// form. Expiry intentionally is not part of the key: a tuple write replaces
// the expiry for its exact relationship identity.
func encodeTupleKey(value dsl.Tuple) ([]byte, error) {
	key, err := policyengine.NewTupleKey(value)
	if err != nil {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	tuple := key.Tuple()
	encoded := make([]byte, 0, 1+12+len(tuple.Resource.Type)+len(tuple.Resource.ID)+len(tuple.Relation)+len(tuple.Subject.Type)+len(tuple.Subject.ID)+len(tuple.Subject.Relation))
	encoded = append(encoded, codecVersion)
	encoded = appendCodecString16(encoded, tuple.Resource.Type)
	encoded = appendCodecString16(encoded, tuple.Resource.ID)
	encoded = appendCodecString16(encoded, tuple.Relation)
	encoded = appendCodecString16(encoded, tuple.Subject.Type)
	encoded = appendCodecString16(encoded, tuple.Subject.ID)
	encoded = appendCodecString16(encoded, tuple.Subject.Relation)
	return encoded, nil
}

func decodeTupleKey(encoded []byte) (dsl.Tuple, error) {
	reader := codecReader{data: encoded}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	resourceType, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	resourceID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	relation, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	subjectType, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	subjectID, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	subjectRelation, ok := reader.string16(policyengine.MaxIdentifierBytes)
	if !ok || !reader.done() {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	key, err := policyengine.NewTupleKey(dsl.Tuple{
		Resource: dsl.EntityRef{Type: resourceType, ID: resourceID}, Relation: relation,
		Subject: dsl.SubjectRef{Type: subjectType, ID: subjectID, Relation: subjectRelation},
	})
	if err != nil {
		return dsl.Tuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return key.Tuple(), nil
}

type durableTuple struct {
	key         []byte
	tuple       policyengine.RelationshipTuple
	expiresAtNS sql.NullInt64
}

func canonicalDurableTuple(value policyengine.RelationshipTuple) (durableTuple, error) {
	expiresAt, hasExpiry := value.ExpiresAt()
	var expiry *time.Time
	var expiresAtNS sql.NullInt64
	if hasExpiry {
		canonical, nanos, ok := sqliteTimestamp(expiresAt)
		if !ok {
			return durableTuple{}, sqliteError(policyengine.ErrorInvalidArgument)
		}
		expiry = &canonical
		expiresAtNS = sql.NullInt64{Int64: nanos, Valid: true}
	}
	canonical, err := policyengine.NewRelationshipTuple(value.Tuple(), expiry)
	if err != nil {
		return durableTuple{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	key, err := encodeTupleKey(canonical.Tuple())
	if err != nil {
		return durableTuple{}, err
	}
	return durableTuple{key: key, tuple: canonical, expiresAtNS: expiresAtNS}, nil
}

func decodeDurableTuple(
	key []byte,
	subjectType, subjectID, subjectRelation, relation, resourceType, resourceID string,
	expiresAtNS sql.NullInt64,
) (policyengine.RelationshipTuple, error) {
	tuple := dsl.Tuple{
		Resource: dsl.EntityRef{Type: resourceType, ID: resourceID}, Relation: relation,
		Subject: dsl.SubjectRef{Type: subjectType, ID: subjectID, Relation: subjectRelation},
	}
	var expiry *time.Time
	if expiresAtNS.Valid {
		candidate := time.Unix(0, expiresAtNS.Int64).UTC()
		canonical, nanos, ok := sqliteTimestamp(candidate)
		if !ok || nanos != expiresAtNS.Int64 {
			return policyengine.RelationshipTuple{}, sqliteError(policyengine.ErrorIntegrity)
		}
		expiry = &canonical
	}
	result, err := policyengine.NewRelationshipTuple(tuple, expiry)
	if err != nil {
		return policyengine.RelationshipTuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	expected, err := encodeTupleKey(result.Tuple())
	if err != nil || !bytes.Equal(expected, key) {
		return policyengine.RelationshipTuple{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}
