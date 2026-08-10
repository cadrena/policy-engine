package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"math"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

const idempotencyCodecFingerprint byte = 1

func encodeIdempotencyFingerprint(value store.IdempotencyFingerprint) ([]byte, error) {
	bytes := value.Bytes()
	if !value.Valid() || len(bytes) != sha256.Size {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := make([]byte, 1+len(bytes))
	encoded[0] = codecVersion
	copy(encoded[1:], bytes)
	return encoded, nil
}

func decodeIdempotencyFingerprint(encoded []byte) ([]byte, error) {
	if len(encoded) != 1+sha256.Size || encoded[0] != codecVersion {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	return append([]byte(nil), encoded[1:]...), nil
}

func encodeIdempotencyResponse(value policyengine.WriteDataResponse) ([]byte, error) {
	if value.Generation() == 0 || value.Replayed() {
		return nil, sqliteError(policyengine.ErrorIntegrity)
	}
	encoded := []byte{codecVersion, idempotencyCodecFingerprint}
	return appendCodecUint64(encoded, value.Generation()), nil
}

func decodeIdempotencyResponse(encoded []byte, replayed bool) (policyengine.WriteDataResponse, error) {
	reader := codecReader{data: encoded}
	version, ok := reader.byte()
	if !ok || version != codecVersion {
		return policyengine.WriteDataResponse{}, sqliteError(policyengine.ErrorIntegrity)
	}
	kind, ok := reader.byte()
	if !ok || kind != idempotencyCodecFingerprint {
		return policyengine.WriteDataResponse{}, sqliteError(policyengine.ErrorIntegrity)
	}
	generation, ok := reader.uint64()
	if !ok || !reader.done() {
		return policyengine.WriteDataResponse{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewWriteDataResponse(generation, replayed)
	if err != nil {
		return policyengine.WriteDataResponse{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}

func canonicalWriteDataRequest(value policyengine.WriteDataRequest) (policyengine.WriteDataRequest, error) {
	result, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            value.Namespace(),
		ValidationRevisionID: value.ValidationRevisionID(),
		ExpectedGeneration:   value.ExpectedGeneration(),
		IdempotencyKey:       value.IdempotencyKey(),
		TupleWrites:          value.TupleWrites(),
		TupleDeletes:         value.TupleDeletes(),
		AttributeWrites:      value.AttributeWrites(),
		AttributeDeletes:     value.AttributeDeletes(),
	})
	if err != nil {
		return policyengine.WriteDataRequest{}, mapError(context.Background(), err)
	}
	return result, nil
}

// WriteData validates and fingerprints before writer admission, then atomically
// persists exactly one data generation, one data event, and its replay record.
func (s *Store) WriteData(ctx context.Context, request policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	canonical, err := canonicalWriteDataRequest(request)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	_, fingerprint, err := store.FingerprintWriteData(canonical)
	if err != nil {
		return policyengine.WriteDataResponse{}, mapError(ctx, err)
	}
	fingerprintEncoded, err := encodeIdempotencyFingerprint(fingerprint)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if s == nil || s.db == nil {
		return policyengine.WriteDataResponse{}, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if observer := s.takeDataPreAdmissionObserver(); observer != nil {
		observer.dataPreAdmission(ctx)
	}
	if err := contextError(ctx); err != nil {
		return policyengine.WriteDataResponse{}, err
	}

	var response policyengine.WriteDataResponse
	err = s.db.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		storedFingerprint, storedResponse, found, err := readIdempotencyRecord(ctx, conn, canonical.Namespace(), canonical.IdempotencyKey())
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(storedFingerprint, fingerprint.Bytes()) {
				return sqliteError(policyengine.ErrorConflict)
			}
			response, err = policyengine.NewWriteDataResponse(storedResponse.Generation(), true)
			if err != nil {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			return nil
		}

		if _, exists, err := readRevision(ctx, conn, canonical.Namespace(), canonical.ValidationRevisionID()); err != nil {
			return err
		} else if !exists {
			return sqliteError(policyengine.ErrorNotFound)
		}
		head, err := s.ensureNamespaceHead(ctx, conn, canonical.Namespace())
		if err != nil {
			return err
		}
		if uint64(head.dataGeneration) != canonical.ExpectedGeneration() {
			return sqliteError(policyengine.ErrorConflict)
		}
		if head.dataGeneration == math.MaxInt64 {
			return sqliteError(policyengine.ErrorResourceExhausted)
		}
		nextGeneration := uint64(head.dataGeneration + 1)

		for _, key := range canonical.TupleDeletes() {
			if err := deleteTuple(ctx, conn, canonical.Namespace(), key); err != nil {
				return err
			}
		}
		for _, tuple := range canonical.TupleWrites() {
			if err := upsertTuple(ctx, conn, canonical.Namespace(), tuple); err != nil {
				return err
			}
		}
		for _, key := range canonical.AttributeDeletes() {
			if err := deleteAttribute(ctx, conn, canonical.Namespace(), key); err != nil {
				return err
			}
		}
		for _, attribute := range canonical.AttributeWrites() {
			if err := ensureNoAttributeConflict(ctx, conn, canonical.Namespace(), attribute); err != nil {
				return err
			}
			if err := upsertAttribute(ctx, conn, canonical.Namespace(), attribute); err != nil {
				return err
			}
		}

		occurredAt, err := s.effectiveNow(ctx, conn, canonical.Namespace())
		if err != nil {
			return err
		}
		response, err = policyengine.NewWriteDataResponse(nextGeneration, false)
		if err != nil {
			return sqliteError(policyengine.ErrorInternal)
		}
		responseEncoded, err := encodeIdempotencyResponse(response)
		if err != nil {
			return err
		}
		if err := s.appendStateEvent(ctx, conn, policyengine.StateEventInput{
			Namespace: canonical.Namespace(), Kind: policyengine.StateEventDataWritten, DataGeneration: nextGeneration,
		}, occurredAt); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO idempotency_records(namespace, idempotency_key, fingerprint, response) VALUES (?, ?, ?, ?)", canonical.Namespace(), canonical.IdempotencyKey(), fingerprintEncoded, responseEncoded); err != nil {
			return mapError(ctx, err)
		}
		if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET data_generation = ? WHERE namespace = ?", int64(nextGeneration), canonical.Namespace()); err != nil {
			return mapError(ctx, err)
		}
		return nil
	})
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if !response.Replayed() {
		s.notifyGenerationWaiters(canonical.Namespace())
	}
	return response, nil
}

func readIdempotencyRecord(ctx context.Context, conn *sql.Conn, namespace, key string) ([]byte, policyengine.WriteDataResponse, bool, error) {
	var encodedFingerprint, encodedResponse []byte
	err := conn.QueryRowContext(ctx, "SELECT fingerprint, response FROM idempotency_records WHERE namespace = ? AND idempotency_key = ?", namespace, key).Scan(&encodedFingerprint, &encodedResponse)
	if err == sql.ErrNoRows {
		return nil, policyengine.WriteDataResponse{}, false, nil
	}
	if err != nil {
		return nil, policyengine.WriteDataResponse{}, false, mapError(ctx, err)
	}
	fingerprint, err := decodeIdempotencyFingerprint(encodedFingerprint)
	if err != nil {
		return nil, policyengine.WriteDataResponse{}, false, err
	}
	response, err := decodeIdempotencyResponse(encodedResponse, false)
	if err != nil {
		return nil, policyengine.WriteDataResponse{}, false, err
	}
	return fingerprint, response, true, nil
}

func deleteTuple(ctx context.Context, conn *sql.Conn, namespace string, key policyengine.TupleKey) error {
	canonical, err := policyengine.NewTupleKey(key.Tuple())
	if err != nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	encoded, err := encodeTupleKey(canonical.Tuple())
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM tuples WHERE namespace = ? AND tuple_key = ?", namespace, encoded); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

func upsertTuple(ctx context.Context, conn *sql.Conn, namespace string, value policyengine.RelationshipTuple) error {
	record, err := canonicalDurableTuple(value)
	if err != nil {
		return err
	}
	tuple := record.tuple.Tuple()
	var expiry any
	if record.expiresAtNS.Valid {
		expiry = record.expiresAtNS.Int64
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO tuples(namespace, tuple_key, subject_type, subject_id, subject_relation, relation, resource_type, resource_id, expires_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(namespace, tuple_key) DO UPDATE SET subject_type = excluded.subject_type, subject_id = excluded.subject_id,
subject_relation = excluded.subject_relation, relation = excluded.relation, resource_type = excluded.resource_type,
resource_id = excluded.resource_id, expires_at_ns = excluded.expires_at_ns`,
		namespace, record.key, tuple.Subject.Type, tuple.Subject.ID, tuple.Subject.Relation, tuple.Relation, tuple.Resource.Type, tuple.Resource.ID, expiry,
	)
	if err != nil {
		return mapError(ctx, err)
	}
	return nil
}

func deleteAttribute(ctx context.Context, conn *sql.Conn, namespace string, value policyengine.AttributeKey) error {
	canonical, err := policyengine.NewAttributeKeyPath(value.Entity(), value.Path())
	if err != nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	key, err := encodeAttributeKey(canonical)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM attributes WHERE namespace = ? AND attribute_key = ?", namespace, key); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

func ensureNoAttributeConflict(ctx context.Context, conn *sql.Conn, namespace string, value policyengine.Attribute) error {
	key, err := attributeKeyFromAttribute(value)
	if err != nil {
		return err
	}
	path := key.Path()
	for length := 1; length < len(path); length++ {
		prefix, err := policyengine.NewAttributeKeyPath(key.Entity(), path[:length])
		if err != nil {
			return sqliteError(policyengine.ErrorInternal)
		}
		encoded, err := encodeAttributeKey(prefix)
		if err != nil {
			return err
		}
		var found int
		err = conn.QueryRowContext(ctx, "SELECT 1 FROM attributes WHERE namespace = ? AND attribute_key = ? LIMIT 1", namespace, encoded).Scan(&found)
		if err == nil {
			return sqliteError(policyengine.ErrorConflict)
		}
		if err != sql.ErrNoRows {
			return mapError(ctx, err)
		}
	}
	encoded, err := encodeAttributeKey(key)
	if err != nil {
		return err
	}
	var descendant int
	err = conn.QueryRowContext(ctx, "SELECT 1 FROM attribute_ancestors WHERE namespace = ? AND ancestor_path = ? LIMIT 1", namespace, encoded).Scan(&descendant)
	if err == nil {
		return sqliteError(policyengine.ErrorConflict)
	}
	if err != sql.ErrNoRows {
		return mapError(ctx, err)
	}
	return nil
}

func upsertAttribute(ctx context.Context, conn *sql.Conn, namespace string, value policyengine.Attribute) error {
	record, err := canonicalDurableAttribute(value)
	if err != nil {
		return err
	}
	entity := record.attribute.Entity()
	if _, err := conn.ExecContext(ctx, `INSERT INTO attributes(namespace, attribute_key, entity_type, entity_id, path, value, expires_at_ns)
VALUES (?, ?, ?, ?, ?, ?, NULL)
ON CONFLICT(namespace, attribute_key) DO UPDATE SET entity_type = excluded.entity_type, entity_id = excluded.entity_id,
path = excluded.path, value = excluded.value, expires_at_ns = excluded.expires_at_ns`,
		namespace, record.key, entity.Type, entity.ID, record.path, record.value,
	); err != nil {
		return mapError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM attribute_ancestors WHERE namespace = ? AND attribute_key = ?", namespace, record.key); err != nil {
		return mapError(ctx, err)
	}
	key, err := attributeKeyFromAttribute(record.attribute)
	if err != nil {
		return err
	}
	prefixes, err := strictAttributePrefixes(key)
	if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		if _, err := conn.ExecContext(ctx, "INSERT INTO attribute_ancestors(namespace, attribute_key, ancestor_path) VALUES (?, ?, ?)", namespace, record.key, prefix); err != nil {
			return mapError(ctx, err)
		}
	}
	return nil
}
