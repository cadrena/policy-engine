package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// revisionLifecycleObserver is an optional, instance-local lifecycle observer.
// It cannot return an error or change storage results. The nil default has no
// behavior; package tests install a channel-backed observer for deterministic
// contention and pre-admission ordering checks only.
type revisionLifecycleObserver interface {
	ownerEntered(context.Context)
	contended()
	waiterWoke(context.Context)
	dataPreAdmission(context.Context)
}

type revisionReservationSet struct {
	mu       sync.Mutex
	active   map[string]*revisionReservation
	observer revisionLifecycleObserver
}

type revisionReservation struct {
	done     chan struct{}
	observer revisionLifecycleObserver
}

func (s *Store) acquireRevisionReservation(ctx context.Context, namespace string) (*revisionReservation, error) {
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		s.revisions.mu.Lock()
		if s.revisions.active == nil {
			s.revisions.active = make(map[string]*revisionReservation)
		}
		if current := s.revisions.active[namespace]; current != nil {
			observer := current.observer
			done := current.done
			s.revisions.mu.Unlock()
			if observer != nil {
				observer.contended()
			}
			select {
			case <-done:
				if observer != nil {
					observer.waiterWoke(ctx)
				}
				if err := contextError(ctx); err != nil {
					return nil, err
				}
				continue
			case <-ctx.Done():
				return nil, contextError(ctx)
			}
		}
		reservation := &revisionReservation{done: make(chan struct{}), observer: s.revisions.observer}
		s.revisions.observer = nil
		s.revisions.active[namespace] = reservation
		s.revisions.mu.Unlock()
		return reservation, nil
	}
}

func (s *Store) releaseRevisionReservation(namespace string, reservation *revisionReservation) {
	if reservation == nil {
		return
	}
	s.revisions.mu.Lock()
	if s.revisions.active[namespace] == reservation {
		delete(s.revisions.active, namespace)
		close(reservation.done)
	}
	s.revisions.mu.Unlock()
}

// takeDataPreAdmissionObserver consumes the existing private lifecycle seam
// for one validated WriteData call. It is deliberately instance-local and
// nil-by-default; the observer can only delay a test call and cannot alter
// storage errors, values, or commit ordering.
func (s *Store) takeDataPreAdmissionObserver() revisionLifecycleObserver {
	if s == nil {
		return nil
	}
	s.revisions.mu.Lock()
	observer := s.revisions.observer
	s.revisions.observer = nil
	s.revisions.mu.Unlock()
	return observer
}

// PutRevision verifies and atomically stores one immutable content-addressed
// artifact. A canonical equivalent retry returns the immutable first record and
// does not append a second event.
func (s *Store) PutRevision(ctx context.Context, write store.RevisionWrite) (store.PutRevisionResult, error) {
	if err := contextError(ctx); err != nil {
		return store.PutRevisionResult{}, err
	}
	record, publishedAtNS, provenance, err := canonicalRevisionRecord(write)
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	created, err := store.NewPutRevisionResult(record, true)
	if err != nil {
		return store.PutRevisionResult{}, sqliteError(policyengine.ErrorInternal)
	}
	reservation, err := s.acquireRevisionReservation(ctx, record.Metadata().Namespace())
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	defer s.releaseRevisionReservation(record.Metadata().Namespace(), reservation)

	var existing store.RevisionRecord
	found := false
	err = s.db.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		if reservation.observer != nil {
			reservation.observer.ownerEntered(ctx)
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		stored, exists, err := readRevision(ctx, conn, record.Metadata().Namespace(), record.Metadata().ID())
		if err != nil {
			return err
		}
		if exists {
			if !bytes.Equal(stored.Artifact(), record.Artifact()) {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			existing = stored
			found = true
			return nil
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO revisions(namespace, revision_id, artifact, provenance, published_at_ns) VALUES (?, ?, ?, ?, ?)", record.Metadata().Namespace(), record.Metadata().ID(), record.Artifact(), provenance, publishedAtNS); err != nil {
			return mapError(ctx, err)
		}
		occurredAt, err := s.effectiveNow(ctx, conn, record.Metadata().Namespace())
		if err != nil {
			return err
		}
		return s.appendStateEvent(ctx, conn, policyengine.StateEventInput{
			Namespace: record.Metadata().Namespace(), Kind: policyengine.StateEventRevisionPublished, RevisionID: record.Metadata().ID(),
		}, occurredAt)
	})
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	if found {
		return store.NewPutRevisionResult(existing, false)
	}
	return created, nil
}

func canonicalRevisionRecord(write store.RevisionWrite) (store.RevisionRecord, int64, []byte, error) {
	if !write.Valid() {
		return store.RevisionRecord{}, 0, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	metadata := write.Metadata()
	id, err := policyengine.ParseRevisionID(metadata.ID())
	if err != nil {
		return store.RevisionRecord{}, 0, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	publishedAt, publishedAtNS, ok := sqliteTimestamp(metadata.PublishedAt())
	if !ok {
		return store.RevisionRecord{}, 0, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	canonicalMetadata, err := policyengine.NewRevisionMetadata(metadata.Namespace(), id, publishedAt)
	if err != nil {
		return store.RevisionRecord{}, 0, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	provenance := write.Provenance()
	artifact := write.Artifact()
	var canonicalWrite store.RevisionWrite
	if provenance.Valid() {
		canonicalWrite, err = store.NewRevisionWriteWithProvenance(canonicalMetadata, artifact, provenance)
	} else {
		canonicalWrite, err = store.NewRevisionWrite(canonicalMetadata, artifact)
	}
	if err != nil {
		return store.RevisionRecord{}, 0, nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	record, err := store.NewRevisionRecordFromWrite(canonicalWrite)
	if err != nil {
		return store.RevisionRecord{}, 0, nil, err
	}
	encodedProvenance, err := encodeRevisionProvenance(record.Provenance())
	if err != nil {
		return store.RevisionRecord{}, 0, nil, err
	}
	return record, publishedAtNS, encodedProvenance, nil
}

// GetRevision returns one verified immutable revision in the requested
// namespace without revealing cross-namespace existence.
func (s *Store) GetRevision(ctx context.Context, request policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	if err := contextError(ctx); err != nil {
		return store.RevisionRecord{}, err
	}
	if _, err := policyengine.NewGetRevisionRequest(request.Namespace(), request.RevisionID()); err != nil {
		return store.RevisionRecord{}, mapError(ctx, err)
	}
	var result store.RevisionRecord
	found := false
	err := s.read(ctx, func(database *sql.DB) error {
		value, exists, err := readRevision(ctx, database, request.Namespace(), request.RevisionID())
		if err != nil {
			return err
		}
		result, found = value, exists
		return nil
	})
	if err != nil {
		return store.RevisionRecord{}, err
	}
	if !found {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorNotFound)
	}
	return result, nil
}

func readRevision(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, namespace, revisionID string) (store.RevisionRecord, bool, error) {
	var artifact, provenance []byte
	var publishedAtNS int64
	err := queryer.QueryRowContext(ctx, "SELECT artifact, provenance, published_at_ns FROM revisions WHERE namespace = ? AND revision_id = ?", namespace, revisionID).Scan(&artifact, &provenance, &publishedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return store.RevisionRecord{}, false, nil
	}
	if err != nil {
		return store.RevisionRecord{}, false, mapError(ctx, err)
	}
	record, err := decodeRevisionRecord(namespace, revisionID, artifact, provenance, publishedAtNS)
	if err != nil {
		return store.RevisionRecord{}, false, err
	}
	return record, true, nil
}

func decodeRevisionRecord(namespace, revisionID string, artifact, provenance []byte, publishedAtNS int64) (store.RevisionRecord, error) {
	if len(artifact) == 0 || len(artifact) > policyengine.MaxPolicyArtifactBytes {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorIntegrity)
	}
	id, err := policyengine.ParseRevisionID(revisionID)
	if err != nil {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorIntegrity)
	}
	publishedAt := time.Unix(0, publishedAtNS).UTC()
	metadata, err := policyengine.NewRevisionMetadata(namespace, id, publishedAt)
	if err != nil {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorIntegrity)
	}
	decodedProvenance, err := decodeRevisionProvenance(namespace, provenance)
	if err != nil {
		return store.RevisionRecord{}, err
	}
	var write store.RevisionWrite
	if decodedProvenance.Valid() {
		write, err = store.NewRevisionWriteWithProvenance(metadata, artifact, decodedProvenance)
	} else {
		write, err = store.NewRevisionWrite(metadata, artifact)
	}
	if err != nil {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorIntegrity)
	}
	record, err := store.NewRevisionRecordFromWrite(write)
	if err != nil {
		return store.RevisionRecord{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return record, nil
}

// ListRevisions returns deterministic publication-time and revision-ID ordered
// namespace pages.
func (s *Store) ListRevisions(ctx context.Context, request policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	if _, err := policyengine.NewListRevisionsRequest(request.Namespace(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListRevisionsResponse{}, mapError(ctx, err)
	}
	cursor, err := s.decodeCursor(request.Cursor(), cursorDomainRevision, request.Namespace(), "")
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	cursorNS := int64(0)
	if request.Cursor() != "" {
		var ok bool
		_, cursorNS, ok = sqliteTimestamp(cursor.revisionPublishedAt)
		if !ok {
			return policyengine.ListRevisionsResponse{}, sqliteError(policyengine.ErrorInvalidArgument)
		}
	}
	metadata := make([]policyengine.RevisionMetadata, 0, request.Limit()+1)
	err = s.read(ctx, func(database *sql.DB) error {
		var rows *sql.Rows
		var err error
		if request.Cursor() == "" {
			rows, err = database.QueryContext(ctx, "SELECT revision_id, published_at_ns FROM revisions WHERE namespace = ? ORDER BY published_at_ns ASC, revision_id ASC LIMIT ?", request.Namespace(), request.Limit()+1)
		} else {
			rows, err = database.QueryContext(ctx, "SELECT revision_id, published_at_ns FROM revisions WHERE namespace = ? AND (published_at_ns > ? OR (published_at_ns = ? AND revision_id > ?)) ORDER BY published_at_ns ASC, revision_id ASC LIMIT ?", request.Namespace(), cursorNS, cursorNS, cursor.revisionID, request.Limit()+1)
		}
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var revisionID string
			var publishedAtNS int64
			if err := rows.Scan(&revisionID, &publishedAtNS); err != nil {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			value, err := decodeRevisionMetadataColumns(request.Namespace(), revisionID, publishedAtNS)
			if err != nil {
				return err
			}
			metadata = append(metadata, value)
		}
		return rows.Err()
	})
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	more := len(metadata) > request.Limit()
	if more {
		metadata = metadata[:request.Limit()]
	}
	next := ""
	if more {
		last := metadata[len(metadata)-1]
		next, err = s.newCursor(cursorState{
			domain: cursorDomainRevision, namespace: request.Namespace(), revisionPublishedAt: last.PublishedAt(), revisionID: last.ID(),
		})
		if err != nil {
			return policyengine.ListRevisionsResponse{}, err
		}
	}
	return policyengine.NewListRevisionsResponse(request, metadata, next)
}

func decodeRevisionMetadataColumns(namespace, revisionID string, publishedAtNS int64) (policyengine.RevisionMetadata, error) {
	id, err := policyengine.ParseRevisionID(revisionID)
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewRevisionMetadata(namespace, id, time.Unix(0, publishedAtNS).UTC())
	if err != nil {
		return policyengine.RevisionMetadata{}, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, nil
}
