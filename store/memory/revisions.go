package memory

import (
	"bytes"
	"context"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

// PutRevision verifies and atomically stores one immutable content-addressed artifact.
func (s *Store) PutRevision(ctx context.Context, write store.RevisionWrite) (store.PutRevisionResult, error) {
	if err := safeContextError(ctx); err != nil {
		return store.PutRevisionResult{}, err
	}
	if !write.Valid() {
		return store.PutRevisionResult{}, engineError(policyengine.ErrorInvalidArgument)
	}
	metadata := write.Metadata()
	artifact := write.Artifact()
	record, err := store.NewRevisionRecord(metadata, artifact)
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	createdResult, err := store.NewPutRevisionResult(record, true)
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	done, err := contextDone(ctx)
	if err != nil {
		return store.PutRevisionResult{}, err
	}

	namespace := metadata.Namespace()
	// Revision publication shares one namespace-ordered event stream. Reserve
	// the whole revision domain for a namespace so a second publication cannot
	// overtake a blocked one while its cancellation is being observed.
	reservationKey := commitReservationKey{domain: "revision", namespace: namespace}
	s.mu.Lock()
	reservation, reserved := s.reserveCommitLocked(reservationKey)
	if !reserved {
		s.mu.Unlock()
		return store.PutRevisionResult{}, engineError(policyengine.ErrorUnavailable)
	}
	if existing, ok := s.revisions[namespace][metadata.ID()]; ok {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		if !bytes.Equal(existing.Artifact(), artifact) {
			return store.PutRevisionResult{}, engineError(policyengine.ErrorIntegrity)
		}
		return store.NewPutRevisionResult(existing, false)
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return store.PutRevisionResult{}, err
	}
	failEvent := s.failNextEvent
	s.mu.Unlock()

	held := true
	release := func() {
		if held {
			s.releaseCommitReservation(reservation)
			held = false
		}
	}
	defer release()
	if contextSignaled(done) {
		release()
		return store.PutRevisionResult{}, contextWaitError(ctx)
	}
	if failEvent {
		s.mu.Lock()
		if !s.ownsCommitReservationLocked(reservation) {
			s.mu.Unlock()
			return store.PutRevisionResult{}, engineError(policyengine.ErrorInternal)
		}
		if s.failNextEvent {
			s.failNextEvent = false
			s.mu.Unlock()
			return store.PutRevisionResult{}, engineError(policyengine.ErrorUnavailable)
		}
		s.mu.Unlock()
	}
	now, err := s.now()
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	if contextSignaled(done) {
		release()
		return store.PutRevisionResult{}, contextWaitError(ctx)
	}

	s.mu.Lock()
	if !s.ownsCommitReservationLocked(reservation) {
		s.mu.Unlock()
		return store.PutRevisionResult{}, engineError(policyengine.ErrorInternal)
	}
	if contextSignaled(done) {
		s.mu.Unlock()
		release()
		return store.PutRevisionResult{}, contextWaitError(ctx)
	}
	byID := s.revisions[namespace]
	if existing, ok := byID[metadata.ID()]; ok {
		s.mu.Unlock()
		if !bytes.Equal(existing.Artifact(), artifact) {
			return store.PutRevisionResult{}, engineError(policyengine.ErrorIntegrity)
		}
		return store.NewPutRevisionResult(existing, false)
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.mu.Unlock()
		return store.PutRevisionResult{}, err
	}
	now = s.effectiveTimeLocked(now)
	event, err := s.newEventLocked(policyengine.StateEventInput{
		Namespace: namespace, Kind: policyengine.StateEventRevisionPublished, RevisionID: record.Metadata().ID(),
	}, now)
	if err != nil {
		s.mu.Unlock()
		return store.PutRevisionResult{}, err
	}
	ordered := revisionSet(s.revisionOrder[namespace], record)
	if byID == nil {
		byID = make(map[string]store.RevisionRecord)
		s.revisions[namespace] = byID
	}
	byID[record.Metadata().ID()] = record
	s.revisionOrder[namespace] = ordered
	s.appendEventLocked(event, now)
	s.mu.Unlock()
	release()
	return createdResult, nil
}

// GetRevision returns one verified immutable revision in the requested namespace.
func (s *Store) GetRevision(ctx context.Context, request policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	if err := safeContextError(ctx); err != nil {
		return store.RevisionRecord{}, err
	}
	if _, err := policyengine.NewGetRevisionRequest(request.Namespace(), request.RevisionID()); err != nil {
		return store.RevisionRecord{}, engineError(policyengine.ErrorInvalidArgument)
	}
	if err := safeContextError(ctx); err != nil {
		return store.RevisionRecord{}, err
	}
	s.mu.Lock()
	record, ok := s.revisions[request.Namespace()][request.RevisionID()]
	s.mu.Unlock()
	if err := safeContextError(ctx); err != nil {
		return store.RevisionRecord{}, err
	}
	if !ok {
		return store.RevisionRecord{}, engineError(policyengine.ErrorNotFound)
	}
	return record, nil
}

// ListRevisions returns deterministic publication-time and revision-ID ordered pages.
func (s *Store) ListRevisions(ctx context.Context, request policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	if _, err := policyengine.NewListRevisionsRequest(request.Namespace(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListRevisionsResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	cursor, err := s.cursorStateLocked(request.Cursor(), "revision", request.Namespace(), "")
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	s.mu.Lock()
	root := s.revisionOrder[request.Namespace()]
	s.mu.Unlock()
	metadata := make([]policyengine.RevisionMetadata, 0, request.Limit())
	_, more := revisionPage(
		root,
		revisionKey{publishedAt: cursor.revisionPublishedAt, id: cursor.revisionID},
		request.Cursor() != "",
		request.Limit(),
		func(record store.RevisionRecord) bool {
			metadata = append(metadata, record.Metadata())
			return true
		},
	)
	next := ""
	if more {
		last := metadata[len(metadata)-1]
		next, err = s.newCursorLocked(cursorState{
			domain:              "revision",
			namespace:           request.Namespace(),
			revisionPublishedAt: last.PublishedAt(),
			revisionID:          last.ID(),
		})
		if err != nil {
			return policyengine.ListRevisionsResponse{}, err
		}
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	return policyengine.NewListRevisionsResponse(request, metadata, next)
}
