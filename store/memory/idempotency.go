package memory

import (
	"bytes"
	"context"
	"math"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

// WriteData atomically commits structurally-shared tuple and attribute indexes,
// generation, idempotency record, and one state event.
func (s *Store) WriteData(ctx context.Context, request policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	_, fingerprint, err := store.FingerprintWriteData(request)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	fingerprintBytes := fingerprint.Bytes()
	done, err := contextDone(ctx)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if pause := s.consumeDataCommitPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-done:
			return policyengine.WriteDataResponse{}, contextWaitError(ctx)
		}
	}
	if contextSignaled(done) {
		return policyengine.WriteDataResponse{}, contextWaitError(ctx)
	}

	namespace := request.Namespace()
	reservationKey := commitReservationKey{domain: "data", namespace: namespace}

reserve:
	if contextSignaled(done) {
		return policyengine.WriteDataResponse{}, contextWaitError(ctx)
	}
	s.mu.Lock()
	reservation, reserved := s.reserveCommitLocked(reservationKey)
	if !reserved {
		pending := s.reservations[reservationKey]
		if pending != nil && pending.operation == "data" &&
			pending.idempotencyKey == request.IdempotencyKey() &&
			bytes.Equal(pending.fingerprint, fingerprintBytes) {
			completed := pending.done
			s.mu.Unlock()
			select {
			case <-completed:
				goto reserve
			case <-done:
				return policyengine.WriteDataResponse{}, contextWaitError(ctx)
			}
		}
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
	}
	reservation.operation = "data"
	reservation.idempotencyKey = request.IdempotencyKey()
	reservation.fingerprint = append([]byte(nil), fingerprintBytes...)
	state := s.data[namespace]
	if previous, ok := idempotencyRecord(state, request.IdempotencyKey()); ok {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		if !bytes.Equal(previous.fingerprint, fingerprintBytes) {
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
		}
		return policyengine.NewWriteDataResponse(previous.response.Generation(), true)
	}
	if _, ok := s.revisions[namespace][request.ValidationRevisionID()]; !ok {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorNotFound)
	}
	currentGeneration := uint64(0)
	var base *dataVersion
	if state != nil {
		currentGeneration = state.generation
		base = state.current
	}
	if currentGeneration != request.ExpectedGeneration() {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
	}
	if currentGeneration == math.MaxUint64 {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorResourceExhausted)
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, err
	}
	if base == nil {
		base = &dataVersion{generation: currentGeneration}
	}
	tupleRoot := base.tuples
	attributeRoot := base.attributes
	for _, key := range request.TupleDeletes() {
		tupleRoot = tupleDelete(tupleRoot, key.Tuple())
	}
	for _, tuple := range request.TupleWrites() {
		tupleRoot = tupleSet(tupleRoot, tuple.Tuple(), tuple)
	}
	for _, key := range request.AttributeDeletes() {
		attributeRoot = attributeDelete(attributeRoot, key)
	}
	for _, attribute := range request.AttributeWrites() {
		var ok bool
		attributeRoot, ok = attributeSet(attributeRoot, attribute)
		if !ok {
			s.releaseCommitReservationLocked(reservation)
			s.mu.Unlock()
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
		}
	}
	generation := currentGeneration + 1
	candidate := &dataVersion{generation: generation, tuples: tupleRoot, attributes: attributeRoot}
	response, err := policyengine.NewWriteDataResponse(generation, false)
	if err != nil {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, err
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
		return policyengine.WriteDataResponse{}, contextWaitError(ctx)
	}
	if failEvent {
		s.mu.Lock()
		if !s.ownsCommitReservationLocked(reservation) {
			s.mu.Unlock()
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorInternal)
		}
		if s.failNextEvent {
			s.failNextEvent = false
			s.mu.Unlock()
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorUnavailable)
		}
		s.mu.Unlock()
	}
	now, err := s.now()
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if contextSignaled(done) {
		release()
		return policyengine.WriteDataResponse{}, contextWaitError(ctx)
	}

	s.mu.Lock()
	if !s.ownsCommitReservationLocked(reservation) {
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorInternal)
	}
	if contextSignaled(done) {
		s.mu.Unlock()
		release()
		return policyengine.WriteDataResponse{}, contextWaitError(ctx)
	}
	// Clock.Now ran without Store.mu. Revalidate every authoritative commit
	// precondition before publishing the candidate.
	state = s.data[namespace]
	if state == nil {
		if request.ExpectedGeneration() != 0 || base.generation != 0 {
			s.mu.Unlock()
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
		}
	} else if state.generation != request.ExpectedGeneration() || state.current != base {
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
	}
	if _, ok := s.revisions[namespace][request.ValidationRevisionID()]; !ok {
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorNotFound)
	}
	if previous, ok := idempotencyRecord(state, request.IdempotencyKey()); ok {
		s.mu.Unlock()
		if !bytes.Equal(previous.fingerprint, fingerprintBytes) {
			return policyengine.WriteDataResponse{}, engineError(policyengine.ErrorConflict)
		}
		return policyengine.NewWriteDataResponse(previous.response.Generation(), true)
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, err
	}
	now = s.effectiveTimeLocked(now)
	event, err := s.newEventLocked(policyengine.StateEventInput{
		Namespace: namespace, Kind: policyengine.StateEventDataWritten, DataGeneration: generation,
	}, now)
	if err != nil {
		s.mu.Unlock()
		return policyengine.WriteDataResponse{}, err
	}
	if state == nil {
		state = &dataState{current: base, idempotency: make(map[string]idempotencyState)}
		s.data[namespace] = state
	}
	state.generation = generation
	state.current = candidate
	state.idempotency[request.IdempotencyKey()] = idempotencyState{
		fingerprint: fingerprintBytes, response: response,
	}
	s.notifyGenerationWaitersLocked(namespace)
	s.appendEventLocked(event, now)
	s.mu.Unlock()
	release()
	return response, nil
}

func idempotencyRecord(state *dataState, key string) (idempotencyState, bool) {
	if state == nil {
		return idempotencyState{}, false
	}
	value, ok := state.idempotency[key]
	return value, ok
}
