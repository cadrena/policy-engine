package memory

import (
	"context"
	"math"
	"sort"

	policyengine "github.com/cadrena/policy-engine"
)

// Activate performs an ABA-safe slot CAS and atomically appends history and an event.
func (s *Store) Activate(ctx context.Context, request policyengine.ActivateRequest) (policyengine.ActivateResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if _, err := policyengine.NewActivateRequest(request.Namespace(), request.Slot(), request.TargetRevisionID(), request.Expectation()); err != nil {
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	done, err := contextDone(ctx)
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	namespace := request.Namespace()
	slot := request.Slot()
	targetRevisionID := request.TargetRevisionID()
	expectation := request.Expectation()
	reservationKey := commitReservationKey{domain: "slot", namespace: namespace, name: slot}

	s.mu.Lock()
	reservation, reserved := s.reserveCommitLocked(reservationKey)
	if !reserved {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorConflict)
	}
	if _, ok := s.revisions[namespace][targetRevisionID]; !ok {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorNotFound)
	}
	bySlot := s.slots[namespace]
	state := bySlot[slot]
	if !activationExpectationMatches(expectation, state) {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorConflict)
	}
	generation := uint64(1)
	if state != nil {
		if state.current.Generation() == math.MaxUint64 {
			s.releaseCommitReservationLocked(reservation)
			s.mu.Unlock()
			return policyengine.ActivateResponse{}, engineError(policyengine.ErrorResourceExhausted)
		}
		generation = state.current.Generation() + 1
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.releaseCommitReservationLocked(reservation)
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, err
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
		return policyengine.ActivateResponse{}, contextWaitError(ctx)
	}
	if failEvent {
		s.mu.Lock()
		if !s.ownsCommitReservationLocked(reservation) {
			s.mu.Unlock()
			return policyengine.ActivateResponse{}, engineError(policyengine.ErrorInternal)
		}
		if s.failNextEvent {
			s.failNextEvent = false
			s.mu.Unlock()
			return policyengine.ActivateResponse{}, engineError(policyengine.ErrorUnavailable)
		}
		s.mu.Unlock()
	}
	now, err := s.now()
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if contextSignaled(done) {
		release()
		return policyengine.ActivateResponse{}, contextWaitError(ctx)
	}

	s.mu.Lock()
	if !s.ownsCommitReservationLocked(reservation) {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorInternal)
	}
	if contextSignaled(done) {
		s.mu.Unlock()
		release()
		return policyengine.ActivateResponse{}, contextWaitError(ctx)
	}
	if _, ok := s.revisions[namespace][targetRevisionID]; !ok {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorNotFound)
	}
	bySlot = s.slots[namespace]
	state = bySlot[slot]
	if !activationExpectationMatches(expectation, state) {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorConflict)
	}
	currentGeneration := uint64(1)
	if state != nil {
		if state.current.Generation() == math.MaxUint64 {
			s.mu.Unlock()
			return policyengine.ActivateResponse{}, engineError(policyengine.ErrorResourceExhausted)
		}
		currentGeneration = state.current.Generation() + 1
	}
	if currentGeneration != generation {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, engineError(policyengine.ErrorConflict)
	}
	if _, err := s.nextEventSequenceLocked(namespace); err != nil {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, err
	}
	now = s.effectiveTimeLocked(now)
	activation, err := policyengine.NewActivation(namespace, slot, targetRevisionID, generation, now)
	if err != nil {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, err
	}
	response, err := policyengine.NewActivateResponse(activation)
	if err != nil {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, err
	}
	event, err := s.newEventLocked(policyengine.StateEventInput{
		Namespace: namespace, Kind: policyengine.StateEventSlotActivated,
		RevisionID: targetRevisionID, Slot: slot, SlotGeneration: generation,
	}, now)
	if err != nil {
		s.mu.Unlock()
		return policyengine.ActivateResponse{}, err
	}
	if bySlot == nil {
		bySlot = make(map[string]*slotState)
		s.slots[namespace] = bySlot
	}
	if state == nil {
		state = &slotState{}
		bySlot[slot] = state
	}
	state.current = activation
	state.history = append(state.history, activation)
	if len(state.history) > activationHistoryRetention {
		state.history = append([]policyengine.Activation(nil), state.history[len(state.history)-activationHistoryRetention:]...)
	}
	s.appendEventLocked(event, now)
	s.mu.Unlock()
	release()
	return response, nil
}

func activationExpectationMatches(expectation policyengine.SlotExpectation, state *slotState) bool {
	if expectation.IsUnset() {
		return state == nil
	}
	revisionID, generation, active := expectation.Active()
	return active && state != nil && state.current.RevisionID() == revisionID && state.current.Generation() == generation
}

// Resolve returns the exact active revision and generation for a local slot.
func (s *Store) Resolve(ctx context.Context, request policyengine.ResolveRequest) (policyengine.ResolveResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	if _, err := policyengine.NewResolveRequest(request.Namespace(), request.Slot()); err != nil {
		return policyengine.ResolveResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	s.mu.Lock()
	state := s.slots[request.Namespace()][request.Slot()]
	var activation policyengine.Activation
	if state != nil {
		activation = state.current
	}
	s.mu.Unlock()
	if err := safeContextError(ctx); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	if state == nil {
		return policyengine.ResolveResponse{}, engineError(policyengine.ErrorNotFound)
	}
	return policyengine.NewResolveResponse(activation)
}

// ListActivationHistory returns retained ascending-generation slot history.
func (s *Store) ListActivationHistory(ctx context.Context, request policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	if _, err := policyengine.NewListActivationHistoryRequest(request.Namespace(), request.Slot(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListActivationHistoryResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	position, err := s.cursorPositionLocked(request.Cursor(), "history", request.Namespace(), request.Slot())
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	s.mu.Lock()
	state := s.slots[request.Namespace()][request.Slot()]
	history := []policyengine.Activation{}
	if state != nil {
		history = append(history, state.history...)
	}
	s.mu.Unlock()
	if request.Cursor() != "" && len(history) > 0 && position < history[0].Generation() {
		return policyengine.ListActivationHistoryResponse{}, engineError(policyengine.ErrorCursorExpired)
	}
	start := sort.Search(len(history), func(i int) bool { return history[i].Generation() > position })
	end := min(start+request.Limit(), len(history))
	page := append([]policyengine.Activation(nil), history[start:end]...)
	next := ""
	if end < len(history) {
		next, err = s.newCursorLocked(cursorState{
			domain: "history", namespace: request.Namespace(), slot: request.Slot(), position: page[len(page)-1].Generation(),
		})
		if err != nil {
			return policyengine.ListActivationHistoryResponse{}, err
		}
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	return policyengine.NewListActivationHistoryResponse(request, page, next)
}
