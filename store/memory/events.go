package memory

import (
	"context"
	"math"
	"sort"
	"time"

	policyengine "github.com/conductera/policy-engine"
)

// ListEvents returns retained namespace events in atomic commit order.
func (s *Store) ListEvents(ctx context.Context, request policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if _, err := policyengine.NewListEventsRequest(request.Namespace(), request.AfterCursor(), request.Limit()); err != nil {
		return policyengine.ListEventsResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	position, err := s.cursorPositionLocked(request.AfterCursor(), "event", request.Namespace(), "")
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	now, err := s.now()
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	s.mu.Lock()
	now = s.effectiveTimeLocked(now)
	s.pruneEventsLocked(request.Namespace(), now)
	state := s.events[request.Namespace()]
	values := []eventRecord{}
	expiredThrough := uint64(0)
	if state != nil {
		values = append(values, state.values...)
		expiredThrough = state.expiredThrough
	}
	s.mu.Unlock()
	if request.AfterCursor() != "" && position <= expiredThrough {
		return policyengine.ListEventsResponse{}, engineError(policyengine.ErrorCursorExpired)
	}
	start := sort.Search(len(values), func(i int) bool { return values[i].sequence > position })
	end := min(start+request.Limit(), len(values))
	page := make([]policyengine.StateEvent, 0, end-start)
	for _, event := range values[start:end] {
		page = append(page, event.value)
	}
	next := ""
	if end < len(values) {
		next = page[len(page)-1].Cursor()
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	return policyengine.NewListEventsResponse(request, page, next)
}

func (s *Store) newEventLocked(input policyengine.StateEventInput, occurredAt time.Time) (eventRecord, error) {
	sequence, err := s.nextEventSequenceLocked(input.Namespace)
	if err != nil {
		return eventRecord{}, err
	}
	cursor, err := s.newCursorLocked(cursorState{domain: "event", namespace: input.Namespace, position: sequence})
	if err != nil {
		return eventRecord{}, err
	}
	input.Cursor = cursor
	input.OccurredAt = occurredAt
	value, err := policyengine.NewStateEvent(input)
	if err != nil {
		return eventRecord{}, err
	}
	return eventRecord{sequence: sequence, value: value}, nil
}

func (s *Store) nextEventSequenceLocked(namespace string) (uint64, error) {
	highWater := uint64(0)
	state := s.events[namespace]
	if state != nil {
		highWater = state.expiredThrough
		if len(state.values) > 0 {
			highWater = max(highWater, state.values[len(state.values)-1].sequence)
		}
	}
	if highWater == math.MaxUint64 {
		return 0, engineError(policyengine.ErrorResourceExhausted)
	}
	return highWater + 1, nil
}

func (s *Store) appendEventLocked(event eventRecord, now time.Time) {
	namespace := event.value.Namespace()
	state := s.events[namespace]
	if state == nil {
		state = &eventState{}
		s.events[namespace] = state
	}
	state.values = append(state.values, event)
	s.pruneEventsLocked(namespace, now)
}

func (s *Store) pruneEventsLocked(namespace string, now time.Time) {
	state := s.events[namespace]
	if state == nil || len(state.values) == 0 {
		return
	}
	cutoff := now.Add(-defaultEventRetention)
	timeCut := sort.Search(len(state.values), func(index int) bool {
		return state.values[index].value.OccurredAt().After(cutoff)
	})
	countCut := max(0, len(state.values)-eventRetentionLimit)
	cut := max(timeCut, countCut)
	if cut == 0 {
		return
	}
	state.expiredThrough = max(state.expiredThrough, state.values[cut-1].sequence)
	state.values = append([]eventRecord(nil), state.values[cut:]...)
}

// expireEvents is a deterministic package-internal conformance control.
func (s *Store) expireEvents(ctx context.Context, namespace, throughCursor string) error {
	if err := safeContextError(ctx); err != nil {
		return err
	}
	position, err := s.cursorPositionLocked(throughCursor, "event", namespace, "")
	if err != nil {
		return err
	}
	if err := safeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.events[namespace]
	if state == nil {
		return engineError(policyengine.ErrorInvalidArgument)
	}
	cut := sort.Search(len(state.values), func(i int) bool { return state.values[i].sequence > position })
	state.values = append([]eventRecord(nil), state.values[cut:]...)
	state.expiredThrough = max(state.expiredThrough, position)
	return nil
}
