package conformance_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
	"github.com/conductera/policy-engine/store/conformance"
)

const referenceHistoryRetention = 3

type referenceModel struct {
	mu sync.Mutex

	revisions            map[string]map[string]store.RevisionRecord
	revisionReservations map[string]*referenceRevisionReservation
	slots                map[string]map[string]*referenceSlot
	data                 map[string]*referenceData
	events               map[string]*referenceEvents
	cursors              map[string]referenceCursor
	cursorSeq            uint64

	failNextEvent     bool
	blockNextRead     bool
	nextReadPause     *referenceReadPause
	nextDataPause     *referenceReadPause
	nextRevisionPause *referenceReadPause
}

type referenceReadPause struct {
	entered       chan struct{}
	contended     chan struct{}
	release       chan struct{}
	enteredOnce   sync.Once
	contendedOnce sync.Once
	releaseOnce   sync.Once
}

type referenceRevisionReservation struct {
	done  chan struct{}
	pause *referenceReadPause
}

type referenceSlot struct {
	current policyengine.Activation
	history []policyengine.Activation
}

type referenceData struct {
	generation  uint64
	tuples      map[dsl.Tuple]policyengine.RelationshipTuple
	attributes  map[referenceAttributeKey]policyengine.Attribute
	idempotency map[string]referenceIdempotency
	changed     chan struct{}
}

type referenceIdempotency struct {
	fingerprint []byte
	response    policyengine.WriteDataResponse
}

type referenceEvents struct {
	values         []referenceEvent
	expiredThrough uint64
}

type referenceEvent struct {
	sequence uint64
	value    policyengine.StateEvent
}

type referenceCursor struct {
	domain    string
	namespace string
	slot      string
	position  uint64
}

type referenceAttributeKey struct {
	entity dsl.EntityRef
	path   string
}

var _ store.Store = (*referenceModel)(nil)
var _ store.Snapshot = (*referenceSnapshot)(nil)

func newReferenceFixture(testing.TB) conformance.Fixture {
	model := &referenceModel{
		revisions:            make(map[string]map[string]store.RevisionRecord),
		revisionReservations: make(map[string]*referenceRevisionReservation),
		slots:                make(map[string]map[string]*referenceSlot),
		data:                 make(map[string]*referenceData),
		events:               make(map[string]*referenceEvents),
		cursors:              make(map[string]referenceCursor),
	}
	return conformance.Fixture{
		Store:                      model,
		ActivationHistoryRetention: referenceHistoryRetention,
		ArmNextEventAppendFailure:  model.armNextEventFailure,
		ArmNextSnapshotReadBlock:   model.armNextSnapshotReadBlock,
		PauseNextSnapshotRead:      model.pauseNextSnapshotRead,
		PauseNextDataCommit:        model.pauseNextDataCommit,
		PauseNextRevisionCommit:    model.pauseNextRevisionCommit,
		ExpireEvents:               model.expireEvents,
	}
}

func (m *referenceModel) PutRevision(ctx context.Context, write store.RevisionWrite) (store.PutRevisionResult, error) {
	if err := store.ContextError(ctx); err != nil {
		return store.PutRevisionResult{}, err
	}
	if !write.Valid() {
		return store.PutRevisionResult{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	record, err := store.NewRevisionRecordFromWrite(write)
	if err != nil {
		return store.PutRevisionResult{}, err
	}
	namespace := write.Metadata().Namespace()
	var reservation *referenceRevisionReservation
	var pause *referenceReadPause
	for {
		m.mu.Lock()
		byID := m.revisions[namespace]
		if existing, ok := byID[write.Metadata().ID()]; ok {
			m.mu.Unlock()
			if !bytes.Equal(existing.Artifact(), write.Artifact()) {
				return store.PutRevisionResult{}, referenceError(policyengine.ErrorIntegrity)
			}
			return store.NewPutRevisionResult(existing, false)
		}
		if wait := m.revisionReservations[namespace]; wait != nil {
			if wait.pause != nil {
				wait.pause.contendedOnce.Do(func() { close(wait.pause.contended) })
			}
			m.mu.Unlock()
			select {
			case <-wait.done:
				continue
			case <-ctx.Done():
				return store.PutRevisionResult{}, store.ContextError(ctx)
			}
		}
		pause = m.nextRevisionPause
		m.nextRevisionPause = nil
		reservation = &referenceRevisionReservation{
			done:  make(chan struct{}),
			pause: pause,
		}
		m.revisionReservations[namespace] = reservation
		m.mu.Unlock()
		break
	}
	releaseReservationLocked := func() {
		if m.revisionReservations[namespace] == reservation {
			delete(m.revisionReservations, namespace)
			close(reservation.done)
		}
	}
	if pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-ctx.Done():
			m.mu.Lock()
			releaseReservationLocked()
			m.mu.Unlock()
			return store.PutRevisionResult{}, store.ContextError(ctx)
		}
	}
	if err := store.ContextError(ctx); err != nil {
		m.mu.Lock()
		releaseReservationLocked()
		m.mu.Unlock()
		return store.PutRevisionResult{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	byID := m.revisions[namespace]
	if m.consumeEventFailureLocked() {
		releaseReservationLocked()
		return store.PutRevisionResult{}, referenceError(policyengine.ErrorUnavailable)
	}
	event, err := m.newEventLocked(policyengine.StateEventInput{
		Namespace:  namespace,
		Kind:       policyengine.StateEventRevisionPublished,
		RevisionID: record.Metadata().ID(),
	})
	if err != nil {
		releaseReservationLocked()
		return store.PutRevisionResult{}, err
	}
	result, err := store.NewPutRevisionResult(record, true)
	if err != nil {
		releaseReservationLocked()
		return store.PutRevisionResult{}, err
	}
	if byID == nil {
		byID = make(map[string]store.RevisionRecord)
		m.revisions[namespace] = byID
	}
	byID[record.Metadata().ID()] = record
	m.appendEventLocked(event)
	releaseReservationLocked()
	return result, nil
}

func (m *referenceModel) GetRevision(ctx context.Context, request policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	if err := store.ContextError(ctx); err != nil {
		return store.RevisionRecord{}, err
	}
	if _, err := policyengine.NewGetRevisionRequest(request.Namespace(), request.RevisionID()); err != nil {
		return store.RevisionRecord{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.revisions[request.Namespace()][request.RevisionID()]
	if !ok {
		return store.RevisionRecord{}, referenceError(policyengine.ErrorNotFound)
	}
	return record, nil
}

func (m *referenceModel) ListRevisions(ctx context.Context, request policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	if _, err := policyengine.NewListRevisionsRequest(request.Namespace(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListRevisionsResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	position, err := m.cursorPositionLocked(request.Cursor(), "revision", request.Namespace(), "")
	if err != nil {
		return policyengine.ListRevisionsResponse{}, err
	}
	records := make([]store.RevisionRecord, 0, len(m.revisions[request.Namespace()]))
	for _, record := range m.revisions[request.Namespace()] {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := records[i].Metadata(), records[j].Metadata()
		if !left.PublishedAt().Equal(right.PublishedAt()) {
			return left.PublishedAt().Before(right.PublishedAt())
		}
		return left.ID() < right.ID()
	})
	if position > uint64(len(records)) {
		return policyengine.ListRevisionsResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	end := min(int(position)+request.Limit(), len(records))
	metadata := make([]policyengine.RevisionMetadata, 0, end-int(position))
	for _, record := range records[position:end] {
		metadata = append(metadata, record.Metadata())
	}
	next := ""
	if end < len(records) {
		next = m.newCursorLocked(referenceCursor{domain: "revision", namespace: request.Namespace(), position: uint64(end)})
	}
	return policyengine.NewListRevisionsResponse(request, metadata, next)
}

func (m *referenceModel) Activate(ctx context.Context, request policyengine.ActivateRequest) (policyengine.ActivateResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if _, err := policyengine.NewActivateRequest(request.Namespace(), request.Slot(), request.TargetRevisionID(), request.Expectation()); err != nil {
		return policyengine.ActivateResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.revisions[request.Namespace()][request.TargetRevisionID()]; !ok {
		return policyengine.ActivateResponse{}, referenceError(policyengine.ErrorNotFound)
	}
	bySlot := m.slots[request.Namespace()]
	state := bySlot[request.Slot()]
	if !activationExpectationMatches(request.Expectation(), state) {
		return policyengine.ActivateResponse{}, referenceError(policyengine.ErrorConflict)
	}
	generation := uint64(1)
	if state != nil {
		generation = state.current.Generation() + 1
	}
	activation, err := policyengine.NewActivation(
		request.Namespace(), request.Slot(), request.TargetRevisionID(), generation, time.Now().UTC(),
	)
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	response, err := policyengine.NewActivateResponse(activation)
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if m.consumeEventFailureLocked() {
		return policyengine.ActivateResponse{}, referenceError(policyengine.ErrorUnavailable)
	}
	event, err := m.newEventLocked(policyengine.StateEventInput{
		Namespace:      request.Namespace(),
		Kind:           policyengine.StateEventSlotActivated,
		RevisionID:     request.TargetRevisionID(),
		Slot:           request.Slot(),
		SlotGeneration: generation,
	})
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if bySlot == nil {
		bySlot = make(map[string]*referenceSlot)
		m.slots[request.Namespace()] = bySlot
	}
	if state == nil {
		state = &referenceSlot{}
		bySlot[request.Slot()] = state
	}
	state.current = activation
	state.history = append(state.history, activation)
	if len(state.history) > referenceHistoryRetention {
		state.history = append([]policyengine.Activation(nil), state.history[len(state.history)-referenceHistoryRetention:]...)
	}
	m.appendEventLocked(event)
	return response, nil
}

func activationExpectationMatches(expectation policyengine.SlotExpectation, state *referenceSlot) bool {
	if expectation.IsUnset() {
		return state == nil
	}
	revisionID, generation, active := expectation.Active()
	return active && state != nil && state.current.RevisionID() == revisionID && state.current.Generation() == generation
}

func (m *referenceModel) Resolve(ctx context.Context, request policyengine.ResolveRequest) (policyengine.ResolveResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	if _, err := policyengine.NewResolveRequest(request.Namespace(), request.Slot()); err != nil {
		return policyengine.ResolveResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.slots[request.Namespace()][request.Slot()]
	if state == nil {
		return policyengine.ResolveResponse{}, referenceError(policyengine.ErrorNotFound)
	}
	return policyengine.NewResolveResponse(state.current)
}

func (m *referenceModel) ListActivationHistory(ctx context.Context, request policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	if _, err := policyengine.NewListActivationHistoryRequest(request.Namespace(), request.Slot(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListActivationHistoryResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	position, err := m.cursorPositionLocked(request.Cursor(), "history", request.Namespace(), request.Slot())
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	state := m.slots[request.Namespace()][request.Slot()]
	history := []policyengine.Activation{}
	if state != nil {
		history = state.history
	}
	if request.Cursor() != "" && len(history) > 0 && position < history[0].Generation() {
		return policyengine.ListActivationHistoryResponse{}, referenceError(policyengine.ErrorCursorExpired)
	}
	start := sort.Search(len(history), func(i int) bool { return history[i].Generation() > position })
	end := min(start+request.Limit(), len(history))
	page := append([]policyengine.Activation(nil), history[start:end]...)
	next := ""
	if end < len(history) {
		next = m.newCursorLocked(referenceCursor{
			domain: "history", namespace: request.Namespace(), slot: request.Slot(), position: page[len(page)-1].Generation(),
		})
	}
	return policyengine.NewListActivationHistoryResponse(request, page, next)
}

func (m *referenceModel) GetDataGeneration(ctx context.Context, request policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	if _, err := policyengine.NewGetDataGenerationRequest(request.Namespace()); err != nil {
		return policyengine.GetDataGenerationResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	generation := uint64(0)
	if state := m.data[request.Namespace()]; state != nil {
		generation = state.generation
	}
	return policyengine.NewGetDataGenerationResponse(generation)
}

func (m *referenceModel) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	if err := store.ContextError(ctx); err != nil {
		return nil, err
	}
	if !request.Valid() {
		return nil, referenceError(policyengine.ErrorInvalidArgument)
	}
	for {
		m.mu.Lock()
		state := m.dataStateLocked(request.Namespace())
		if state.generation >= request.MinimumGeneration() {
			snapshot := &referenceSnapshot{
				owner:      m,
				namespace:  request.Namespace(),
				generation: state.generation,
				minimum:    request.MinimumGeneration(),
				readAt:     request.ReadAt(),
				tuples:     cloneTupleMap(state.tuples),
				attributes: cloneAttributeMap(state.attributes),
			}
			m.mu.Unlock()
			return snapshot, nil
		}
		changed := state.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, store.ContextError(ctx)
		}
	}
}

func (m *referenceModel) WriteData(ctx context.Context, request policyengine.WriteDataRequest) (policyengine.WriteDataResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	_, fingerprint, err := store.FingerprintWriteData(request)
	if err != nil {
		return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	if pause := m.consumeDataCommitPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-ctx.Done():
			return policyengine.WriteDataResponse{}, store.ContextError(ctx)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.dataStateLocked(request.Namespace())
	if previous, ok := state.idempotency[request.IdempotencyKey()]; ok {
		if !bytes.Equal(previous.fingerprint, fingerprint.Bytes()) {
			return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorConflict)
		}
		return policyengine.NewWriteDataResponse(previous.response.Generation(), true)
	}
	if _, ok := m.revisions[request.Namespace()][request.ValidationRevisionID()]; !ok {
		return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorNotFound)
	}
	if state.generation != request.ExpectedGeneration() {
		return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorConflict)
	}
	tuples := cloneTupleMap(state.tuples)
	attributes := cloneAttributeMap(state.attributes)
	for _, key := range request.TupleDeletes() {
		delete(tuples, key.Tuple())
	}
	for _, tuple := range request.TupleWrites() {
		tuples[tuple.Tuple()] = tuple
	}
	for _, key := range request.AttributeDeletes() {
		delete(attributes, makeReferenceAttributeKey(key.Entity(), key.Path()))
	}
	writes := request.AttributeWrites()
	if persistedAttributePrefixConflict(attributes, writes) {
		return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorConflict)
	}
	for _, attribute := range writes {
		attributes[makeReferenceAttributeKey(attribute.Entity(), attribute.Path())] = attribute
	}
	generation := state.generation + 1
	response, err := policyengine.NewWriteDataResponse(generation, false)
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	if m.consumeEventFailureLocked() {
		return policyengine.WriteDataResponse{}, referenceError(policyengine.ErrorUnavailable)
	}
	event, err := m.newEventLocked(policyengine.StateEventInput{
		Namespace: request.Namespace(), Kind: policyengine.StateEventDataWritten, DataGeneration: generation,
	})
	if err != nil {
		return policyengine.WriteDataResponse{}, err
	}
	state.generation = generation
	state.tuples = tuples
	state.attributes = attributes
	state.idempotency[request.IdempotencyKey()] = referenceIdempotency{
		fingerprint: fingerprint.Bytes(),
		response:    response,
	}
	close(state.changed)
	state.changed = make(chan struct{})
	m.appendEventLocked(event)
	return response, nil
}

func (m *referenceModel) ListEvents(ctx context.Context, request policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error) {
	if err := store.ContextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if _, err := policyengine.NewListEventsRequest(request.Namespace(), request.AfterCursor(), request.Limit()); err != nil {
		return policyengine.ListEventsResponse{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	position, err := m.cursorPositionLocked(request.AfterCursor(), "event", request.Namespace(), "")
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	state := m.events[request.Namespace()]
	if request.AfterCursor() != "" && state != nil && position <= state.expiredThrough {
		return policyengine.ListEventsResponse{}, referenceError(policyengine.ErrorCursorExpired)
	}
	values := []referenceEvent{}
	if state != nil {
		values = state.values
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
	return policyengine.NewListEventsResponse(request, page, next)
}

func (m *referenceModel) expireEvents(ctx context.Context, namespace, throughCursor string) error {
	if err := store.ContextError(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	position, err := m.cursorPositionLocked(throughCursor, "event", namespace, "")
	if err != nil {
		return err
	}
	state := m.events[namespace]
	if state == nil {
		return referenceError(policyengine.ErrorInvalidArgument)
	}
	cut := sort.Search(len(state.values), func(i int) bool { return state.values[i].sequence > position })
	state.values = append([]referenceEvent(nil), state.values[cut:]...)
	state.expiredThrough = max(state.expiredThrough, position)
	return nil
}

func (m *referenceModel) armNextEventFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNextEvent = true
}

func (m *referenceModel) armNextSnapshotReadBlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockNextRead = true
}

func (m *referenceModel) pauseNextSnapshotRead() conformance.SnapshotReadPause {
	m.mu.Lock()
	defer m.mu.Unlock()
	pause := &referenceReadPause{
		entered:   make(chan struct{}),
		contended: make(chan struct{}),
		release:   make(chan struct{}),
	}
	m.nextReadPause = pause
	return conformance.SnapshotReadPause{
		Entered: pause.entered,
		Release: func() { pause.releaseOnce.Do(func() { close(pause.release) }) },
	}
}

func (m *referenceModel) consumeSnapshotReadPause() *referenceReadPause {
	m.mu.Lock()
	defer m.mu.Unlock()
	pause := m.nextReadPause
	m.nextReadPause = nil
	return pause
}

func (m *referenceModel) pauseNextDataCommit() conformance.DataCommitPause {
	m.mu.Lock()
	defer m.mu.Unlock()
	pause := &referenceReadPause{entered: make(chan struct{}), release: make(chan struct{})}
	m.nextDataPause = pause
	return conformance.DataCommitPause{
		Entered: pause.entered,
		Release: func() { pause.releaseOnce.Do(func() { close(pause.release) }) },
	}
}

func (m *referenceModel) consumeDataCommitPause() *referenceReadPause {
	m.mu.Lock()
	defer m.mu.Unlock()
	pause := m.nextDataPause
	m.nextDataPause = nil
	return pause
}

func (m *referenceModel) pauseNextRevisionCommit() conformance.RevisionCommitPause {
	m.mu.Lock()
	defer m.mu.Unlock()
	pause := &referenceReadPause{
		entered:   make(chan struct{}),
		contended: make(chan struct{}),
		release:   make(chan struct{}),
	}
	m.nextRevisionPause = pause
	return conformance.RevisionCommitPause{
		Entered:   pause.entered,
		Contended: pause.contended,
		Release:   func() { pause.releaseOnce.Do(func() { close(pause.release) }) },
	}
}

func (m *referenceModel) consumeSnapshotReadBlock() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	blocked := m.blockNextRead
	m.blockNextRead = false
	return blocked
}

func (m *referenceModel) consumeEventFailureLocked() bool {
	failed := m.failNextEvent
	m.failNextEvent = false
	return failed
}

func (m *referenceModel) dataStateLocked(namespace string) *referenceData {
	state := m.data[namespace]
	if state != nil {
		return state
	}
	state = &referenceData{
		tuples:      make(map[dsl.Tuple]policyengine.RelationshipTuple),
		attributes:  make(map[referenceAttributeKey]policyengine.Attribute),
		idempotency: make(map[string]referenceIdempotency),
		changed:     make(chan struct{}),
	}
	m.data[namespace] = state
	return state
}

func (m *referenceModel) newEventLocked(input policyengine.StateEventInput) (referenceEvent, error) {
	state := m.events[input.Namespace]
	sequence := uint64(1)
	if state != nil && len(state.values) > 0 {
		sequence = state.values[len(state.values)-1].sequence + 1
	} else if state != nil {
		sequence = state.expiredThrough + 1
	}
	cursor := m.newCursorLocked(referenceCursor{domain: "event", namespace: input.Namespace, position: sequence})
	input.Cursor = cursor
	input.OccurredAt = time.Now().UTC()
	value, err := policyengine.NewStateEvent(input)
	if err != nil {
		return referenceEvent{}, err
	}
	return referenceEvent{sequence: sequence, value: value}, nil
}

func (m *referenceModel) appendEventLocked(event referenceEvent) {
	namespace := event.value.Namespace()
	state := m.events[namespace]
	if state == nil {
		state = &referenceEvents{}
		m.events[namespace] = state
	}
	state.values = append(state.values, event)
}

func (m *referenceModel) newCursorLocked(cursor referenceCursor) string {
	m.cursorSeq++
	value := "c" + strconv.FormatUint(m.cursorSeq, 10)
	m.cursors[value] = cursor
	return value
}

func (m *referenceModel) cursorPositionLocked(value, domain, namespace, slot string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	cursor, ok := m.cursors[value]
	if !ok || cursor.domain != domain || cursor.namespace != namespace || cursor.slot != slot {
		return 0, referenceError(policyengine.ErrorInvalidArgument)
	}
	return cursor.position, nil
}

type referenceSnapshot struct {
	owner *referenceModel

	lifecycle  sync.RWMutex
	closed     bool
	namespace  string
	generation uint64
	minimum    uint64
	readAt     time.Time
	tuples     map[dsl.Tuple]policyengine.RelationshipTuple
	attributes map[referenceAttributeKey]policyengine.Attribute
}

func (s *referenceSnapshot) Namespace() string         { return s.namespace }
func (s *referenceSnapshot) Generation() uint64        { return s.generation }
func (s *referenceSnapshot) MinimumGeneration() uint64 { return s.minimum }
func (s *referenceSnapshot) ReadAt() time.Time         { return s.readAt }

func (*referenceSnapshot) String() string { return "Snapshot{[REDACTED]}" }

func (*referenceSnapshot) GoString() string { return "Snapshot{[REDACTED]}" }

func (*referenceSnapshot) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("Snapshot{[REDACTED]}"))
}

func (*referenceSnapshot) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", "Snapshot"), slog.String("value", "[REDACTED]"))
}

func (s *referenceSnapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	if err := store.ContextError(ctx); err != nil {
		return store.TupleResult{}, err
	}
	if !query.Valid() {
		return store.TupleResult{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return store.TupleResult{}, referenceError(policyengine.ErrorFailedPrecondition)
	}
	if s.owner.consumeSnapshotReadBlock() {
		<-ctx.Done()
		return store.TupleResult{}, store.ContextError(ctx)
	}
	if pause := s.owner.consumeSnapshotReadPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-ctx.Done():
			return store.TupleResult{}, store.ContextError(ctx)
		}
	}
	subjects := make([]dsl.SubjectRef, 0)
	for tuple, value := range s.tuples {
		if tuple.Resource != query.Resource() || tuple.Relation != query.Relation() {
			continue
		}
		expiresAt, expires := value.ExpiresAt()
		if expires && !expiresAt.After(s.readAt) {
			continue
		}
		subjects = append(subjects, tuple.Subject)
		if len(subjects) > query.Limit() {
			return store.TupleResult{}, referenceError(policyengine.ErrorResourceExhausted)
		}
	}
	if err := store.ContextError(ctx); err != nil {
		return store.TupleResult{}, err
	}
	return store.NewTupleResult(query, subjects)
}

func (s *referenceSnapshot) GetAttribute(ctx context.Context, key policyengine.AttributeKey) (store.AttributeResult, error) {
	if err := store.ContextError(ctx); err != nil {
		return store.AttributeResult{}, err
	}
	canonical, err := policyengine.NewAttributeKeyPath(key.Entity(), key.Path())
	if err != nil || !reflect.DeepEqual(canonical.Path(), key.Path()) {
		return store.AttributeResult{}, referenceError(policyengine.ErrorInvalidArgument)
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return store.AttributeResult{}, referenceError(policyengine.ErrorFailedPrecondition)
	}
	if s.owner.consumeSnapshotReadBlock() {
		<-ctx.Done()
		return store.AttributeResult{}, store.ContextError(ctx)
	}
	if pause := s.owner.consumeSnapshotReadPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-ctx.Done():
			return store.AttributeResult{}, store.ContextError(ctx)
		}
	}
	attribute, found := s.attributes[makeReferenceAttributeKey(key.Entity(), key.Path())]
	if err := store.ContextError(ctx); err != nil {
		return store.AttributeResult{}, err
	}
	if !found {
		return store.NewAttributeResult(key, policyengine.Value{}, false)
	}
	return store.NewAttributeResult(key, attribute.Value(), true)
}

func (s *referenceSnapshot) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.closed = true
	return nil
}

func cloneTupleMap(input map[dsl.Tuple]policyengine.RelationshipTuple) map[dsl.Tuple]policyengine.RelationshipTuple {
	result := make(map[dsl.Tuple]policyengine.RelationshipTuple, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func cloneAttributeMap(input map[referenceAttributeKey]policyengine.Attribute) map[referenceAttributeKey]policyengine.Attribute {
	result := make(map[referenceAttributeKey]policyengine.Attribute, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func makeReferenceAttributeKey(entity dsl.EntityRef, path []string) referenceAttributeKey {
	var encoded strings.Builder
	for _, segment := range path {
		_, _ = fmt.Fprintf(&encoded, "%d:%s", len(segment), segment)
	}
	return referenceAttributeKey{entity: entity, path: encoded.String()}
}

func persistedAttributePrefixConflict(existing map[referenceAttributeKey]policyengine.Attribute, writes []policyengine.Attribute) bool {
	for _, write := range writes {
		writePath := write.Path()
		writeKey := makeReferenceAttributeKey(write.Entity(), writePath)
		for key, current := range existing {
			if key == writeKey || current.Entity() != write.Entity() {
				continue
			}
			if pathPrefixConflict(current.Path(), writePath) {
				return true
			}
		}
	}
	return false
}

func pathPrefixConflict(left, right []string) bool {
	if len(left) == len(right) {
		return false
	}
	shorter, longer := left, right
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

func referenceError(category policyengine.ErrorCategory) error {
	err, constructorErr := policyengine.NewEngineError(category)
	if constructorErr != nil {
		panic(constructorErr)
	}
	return err
}
