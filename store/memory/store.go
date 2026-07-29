// Package memory provides a deterministic, process-local implementation of the
// public store contracts. It is intended for development and tests; it is not a
// durable database.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

const (
	activationHistoryRetention = 3
	eventRetentionLimit        = policyengine.MaxAggregateWorkItems
	defaultEventRetention      = 24 * time.Hour
)

// Clock supplies UTC event and activation timestamps and drives event
// retention. Implementations must be safe for concurrent use, return a nonzero
// value in bounded time, and must not panic. Clock.Now may reenter read-only
// Store methods but must not synchronously invoke mutating Store methods.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Store is an isolated synchronized in-memory local store.
type Store struct {
	mu sync.Mutex

	clock Clock
	// effectiveTime is the non-decreasing clock observed at successful commit
	// and retention boundaries. It makes rollback safe for ordered pruning.
	effectiveTime time.Time

	revisions     map[string]map[string]store.RevisionRecord
	revisionOrder map[string]*revisionNode
	slots         map[string]map[string]*slotState
	data          map[string]*dataState
	waiters       map[string]*generationWait
	events        map[string]*eventState
	reservations  map[commitReservationKey]*commitReservation
	cursorKey     [32]byte
	cursorKeyOK   bool

	failNextEvent bool
	blockNextRead bool
	nextReadPause *pauseState
	nextDataPause *pauseState
}

// New constructs an isolated store using the system clock. It panics with a
// static message if the operating system cannot provide cursor-key entropy;
// returning a store that can never issue authenticated cursors would be unsafe.
func New() *Store {
	result, err := newStoreWithCursorKeySource(systemClock{}, initializeCursorKey)
	if err != nil {
		panic("memory: cursor key initialization failed")
	}
	return result
}

// NewWithClock constructs an isolated store with an injected clock.
func NewWithClock(clock Clock) (*Store, error) {
	if nilInterface(clock) {
		return nil, engineError(policyengine.ErrorInvalidArgument)
	}
	return newStoreWithCursorKeySource(clock, initializeCursorKey)
}

func newStoreWithCursorKeySource(clock Clock, source cursorKeySource) (*Store, error) {
	result := &Store{
		clock:         clock,
		revisions:     make(map[string]map[string]store.RevisionRecord),
		revisionOrder: make(map[string]*revisionNode),
		slots:         make(map[string]map[string]*slotState),
		data:          make(map[string]*dataState),
		waiters:       make(map[string]*generationWait),
		events:        make(map[string]*eventState),
		reservations:  make(map[commitReservationKey]*commitReservation),
	}
	written, err := source(result.cursorKey[:])
	if err != nil || written != len(result.cursorKey) {
		return nil, engineError(policyengine.ErrorInternal)
	}
	result.cursorKeyOK = true
	return result, nil
}

var _ store.Store = (*Store)(nil)

// String returns a static privacy-safe store representation.
func (*Store) String() string { return "Store{[REDACTED]}" }

// GoString returns a static privacy-safe Go-syntax store representation.
func (*Store) GoString() string { return "Store{[REDACTED]}" }

// Format redacts Store for every supported formatting verb.
func (*Store) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("Store{[REDACTED]}"))
}

// LogValue returns static privacy-safe structured logging metadata.
func (*Store) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", "Store"), slog.String("value", "[REDACTED]"))
}

type slotState struct {
	current policyengine.Activation
	history []policyengine.Activation
}

type dataState struct {
	generation  uint64
	current     *dataVersion
	idempotency map[string]idempotencyState
}

type generationWait struct {
	changed chan struct{}
	refs    int
}

type idempotencyState struct {
	fingerprint []byte
	response    policyengine.WriteDataResponse
}

type eventState struct {
	values         []eventRecord
	expiredThrough uint64
}

type eventRecord struct {
	sequence uint64
	value    policyengine.StateEvent
}

type cursorState struct {
	domain              string
	namespace           string
	slot                string
	position            uint64
	revisionPublishedAt time.Time
	revisionID          string
}

type pauseState struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

type commitReservation struct {
	key            commitReservationKey
	done           chan struct{}
	operation      string
	idempotencyKey string
	fingerprint    []byte
}

type commitReservationKey struct {
	domain    string
	namespace string
	name      string
}

func (s *Store) reserveCommitLocked(key commitReservationKey) (*commitReservation, bool) {
	if s.reservations[key] != nil {
		return nil, false
	}
	reservation := &commitReservation{key: key, done: make(chan struct{})}
	s.reservations[key] = reservation
	return reservation, true
}

func (s *Store) ownsCommitReservationLocked(reservation *commitReservation) bool {
	return reservation != nil && s.reservations[reservation.key] == reservation
}

func (s *Store) releaseCommitReservationLocked(reservation *commitReservation) {
	if s.ownsCommitReservationLocked(reservation) {
		delete(s.reservations, reservation.key)
		close(reservation.done)
	}
}

func (s *Store) releaseCommitReservation(reservation *commitReservation) {
	s.mu.Lock()
	s.releaseCommitReservationLocked(reservation)
	s.mu.Unlock()
}

func contextSignaled(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (s *Store) now() (value time.Time, err error) {
	defer func() {
		if recover() != nil {
			value = time.Time{}
			err = engineError(policyengine.ErrorInternal)
		}
	}()
	value = s.clock.Now().UTC()
	if value.IsZero() {
		return time.Time{}, engineError(policyengine.ErrorInternal)
	}
	return value, nil
}

func (s *Store) effectiveTimeLocked(candidate time.Time) time.Time {
	if candidate.Before(s.effectiveTime) {
		return s.effectiveTime
	}
	s.effectiveTime = candidate
	return candidate
}

func engineError(category policyengine.ErrorCategory) error {
	value, err := policyengine.NewEngineError(category)
	if err == nil {
		return value
	}
	fallback, _ := policyengine.NewEngineError(policyengine.ErrorInternal)
	return fallback
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (s *Store) registerGenerationWaitLocked(namespace string) *generationWait {
	wait := s.waiters[namespace]
	if wait == nil {
		wait = &generationWait{changed: make(chan struct{})}
		s.waiters[namespace] = wait
	}
	wait.refs++
	return wait
}

func (s *Store) unregisterGenerationWaitLocked(namespace string, wait *generationWait) {
	if s.waiters[namespace] != wait {
		return
	}
	wait.refs--
	if wait.refs == 0 {
		delete(s.waiters, namespace)
	}
}

func (s *Store) notifyGenerationWaitersLocked(namespace string) {
	wait := s.waiters[namespace]
	if wait == nil {
		return
	}
	delete(s.waiters, namespace)
	close(wait.changed)
}

func (s *Store) armNextEventFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNextEvent = true
}

func (s *Store) armNextSnapshotReadBlock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockNextRead = true
}

func (s *Store) consumeSnapshotReadBlock() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	blocked := s.blockNextRead
	s.blockNextRead = false
	return blocked
}

func (s *Store) newPause(target **pauseState) *pauseState {
	s.mu.Lock()
	defer s.mu.Unlock()
	pause := &pauseState{entered: make(chan struct{}), release: make(chan struct{})}
	*target = pause
	return pause
}

func (s *Store) consumePause(target **pauseState) *pauseState {
	s.mu.Lock()
	defer s.mu.Unlock()
	pause := *target
	*target = nil
	return pause
}

func safeContextError(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = engineError(policyengine.ErrorInternal)
		}
	}()
	return store.ContextError(ctx)
}

func contextDone(ctx context.Context) (done <-chan struct{}, err error) {
	if err := safeContextError(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			done = nil
			err = engineError(policyengine.ErrorInternal)
		}
	}()
	return ctx.Done(), nil
}

func contextWaitError(ctx context.Context) error {
	if err := safeContextError(ctx); err != nil {
		return err
	}
	return engineError(policyengine.ErrorInternal)
}
