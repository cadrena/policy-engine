package memory

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

// GetDataGeneration returns the current exact committed namespace generation.
func (s *Store) GetDataGeneration(ctx context.Context, request policyengine.GetDataGenerationRequest) (policyengine.GetDataGenerationResponse, error) {
	if err := safeContextError(ctx); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	if _, err := policyengine.NewGetDataGenerationRequest(request.Namespace()); err != nil {
		return policyengine.GetDataGenerationResponse{}, engineError(policyengine.ErrorInvalidArgument)
	}
	if err := safeContextError(ctx); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	s.mu.Lock()
	generation := uint64(0)
	if state := s.data[request.Namespace()]; state != nil {
		generation = state.generation
	}
	s.mu.Unlock()
	if err := safeContextError(ctx); err != nil {
		return policyengine.GetDataGenerationResponse{}, err
	}
	return policyengine.NewGetDataGenerationResponse(generation)
}

// OpenSnapshot waits for its lower bound and pins one immutable exact version
// by pointer. It never clones or scans namespace data.
func (s *Store) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	if err := safeContextError(ctx); err != nil {
		return nil, err
	}
	if !request.Valid() {
		return nil, engineError(policyengine.ErrorInvalidArgument)
	}
	for {
		if err := safeContextError(ctx); err != nil {
			return nil, err
		}
		s.mu.Lock()
		state := s.data[request.Namespace()]
		generation := uint64(0)
		var version *dataVersion
		if state != nil {
			generation = state.generation
			version = state.current
		}
		if generation >= request.MinimumGeneration() {
			if version == nil {
				version = &dataVersion{generation: generation}
			}
			view := &snapshot{
				owner: s, namespace: request.Namespace(), generation: generation,
				minimum: request.MinimumGeneration(), readAt: request.ReadAt(), version: version,
				closeDone: make(chan struct{}),
			}
			s.mu.Unlock()
			if err := safeContextError(ctx); err != nil {
				return nil, err
			}
			return view, nil
		}
		wait := s.registerGenerationWaitLocked(request.Namespace())
		s.mu.Unlock()
		done, err := contextDone(ctx)
		if err != nil {
			s.mu.Lock()
			s.unregisterGenerationWaitLocked(request.Namespace(), wait)
			s.mu.Unlock()
			return nil, err
		}
		var waitErr error
		select {
		case <-wait.changed:
		case <-done:
			waitErr = contextWaitError(ctx)
		}
		s.mu.Lock()
		s.unregisterGenerationWaitLocked(request.Namespace(), wait)
		s.mu.Unlock()
		if waitErr != nil {
			return nil, waitErr
		}
	}
}

type snapshot struct {
	lifecycle sync.Mutex
	closing   bool
	active    int
	closeDone chan struct{}

	owner      *Store
	namespace  string
	generation uint64
	minimum    uint64
	readAt     time.Time
	version    *dataVersion
}

var _ store.Snapshot = (*snapshot)(nil)

func (s *snapshot) Namespace() string         { return s.namespace }
func (s *snapshot) Generation() uint64        { return s.generation }
func (s *snapshot) MinimumGeneration() uint64 { return s.minimum }
func (s *snapshot) ReadAt() time.Time         { return s.readAt }

func (s *snapshot) admit() (*dataVersion, *Store, error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closing {
		return nil, nil, engineError(policyengine.ErrorFailedPrecondition)
	}
	s.active++
	return s.version, s.owner, nil
}

func (s *snapshot) release() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.active--
	if s.closing && s.active == 0 && s.version != nil {
		s.version = nil
		s.owner = nil
		close(s.closeDone)
	}
}

// QueryTuples visits only the exact indexed resource/relation bucket and
// returns every active match or RESOURCE_EXHAUSTED without truncation.
func (s *snapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	if err := safeContextError(ctx); err != nil {
		return store.TupleResult{}, err
	}
	if !query.Valid() {
		return store.TupleResult{}, engineError(policyengine.ErrorInvalidArgument)
	}
	done, err := contextDone(ctx)
	if err != nil {
		return store.TupleResult{}, err
	}
	version, owner, err := s.admit()
	if err != nil {
		return store.TupleResult{}, err
	}
	admitted := true
	release := func() {
		if admitted {
			s.release()
			admitted = false
		}
	}
	defer release()
	if owner.consumeSnapshotReadBlock() {
		<-done
		release()
		return store.TupleResult{}, contextWaitError(ctx)
	}
	if pause := owner.consumeSnapshotReadPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-done:
			release()
			return store.TupleResult{}, contextWaitError(ctx)
		}
	}
	subjects := make([]dsl.SubjectRef, 0, min(query.Limit(), 16))
	resultExhausted := false
	workExhausted := false
	canceled := false
	visited := 0
	queryTupleBucket(version.tuples, query.Resource(), query.Relation(), func(value policyengine.RelationshipTuple) bool {
		visited++
		if visited > policyengine.MaxAggregateWorkItems {
			workExhausted = true
			return false
		}
		if visited%64 == 0 && contextSignaled(done) {
			canceled = true
			return false
		}
		expiresAt, expires := value.ExpiresAt()
		if expires && !expiresAt.After(s.readAt) {
			return true
		}
		subjects = append(subjects, value.Tuple().Subject)
		if len(subjects) > query.Limit() {
			resultExhausted = true
			return false
		}
		return true
	})
	if canceled {
		// Cancellation observed at a periodic check precedes any later work or
		// result bound because traversal stops at that observation.
		release()
		return store.TupleResult{}, contextWaitError(ctx)
	}
	if workExhausted || resultExhausted {
		// Once either bound is proven, RESOURCE_EXHAUSTED precedes the final
		// cancellation check and no partial result is returned.
		release()
		return store.TupleResult{}, engineError(policyengine.ErrorResourceExhausted)
	}
	result, err := store.NewTupleResult(query, subjects)
	if err != nil {
		release()
		return store.TupleResult{}, err
	}
	canceled = contextSignaled(done)
	release()
	if canceled {
		return store.TupleResult{}, contextWaitError(ctx)
	}
	return result, nil
}

// GetAttribute traverses one entity-scoped immutable segment trie by the exact
// structured path; it never scans other entities or attributes.
func (s *snapshot) GetAttribute(ctx context.Context, key policyengine.AttributeKey) (store.AttributeResult, error) {
	if err := safeContextError(ctx); err != nil {
		return store.AttributeResult{}, err
	}
	canonical, err := policyengine.NewAttributeKeyPath(key.Entity(), key.Path())
	if err != nil || !reflect.DeepEqual(canonical.Path(), key.Path()) {
		return store.AttributeResult{}, engineError(policyengine.ErrorInvalidArgument)
	}
	done, err := contextDone(ctx)
	if err != nil {
		return store.AttributeResult{}, err
	}
	version, owner, err := s.admit()
	if err != nil {
		return store.AttributeResult{}, err
	}
	admitted := true
	release := func() {
		if admitted {
			s.release()
			admitted = false
		}
	}
	defer release()
	if owner.consumeSnapshotReadBlock() {
		<-done
		release()
		return store.AttributeResult{}, contextWaitError(ctx)
	}
	if pause := owner.consumeSnapshotReadPause(); pause != nil {
		pause.enteredOnce.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-done:
			release()
			return store.AttributeResult{}, contextWaitError(ctx)
		}
	}
	attribute, found := attributeGet(version.attributes, key)
	var result store.AttributeResult
	if found {
		result, err = store.NewAttributeResult(key, attribute.Value(), true)
	} else {
		result, err = store.NewAttributeResult(key, policyengine.Value{}, false)
	}
	if err != nil {
		release()
		return store.AttributeResult{}, err
	}
	canceled := contextSignaled(done)
	release()
	if canceled {
		return store.AttributeResult{}, contextWaitError(ctx)
	}
	return result, nil
}

// Close flips admission before waiting, so late reads fail promptly rather than
// queueing behind Close. The final admitted reader releases pinned references.
func (s *snapshot) Close() error {
	s.lifecycle.Lock()
	if s.closing {
		done := s.closeDone
		s.lifecycle.Unlock()
		<-done
		return nil
	}
	s.closing = true
	if s.active == 0 {
		s.version = nil
		s.owner = nil
		close(s.closeDone)
	}
	done := s.closeDone
	s.lifecycle.Unlock()
	<-done
	return nil
}

type pauseControl struct {
	entered      <-chan struct{}
	contended    <-chan struct{}
	waiterWoke   <-chan struct{}
	release      func()
	resumeWaiter func()
}

func (s *Store) pauseNextSnapshotRead() pauseControl {
	pause := s.newPause(&s.nextReadPause)
	return pauseControl{entered: pause.entered, release: func() { pause.releaseOnce.Do(func() { close(pause.release) }) }}
}
func (s *Store) consumeSnapshotReadPause() *pauseState { return s.consumePause(&s.nextReadPause) }
func (s *Store) pauseNextDataCommit() pauseControl {
	pause := s.newPause(&s.nextDataPause)
	return pauseControl{entered: pause.entered, release: func() { pause.releaseOnce.Do(func() { close(pause.release) }) }}
}
func (s *Store) consumeDataCommitPause() *pauseState { return s.consumePause(&s.nextDataPause) }
func (s *Store) pauseNextRevisionCommit() pauseControl {
	pause := s.newPause(&s.nextRevisionPause)
	return pauseControl{
		entered:      pause.entered,
		contended:    pause.contended,
		waiterWoke:   pause.waiterWoke,
		release:      func() { pause.releaseOnce.Do(func() { close(pause.release) }) },
		resumeWaiter: func() { pause.resumeWaiterOnce.Do(func() { close(pause.resumeWaiter) }) },
	}
}

func (*snapshot) String() string                 { return "Snapshot{[REDACTED]}" }
func (*snapshot) GoString() string               { return "Snapshot{[REDACTED]}" }
func (*snapshot) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte("Snapshot{[REDACTED]}")) }
func (*snapshot) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", "Snapshot"), slog.String("value", "[REDACTED]"))
}
