package authorization_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/conformance/authorization"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestEmbeddedEngineAuthorizationConformance(t *testing.T) {
	var pauses pinningCounters
	authorization.Run(t, func(t *testing.T) policyengine.Engine {
		storage, err := memory.New()
		requireNoError(t, err)
		controlled := &controlledStore{Store: storage, counters: &pauses}
		engine, err := embedded.New(
			embedded.WithStore(controlled),
			embedded.WithCallerAuthorizer(conformanceAuthorizer{}),
		)
		requireNoError(t, err)
		return &controlledEngine{Engine: engine, store: controlled}
	})
	if pauses.revision.Load() == 0 || pauses.snapshot.Load() == 0 {
		t.Fatal("authorization conformance did not exercise deterministic pin pauses")
	}
}

type pinningCounters struct {
	revision atomic.Int32
	snapshot atomic.Int32
}

type pause struct {
	entered chan struct{}
	resume  chan struct{}
}

type controlledStore struct {
	store.Store
	counters *pinningCounters
	mu       sync.Mutex
	revision *pause
	snapshot *pause
}

func (s *controlledStore) armRevision() (<-chan struct{}, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &pause{entered: make(chan struct{}), resume: make(chan struct{})}
	s.revision = p
	s.counters.revision.Add(1)
	return p.entered, func() { close(p.resume) }
}

func (s *controlledStore) armSnapshot() (<-chan struct{}, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &pause{entered: make(chan struct{}), resume: make(chan struct{})}
	s.snapshot = p
	s.counters.snapshot.Add(1)
	return p.entered, func() { close(p.resume) }
}

func (s *controlledStore) GetRevision(ctx context.Context, request policyengine.GetRevisionRequest) (store.RevisionRecord, error) {
	s.mu.Lock()
	p := s.revision
	s.revision = nil
	s.mu.Unlock()
	if p != nil {
		close(p.entered)
		select {
		case <-p.resume:
		case <-ctx.Done():
			return store.RevisionRecord{}, ctx.Err()
		}
	}
	return s.Store.GetRevision(ctx, request)
}

func (s *controlledStore) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	snapshot, err := s.Store.OpenSnapshot(ctx, request)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	p := s.snapshot
	s.snapshot = nil
	s.mu.Unlock()
	if p != nil {
		close(p.entered)
		select {
		case <-p.resume:
		case <-ctx.Done():
			_ = snapshot.Close()
			return nil, ctx.Err()
		}
	}
	return snapshot, nil
}

type controlledEngine struct {
	policyengine.Engine
	store *controlledStore
}

func (e *controlledEngine) PauseNextRevisionLoad() (<-chan struct{}, func()) {
	return e.store.armRevision()
}

func (e *controlledEngine) PauseNextSnapshotOpen() (<-chan struct{}, func()) {
	return e.store.armSnapshot()
}

type conformanceAuthorizer struct{}

func (conformanceAuthorizer) Authorize(
	_ context.Context,
	caller policyengine.Caller,
	namespace string,
	capabilities []policyengine.Capability,
) (policyengine.CallerAuthorization, error) {
	if caller.ID() == authorization.DeniedCallerID {
		errorValue, _ := policyengine.NewEngineError(policyengine.ErrorPermissionDenied)
		return policyengine.CallerAuthorization{}, errorValue
	}
	grant, err := policyengine.NewGrant(namespace, capabilities)
	if err != nil {
		return policyengine.CallerAuthorization{}, err
	}
	return policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
