package memory

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	storecontract "github.com/conductera/policy-engine/store"
	"github.com/conductera/policy-engine/store/conformance"
)

func TestNewReturnsInitializedStore(t *testing.T) {
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if adapter == nil {
		t.Fatal("New returned a nil store")
	}
}

func TestStoreFormattingIsStaticRedactedAndRaceSafe(t *testing.T) {
	const (
		namespaceCanary = "namespace-canary-private"
		artifactCanary  = "artifact_canary_private"
		cursorKeyCanary = "231 231 231 231 231 231"
	)
	adapter := MustNew()
	for index := range adapter.cursorKey {
		adapter.cursorKey[index] = 231
	}
	write := revisionWrite(t, namespaceCanary, "entity "+artifactCanary+" {}")
	if !bytes.Contains(write.Artifact(), []byte(artifactCanary)) {
		t.Fatal("privacy test artifact does not contain its byte canary")
	}
	if _, err := adapter.PutRevision(context.Background(), write); err != nil {
		t.Fatal(err)
	}

	var _ fmt.Stringer = adapter
	var _ fmt.GoStringer = adapter
	var _ fmt.Formatter = adapter
	var _ slog.LogValuer = adapter
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}
	assertRedacted := func(label, output string) {
		t.Helper()
		for _, canary := range []string{namespaceCanary, artifactCanary, cursorKeyCanary} {
			if strings.Contains(output, canary) {
				t.Fatalf("%s leaked %q in %q", label, canary, output)
			}
		}
		if !strings.Contains(output, "Store") || !strings.Contains(output, "[REDACTED]") {
			t.Fatalf("%s = %q, want static Store redaction", label, output)
		}
	}
	for _, format := range formats {
		assertRedacted(format, fmt.Sprintf(format, adapter))
		assertRedacted("nested "+format, fmt.Sprintf(format, struct{ Value any }{Value: adapter}))
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuffer, nil)).Info(
		"store",
		"direct", adapter,
		"nested", slog.GroupValue(slog.Any("value", adapter)),
	)
	assertRedacted("slog", logBuffer.String())

	const (
		workers    = 8
		iterations = 64
	)
	concurrentWrites := make([]storecontract.RevisionWrite, iterations)
	for index := range concurrentWrites {
		concurrentWrites[index] = revisionWrite(
			t,
			namespaceCanary,
			"entity concurrent"+strings.Repeat("x", index+1)+" {}",
		)
	}
	start := make(chan struct{})
	formatted := make(chan string, workers*iterations)
	for worker := range workers {
		go func() {
			<-start
			format := formats[worker%len(formats)]
			for range iterations {
				formatted <- fmt.Sprintf(format, adapter)
			}
		}()
	}
	mutationDone := make(chan error, 1)
	go func() {
		<-start
		for _, concurrentWrite := range concurrentWrites {
			if _, err := adapter.PutRevision(context.Background(), concurrentWrite); err != nil {
				mutationDone <- err
				return
			}
		}
		mutationDone <- nil
	}()
	close(start)
	for output := range workers * iterations {
		assertRedacted(fmt.Sprintf("concurrent-%d", output), <-formatted)
	}
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
}

func TestInjectedClockDrivesEventTimestampsAndRetention(t *testing.T) {
	start := time.Unix(2_000, 0).UTC()
	clock := &countingClock{now: start}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		namespace string
		source    string
	}{
		{namespace: "retention-a", source: "entity user {}"},
		{namespace: "retention-a", source: "entity group {}"},
	} {
		if _, err := adapter.PutRevision(context.Background(), revisionWrite(t, input.namespace, input.source)); err != nil {
			t.Fatal(err)
		}
	}
	firstRequest, err := policyengine.NewListEventsRequest("retention-a", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.ListEvents(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if events := first.Events(); len(events) != 1 || !events[0].OccurredAt().Equal(start) || first.NextCursor() == "" {
		t.Fatalf("first event page = %v", first)
	}
	clock.Set(start.Add(defaultEventRetention))
	expiredRequest, err := policyengine.NewListEventsRequest("retention-a", first.NextCursor(), 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ListEvents(context.Background(), expiredRequest)
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr.Category() != policyengine.ErrorCursorExpired {
		t.Fatalf("expired cursor error = %T, want direct CURSOR_EXPIRED", err)
	}
	resync, err := adapter.ListEvents(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(resync.Events()) != 0 {
		t.Fatalf("expired events remained visible: %v", resync)
	}
}

func TestClockRollbackCannotPruneFreshEvents(t *testing.T) {
	base := time.Unix(10_000, 0).UTC()
	clock := &countingClock{now: base.Add(23 * time.Hour)}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.PutRevision(context.Background(), revisionWrite(t, "rollback-a", "entity future {}")); err != nil {
		t.Fatal(err)
	}
	clock.Set(base)
	if _, err := adapter.PutRevision(context.Background(), revisionWrite(t, "rollback-a", "entity rollback {}")); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(25 * time.Hour))
	request, err := policyengine.NewListEventsRequest("rollback-a", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.ListEvents(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if events := page.Events(); len(events) != 2 {
		t.Fatalf("events after forward jump and rollback = %d, want 2", len(events))
	} else if events[1].OccurredAt().Before(events[0].OccurredAt()) {
		t.Fatalf("event timestamps regressed: %v then %v", events[0].OccurredAt(), events[1].OccurredAt())
	}
}

func TestInjectedClockIsReadOnlyForCommittedMutations(t *testing.T) {
	clock := &countingClock{now: time.Unix(1_000, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	write := revisionWrite(t, "clock-a", "entity user {}")
	first, err := adapter.PutRevision(context.Background(), write)
	if err != nil || !first.Created() {
		t.Fatalf("first PutRevision() = %v, %v", first, err)
	}
	duplicate, err := adapter.PutRevision(context.Background(), write)
	if err != nil || duplicate.Created() {
		t.Fatalf("duplicate PutRevision() = %v, %v", duplicate, err)
	}
	if calls := clock.Calls(); calls != 1 {
		t.Fatalf("clock calls = %d, want one committed mutation", calls)
	}
}

func TestWriteDataGenerationOverflowHasNoSideEffects(t *testing.T) {
	const namespace = "data-generation-overflow"
	clock := &countingClock{now: time.Unix(2_100, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	revision := revisionWrite(t, namespace, "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	seedVersion := &dataVersion{generation: math.MaxUint64}
	seedState := &dataState{
		generation:  math.MaxUint64,
		current:     seedVersion,
		idempotency: map[string]idempotencyState{},
	}
	adapter.mu.Lock()
	adapter.data[namespace] = seedState
	adapter.failNextEvent = true
	beforeEffective := adapter.effectiveTime
	beforeEvents := append([]eventRecord(nil), adapter.events[namespace].values...)
	adapter.mu.Unlock()
	beforeClock := clock.Calls()
	request := newMemoryAttributeWrite(t, namespace, revision.Metadata().ID(), math.MaxUint64, "overflow", "secret")
	_, err = adapter.WriteData(context.Background(), request)
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr.Category() != policyengine.ErrorResourceExhausted {
		t.Fatalf("WriteData overflow error = %T/%v, want direct RESOURCE_EXHAUSTED", err, err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.data[namespace] != seedState || seedState.current != seedVersion || seedState.generation != math.MaxUint64 || len(seedState.idempotency) != 0 {
		t.Fatal("WriteData overflow changed data or idempotency state")
	}
	if !adapter.failNextEvent || !reflect.DeepEqual(adapter.events[namespace].values, beforeEvents) {
		t.Fatal("WriteData overflow consumed the event fault or changed events")
	}
	if !adapter.effectiveTime.Equal(beforeEffective) || clock.Calls() != beforeClock {
		t.Fatalf("WriteData overflow effective time/clock calls = %v/%d, want %v/%d", adapter.effectiveTime, clock.Calls(), beforeEffective, beforeClock)
	}
}

func TestActivateGenerationOverflowHasNoSideEffects(t *testing.T) {
	const namespace = "slot-generation-overflow"
	clock := &countingClock{now: time.Unix(2_200, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	revision := revisionWrite(t, namespace, "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	seedActivation, err := policyengine.NewActivation(
		namespace,
		"primary",
		revision.Metadata().ID(),
		math.MaxUint64,
		time.Unix(2_199, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	seedState := &slotState{current: seedActivation, history: []policyengine.Activation{seedActivation}}
	adapter.mu.Lock()
	adapter.slots[namespace] = map[string]*slotState{"primary": seedState}
	adapter.failNextEvent = true
	beforeEffective := adapter.effectiveTime
	beforeEvents := append([]eventRecord(nil), adapter.events[namespace].values...)
	adapter.mu.Unlock()
	beforeClock := clock.Calls()
	expectation, _ := policyengine.NewActiveSlotExpectation(revision.Metadata().ID(), math.MaxUint64)
	request, _ := policyengine.NewActivateRequest(namespace, "primary", revision.Metadata().ID(), expectation)
	_, err = adapter.Activate(context.Background(), request)
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr.Category() != policyengine.ErrorResourceExhausted {
		t.Fatalf("Activate overflow error = %T/%v, want direct RESOURCE_EXHAUSTED", err, err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.slots[namespace]["primary"] != seedState || seedState.current.Generation() != math.MaxUint64 || len(seedState.history) != 1 {
		t.Fatal("Activate overflow changed slot or history state")
	}
	if !adapter.failNextEvent || !reflect.DeepEqual(adapter.events[namespace].values, beforeEvents) {
		t.Fatal("Activate overflow consumed the event fault or changed events")
	}
	if !adapter.effectiveTime.Equal(beforeEffective) || clock.Calls() != beforeClock {
		t.Fatalf("Activate overflow effective time/clock calls = %v/%d, want %v/%d", adapter.effectiveTime, clock.Calls(), beforeEffective, beforeClock)
	}
}

func TestEventSequenceOverflowUsesRetainedOrExpiredHighWaterWithoutSideEffects(t *testing.T) {
	for _, test := range []struct {
		name  string
		state *eventState
	}{
		{
			name: "retained-last",
			state: &eventState{
				values:         []eventRecord{{sequence: math.MaxUint64}},
				expiredThrough: 7,
			},
		},
		{
			name: "expired-through",
			state: &eventState{
				values:         []eventRecord{{sequence: 7}},
				expiredThrough: math.MaxUint64,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const namespace = "event-sequence-overflow"
			clock := &countingClock{now: time.Unix(2_300, 0).UTC()}
			adapter, err := NewWithClock(clock)
			if err != nil {
				t.Fatal(err)
			}
			adapter.mu.Lock()
			adapter.events[namespace] = test.state
			adapter.failNextEvent = true
			beforeEffective := adapter.effectiveTime
			_, directErr := adapter.newEventLocked(policyengine.StateEventInput{
				Namespace:  namespace,
				Kind:       policyengine.StateEventRevisionPublished,
				RevisionID: strings.Repeat("a", 64),
			}, time.Unix(2_300, 0).UTC())
			adapter.mu.Unlock()
			if errorCategory(directErr) != policyengine.ErrorResourceExhausted {
				t.Fatalf("newEventLocked overflow error = %v, want RESOURCE_EXHAUSTED", directErr)
			}
			write := revisionWrite(t, namespace, "entity document {}")
			_, err = adapter.PutRevision(context.Background(), write)
			engineErr, ok := err.(*policyengine.EngineError)
			if !ok || engineErr.Category() != policyengine.ErrorResourceExhausted {
				t.Fatalf("PutRevision overflow error = %T/%v, want direct RESOURCE_EXHAUSTED", err, err)
			}
			adapter.mu.Lock()
			defer adapter.mu.Unlock()
			if !adapter.failNextEvent || len(adapter.revisions[namespace]) != 0 || adapter.revisionOrder[namespace] != nil {
				t.Fatal("event overflow consumed fault or published revision state")
			}
			if adapter.events[namespace] != test.state || !adapter.effectiveTime.Equal(beforeEffective) || clock.Calls() != 0 {
				t.Fatalf("event overflow changed event/effective/clock state: %p/%v/%d", adapter.events[namespace], adapter.effectiveTime, clock.Calls())
			}
		})
	}
}

func TestClockMayReenterStoreReadWithoutDeadlock(t *testing.T) {
	clock := &reentrantClock{now: time.Unix(3_000, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	clock.store = adapter
	done := make(chan error, 1)
	go func() {
		_, err := adapter.PutRevision(context.Background(), revisionWrite(t, "clock-reentrant", "entity user {}"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("PutRevision deadlocked while Clock.Now reentered GetDataGeneration")
	}
}

func TestActivateClockMayReenterStoreReadWithoutDeadlock(t *testing.T) {
	adapter := MustNew()
	revision := revisionWrite(t, "clock-reentrant", "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	adapter.clock = &reentrantClock{store: adapter, now: time.Unix(3_001, 0).UTC()}
	request, err := policyengine.NewActivateRequest(
		"clock-reentrant",
		"primary",
		revision.Metadata().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, callErr := adapter.Activate(context.Background(), request)
		done <- callErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Activate deadlocked while Clock.Now reentered GetDataGeneration")
	}
}

func TestWriteDataClockMayReenterStoreReadWithoutDeadlock(t *testing.T) {
	adapter := MustNew()
	revision := revisionWrite(t, "clock-reentrant", "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	adapter.clock = &reentrantClock{store: adapter, now: time.Unix(3_002, 0).UTC()}
	request := newMemoryAttributeWrite(t, "clock-reentrant", revision.Metadata().ID(), 0, "clock-write", "value")
	done := make(chan error, 1)
	go func() {
		_, callErr := adapter.WriteData(context.Background(), request)
		done <- callErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WriteData deadlocked while Clock.Now reentered GetDataGeneration")
	}
}

func TestListEventsClockMayReenterStoreReadWithoutDeadlock(t *testing.T) {
	adapter := MustNew()
	if _, err := adapter.PutRevision(context.Background(), revisionWrite(t, "clock-reentrant", "entity document {}")); err != nil {
		t.Fatal(err)
	}
	adapter.clock = &reentrantClock{store: adapter, now: time.Now().UTC()}
	request, _ := policyengine.NewListEventsRequest("clock-reentrant", "", 10)
	done := make(chan error, 1)
	go func() {
		_, callErr := adapter.ListEvents(context.Background(), request)
		done <- callErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListEvents deadlocked while Clock.Now reentered GetDataGeneration")
	}
}

type blockingClock struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	now     time.Time
}

func (c *blockingClock) Now() time.Time {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.now
}

type firstBlockingClock struct {
	entered chan struct{}
	release chan struct{}
	now     time.Time

	mu    sync.Mutex
	calls int
}

func (c *firstBlockingClock) Now() time.Time {
	c.mu.Lock()
	c.calls++
	first := c.calls == 1
	c.mu.Unlock()
	if first {
		close(c.entered)
		<-c.release
	}
	return c.now
}

type observedCancelContext struct {
	context.Context
	secondCheck chan struct{}
	once        sync.Once

	mu    sync.Mutex
	calls int
}

func (c *observedCancelContext) Err() error {
	err := c.Context.Err()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.calls++
	second := c.calls == 2
	c.mu.Unlock()
	if second {
		c.once.Do(func() { close(c.secondCheck) })
	}
	return nil
}

func TestCanceledMutationContendingWithBlockedSameNamespaceDoesNotCommit(t *testing.T) {
	clock := &firstBlockingClock{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		now:     time.Unix(3_500, 0).UTC(),
	}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	first := revisionWrite(t, "reservation-cancel", "entity first {}")
	second := revisionWrite(t, "reservation-cancel", "entity second {}")
	firstDone := make(chan error, 1)
	go func() {
		_, callErr := adapter.PutRevision(context.Background(), first)
		firstDone <- callErr
	}()
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("first mutation did not enter Clock.Now")
	}

	base, cancel := context.WithCancel(context.Background())
	contendingCtx := &observedCancelContext{Context: base, secondCheck: make(chan struct{})}
	secondDone := make(chan error, 1)
	go func() {
		_, callErr := adapter.PutRevision(contendingCtx, second)
		secondDone <- callErr
	}()
	select {
	case <-contendingCtx.secondCheck:
	case <-time.After(time.Second):
		close(clock.release)
		t.Fatal("contending mutation did not finish context validation")
	}
	cancel()

	var secondErr error
	select {
	case secondErr = <-secondDone:
		if secondErr == nil {
			close(clock.release)
			t.Fatal("contending mutation succeeded while namespace commit was reserved")
		}
	case <-time.After(100 * time.Millisecond):
		close(clock.release)
		secondErr = <-secondDone
		t.Fatalf("canceled contending mutation waited for the namespace and returned %v", secondErr)
	}
	close(clock.release)
	if callErr := <-firstDone; callErr != nil {
		t.Fatal(callErr)
	}
	if category := errorCategory(secondErr); category != policyengine.ErrorUnavailable && category != policyengine.ErrorCanceled {
		t.Fatalf("contending mutation error = %v, want direct UNAVAILABLE or CANCELED", secondErr)
	}
	adapter.mu.Lock()
	_, committed := adapter.revisions["reservation-cancel"][second.Metadata().ID()]
	events := append([]eventRecord(nil), adapter.events["reservation-cancel"].values...)
	adapter.mu.Unlock()
	if committed || len(events) != 1 {
		t.Fatalf("canceled mutation committed state/events = %v/%d, want false/1", committed, len(events))
	}
}

func TestBlockedNamespaceClockDoesNotSerializeDifferentNamespaceMutation(t *testing.T) {
	clock := &firstBlockingClock{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		now:     time.Unix(3_600, 0).UTC(),
	}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, callErr := adapter.PutRevision(context.Background(), revisionWrite(t, "reservation-a", "entity first {}"))
		firstDone <- callErr
	}()
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("first namespace did not enter Clock.Now")
	}
	secondDone := make(chan error, 1)
	go func() {
		_, callErr := adapter.PutRevision(context.Background(), revisionWrite(t, "reservation-b", "entity second {}"))
		secondDone <- callErr
	}()
	select {
	case callErr := <-secondDone:
		if callErr != nil {
			close(clock.release)
			t.Fatal(callErr)
		}
	case <-time.After(100 * time.Millisecond):
		close(clock.release)
		<-firstDone
		t.Fatal("different namespace mutation waited behind blocked Clock.Now")
	}
	close(clock.release)
	if callErr := <-firstDone; callErr != nil {
		t.Fatal(callErr)
	}
}

func TestBlockingClockDoesNotHoldStoreMutex(t *testing.T) {
	clock := &blockingClock{
		entered: make(chan struct{}), release: make(chan struct{}), now: time.Now().UTC(),
	}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	events, _ := policyengine.NewListEventsRequest("blocking-clock", "", 1)
	listDone := make(chan error, 1)
	go func() { _, callErr := adapter.ListEvents(context.Background(), events); listDone <- callErr }()
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("ListEvents did not enter Clock.Now")
	}
	readDone := make(chan error, 1)
	go func() {
		request, _ := policyengine.NewGetDataGenerationRequest("blocking-clock")
		_, callErr := adapter.GetDataGeneration(context.Background(), request)
		readDone <- callErr
	}()
	select {
	case callErr := <-readDone:
		if callErr != nil {
			t.Fatal(callErr)
		}
	case <-time.After(100 * time.Millisecond):
		close(clock.release)
		t.Fatal("blocking Clock.Now held Store.mu and blocked an unrelated read")
	}
	close(clock.release)
	if callErr := <-listDone; callErr != nil {
		t.Fatal(callErr)
	}
}

func TestConcurrentActivateCASCallsClockOnlyForWinnerAndCommitsOneRecord(t *testing.T) {
	clock := &countingClock{now: time.Unix(4_000, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	revisions := []storecontract.RevisionWrite{
		revisionWrite(t, "activate-race", "entity first {}"),
		revisionWrite(t, "activate-race", "entity second {}"),
	}
	for _, revision := range revisions {
		if _, err := adapter.PutRevision(ctx, revision); err != nil {
			t.Fatal(err)
		}
	}
	baselineCalls := clock.Calls()
	start := make(chan struct{})
	errors := make(chan error, len(revisions))
	for _, revision := range revisions {
		revision := revision
		go func() {
			<-start
			request, requestErr := policyengine.NewActivateRequest(
				"activate-race",
				"primary",
				revision.Metadata().ID(),
				policyengine.NewUnsetSlotExpectation(),
			)
			if requestErr != nil {
				errors <- requestErr
				return
			}
			_, callErr := adapter.Activate(ctx, request)
			errors <- callErr
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	for range revisions {
		switch err := <-errors; errorCategory(err) {
		case "":
			if err != nil {
				t.Fatal(err)
			}
			winners++
		case policyengine.ErrorConflict:
			conflicts++
		default:
			t.Fatalf("Activate race error = %v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("Activate race winners/conflicts = %d/%d, want 1/1", winners, conflicts)
	}
	if calls := clock.Calls() - baselineCalls; calls != 1 {
		t.Fatalf("Activate race clock calls = %d, want winner only", calls)
	}
	adapter.mu.Lock()
	state := adapter.slots["activate-race"]["primary"]
	events := append([]eventRecord(nil), adapter.events["activate-race"].values...)
	adapter.mu.Unlock()
	if state == nil || state.current.Generation() != 1 || len(state.history) != 1 {
		t.Fatalf("Activate race state = %#v, want one generation-1 record", state)
	}
	if len(events) != 3 || events[2].value.Kind() != policyengine.StateEventSlotActivated || events[2].value.SlotGeneration() != 1 {
		t.Fatalf("Activate race events = %v, want two revisions and one generation-1 activation", events)
	}
}

func TestActivateEventFailureRollsBackWithoutReadingClock(t *testing.T) {
	clock := &countingClock{now: time.Unix(5_000, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	revision := revisionWrite(t, "activate-rollback", "entity document {}")
	if _, err := adapter.PutRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewActivateRequest(
		"activate-rollback",
		"primary",
		revision.Metadata().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	baselineCalls := clock.Calls()
	adapter.armNextEventFailure()
	if _, err := adapter.Activate(ctx, request); errorCategory(err) != policyengine.ErrorUnavailable {
		t.Fatalf("failed Activate error = %v, want UNAVAILABLE", err)
	}
	if calls := clock.Calls() - baselineCalls; calls != 0 {
		t.Fatalf("failed Activate clock calls = %d, want zero", calls)
	}
	adapter.mu.Lock()
	state := adapter.slots["activate-rollback"]["primary"]
	eventCount := len(adapter.events["activate-rollback"].values)
	adapter.mu.Unlock()
	if state != nil || eventCount != 1 {
		t.Fatalf("failed Activate state/events = %#v/%d, want nil/revision-only", state, eventCount)
	}
}

type reentrantClock struct {
	store *Store
	now   time.Time
}

func (c *reentrantClock) Now() time.Time {
	request, err := policyengine.NewGetDataGenerationRequest("clock-reentrant")
	if err != nil {
		panic(err)
	}
	if _, err := c.store.GetDataGeneration(context.Background(), request); err != nil {
		panic(err)
	}
	return c.now
}

type mutationReentrantClock struct {
	now      time.Time
	callback func() error
	once     sync.Once

	mu           sync.Mutex
	reentrantErr error
}

func (c *mutationReentrantClock) Now() time.Time {
	c.once.Do(func() {
		err := c.callback()
		c.mu.Lock()
		c.reentrantErr = err
		c.mu.Unlock()
	})
	return c.now
}

func (c *mutationReentrantClock) result() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reentrantErr
}

func TestClockReentrantSameNamespaceMutationsReturnPromptlyWithoutWedge(t *testing.T) {
	t.Run("PutRevision", func(t *testing.T) {
		clock := &mutationReentrantClock{now: time.Unix(5_100, 0).UTC()}
		adapter, err := NewWithClock(clock)
		if err != nil {
			t.Fatal(err)
		}
		write := revisionWrite(t, "mutation-reentry-put", "entity document {}")
		clock.callback = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			_, callErr := adapter.PutRevision(ctx, write)
			return callErr
		}
		done := make(chan error, 1)
		go func() {
			_, callErr := adapter.PutRevision(context.Background(), write)
			done <- callErr
		}()
		select {
		case callErr := <-done:
			if callErr != nil {
				t.Fatal(callErr)
			}
		case <-time.After(time.Second):
			t.Fatal("PutRevision deadlocked when Clock.Now reentered PutRevision")
		}
		if category := errorCategory(clock.result()); category != policyengine.ErrorDeadlineExceeded {
			t.Fatalf("reentrant PutRevision error = %v, want DEADLINE_EXCEEDED", clock.result())
		}
		get, _ := policyengine.NewGetRevisionRequest("mutation-reentry-put", write.Metadata().ID())
		if _, err := adapter.GetRevision(context.Background(), get); err != nil {
			t.Fatalf("outer PutRevision did not commit or store remained wedged: %v", err)
		}
	})

	t.Run("Activate", func(t *testing.T) {
		adapter := MustNew()
		revision := revisionWrite(t, "mutation-reentry-activate", "entity document {}")
		if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
			t.Fatal(err)
		}
		request, _ := policyengine.NewActivateRequest(
			"mutation-reentry-activate", "primary", revision.Metadata().ID(), policyengine.NewUnsetSlotExpectation(),
		)
		clock := &mutationReentrantClock{now: time.Unix(5_200, 0).UTC()}
		clock.callback = func() error {
			_, callErr := adapter.Activate(context.Background(), request)
			return callErr
		}
		adapter.clock = clock
		done := make(chan error, 1)
		go func() {
			_, callErr := adapter.Activate(context.Background(), request)
			done <- callErr
		}()
		select {
		case callErr := <-done:
			if callErr != nil {
				t.Fatal(callErr)
			}
		case <-time.After(time.Second):
			t.Fatal("Activate deadlocked when Clock.Now reentered Activate")
		}
		if category := errorCategory(clock.result()); category != policyengine.ErrorConflict {
			t.Fatalf("reentrant Activate error = %v, want CONFLICT", clock.result())
		}
		resolve, _ := policyengine.NewResolveRequest("mutation-reentry-activate", "primary")
		if _, err := adapter.Resolve(context.Background(), resolve); err != nil {
			t.Fatalf("outer Activate did not commit or store remained wedged: %v", err)
		}
	})

	t.Run("WriteData", func(t *testing.T) {
		adapter := MustNew()
		revision := revisionWrite(t, "mutation-reentry-data", "entity document {}")
		if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
			t.Fatal(err)
		}
		request := newMemoryAttributeWrite(t, "mutation-reentry-data", revision.Metadata().ID(), 0, "outer", "value")
		clock := &mutationReentrantClock{now: time.Unix(5_300, 0).UTC()}
		reentrant := newMemoryAttributeWrite(t, "mutation-reentry-data", revision.Metadata().ID(), 0, "reentrant", "value")
		clock.callback = func() error {
			_, callErr := adapter.WriteData(context.Background(), reentrant)
			return callErr
		}
		adapter.clock = clock
		done := make(chan error, 1)
		go func() {
			_, callErr := adapter.WriteData(context.Background(), request)
			done <- callErr
		}()
		select {
		case callErr := <-done:
			if callErr != nil {
				t.Fatal(callErr)
			}
		case <-time.After(time.Second):
			t.Fatal("WriteData deadlocked when Clock.Now reentered WriteData")
		}
		if category := errorCategory(clock.result()); category != policyengine.ErrorConflict {
			t.Fatalf("reentrant WriteData error = %v, want CONFLICT", clock.result())
		}
		generation, _ := policyengine.NewGetDataGenerationRequest("mutation-reentry-data")
		result, err := adapter.GetDataGeneration(context.Background(), generation)
		if err != nil || result.Generation() != 1 {
			t.Fatalf("outer WriteData generation/error = %d/%v, want 1/nil", result.Generation(), err)
		}
	})
}

func TestRevisionPaginationRemainsOrderedWhenEarlierRevisionIsPublished(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	middle := revisionWriteAt(t, "pagination-a", "entity middle {}", time.Unix(20, 0).UTC())
	later := revisionWriteAt(t, "pagination-a", "entity later {}", time.Unix(30, 0).UTC())
	for _, write := range []storecontract.RevisionWrite{middle, later} {
		if _, err := adapter.PutRevision(ctx, write); err != nil {
			t.Fatal(err)
		}
	}
	firstRequest, err := policyengine.NewListRevisionsRequest("pagination-a", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.ListRevisions(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if revisions := first.Revisions(); len(revisions) != 1 || revisions[0].ID() != middle.Metadata().ID() || first.NextCursor() == "" {
		t.Fatalf("first revision page = %v", first)
	}
	repeated, err := adapter.ListRevisions(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.NextCursor() != first.NextCursor() {
		t.Fatal("repeating an identical page changed its stable cursor")
	}
	earlier := revisionWriteAt(t, "pagination-a", "entity earlier {}", time.Unix(10, 0).UTC())
	if _, err := adapter.PutRevision(ctx, earlier); err != nil {
		t.Fatal(err)
	}
	nextRequest, err := policyengine.NewListRevisionsRequest("pagination-a", first.NextCursor(), 2)
	if err != nil {
		t.Fatal(err)
	}
	next, err := adapter.ListRevisions(ctx, nextRequest)
	if err != nil {
		t.Fatal(err)
	}
	if revisions := next.Revisions(); len(revisions) != 1 || revisions[0].ID() != later.Metadata().ID() {
		t.Fatalf("revision page after insertion = %v, want only later revision", next)
	}
}

func TestRevisionPaginationUsesPersistentBoundedOrderedIndex(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	for index := range 64 {
		publishedAt := time.Unix(int64(100+index), 0).UTC()
		write := revisionWriteAt(t, "revision-index", "entity type"+strings.Repeat("a", index+1)+" {}", publishedAt)
		if _, err := adapter.PutRevision(ctx, write); err != nil {
			t.Fatal(err)
		}
	}
	adapter.mu.Lock()
	root := adapter.revisionOrder["revision-index"]
	adapter.mu.Unlock()
	if root == nil {
		t.Fatal("revision ordered index is missing")
	}
	page := make([]storecontract.RevisionRecord, 0, 3)
	visited, more := revisionPage(root, revisionKey{}, false, 2, func(record storecontract.RevisionRecord) bool {
		page = append(page, record)
		return true
	})
	if len(page) != 2 || !more {
		t.Fatalf("bounded revision page len/more = %d/%v", len(page), more)
	}
	if visited > revisionHeight(root)+3 {
		t.Fatalf("bounded revision page visited %d nodes at height %d", visited, revisionHeight(root))
	}
}

func TestPutRevisionCommitsOrderedIndexMapAndEventAtomically(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	first := revisionWriteAt(t, "revision-atomic", "entity first {}", time.Unix(10, 0).UTC())
	if _, err := adapter.PutRevision(ctx, first); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	originalRoot := adapter.revisionOrder["revision-atomic"]
	adapter.mu.Unlock()
	if originalRoot == nil {
		t.Fatal("first revision did not populate ordered index")
	}
	duplicate, err := adapter.PutRevision(ctx, first)
	if err != nil || duplicate.Created() {
		t.Fatalf("duplicate PutRevision = %v, %v", duplicate, err)
	}
	adapter.mu.Lock()
	duplicateRoot := adapter.revisionOrder["revision-atomic"]
	adapter.mu.Unlock()
	if duplicateRoot != originalRoot {
		t.Fatal("duplicate revision replaced the persistent ordered root")
	}

	second := revisionWriteAt(t, "revision-atomic", "entity second {}", time.Unix(20, 0).UTC())
	adapter.armNextEventFailure()
	if _, err := adapter.PutRevision(ctx, second); errorCategory(err) != policyengine.ErrorUnavailable {
		t.Fatalf("failed PutRevision error = %v, want UNAVAILABLE", err)
	}
	adapter.mu.Lock()
	failedRoot := adapter.revisionOrder["revision-atomic"]
	revisionCount := len(adapter.revisions["revision-atomic"])
	eventCount := len(adapter.events["revision-atomic"].values)
	adapter.mu.Unlock()
	if failedRoot != originalRoot || revisionCount != 1 || eventCount != 1 {
		t.Fatalf("failed PutRevision root/map/events changed = %p/%d/%d", failedRoot, revisionCount, eventCount)
	}
	result, err := adapter.PutRevision(ctx, second)
	if err != nil || !result.Created() {
		t.Fatalf("retried PutRevision = %v, %v", result, err)
	}
	adapter.mu.Lock()
	committedRoot := adapter.revisionOrder["revision-atomic"]
	revisionCount = len(adapter.revisions["revision-atomic"])
	eventCount = len(adapter.events["revision-atomic"].values)
	adapter.mu.Unlock()
	if committedRoot == originalRoot || revisionCount != 2 || eventCount != 2 {
		t.Fatalf("retried PutRevision root/map/events = %p/%d/%d", committedRoot, revisionCount, eventCount)
	}
}

func TestCursorKeyInitializationFailureDoesNotConstructBrokenStore(t *testing.T) {
	adapter, err := newStoreWithCursorKeySource(systemClock{}, func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	})
	if adapter != nil || errorCategory(err) != policyengine.ErrorInternal {
		t.Fatalf("failed key initialization = %p, %T/%v; want nil direct INTERNAL", adapter, err, err)
	}
}

func TestRevisionCursorRoundTripsTimestampsOutsideUnixNanoRange(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	writes := []storecontract.RevisionWrite{
		revisionWriteAt(t, "cursor-time", "entity futureone {}", time.Date(2400, time.January, 2, 3, 4, 5, 6, time.UTC)),
		revisionWriteAt(t, "cursor-time", "entity futuretwo {}", time.Date(2500, time.January, 2, 3, 4, 5, 7, time.UTC)),
	}
	for _, write := range writes {
		if _, err := adapter.PutRevision(ctx, write); err != nil {
			t.Fatal(err)
		}
	}
	firstRequest, err := policyengine.NewListRevisionsRequest("cursor-time", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.ListRevisions(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Revisions(); len(got) != 1 || !got[0].PublishedAt().Equal(writes[0].Metadata().PublishedAt()) || first.NextCursor() == "" {
		t.Fatalf("first extreme-time page = %v", first)
	}
	nextRequest, err := policyengine.NewListRevisionsRequest("cursor-time", first.NextCursor(), 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := adapter.ListRevisions(ctx, nextRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Revisions(); len(got) != 1 || !got[0].PublishedAt().Equal(writes[1].Metadata().PublishedAt()) {
		t.Fatalf("second extreme-time page = %v", next)
	}
}

func TestCursorsAreSelfContainedAuthenticatedScopedAndRegistryFree(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	for _, namespace := range []string{"cursor-secret-a", "cursor-secret-b"} {
		for index, source := range []string{"entity first {}", "entity second {}"} {
			if _, err := adapter.PutRevision(ctx, revisionWriteAt(t, namespace, source, time.Unix(int64(index+1), 0).UTC())); err != nil {
				t.Fatal(err)
			}
		}
	}
	request, err := policyengine.NewListRevisionsRequest("cursor-secret-a", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.ListRevisions(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	cursor := page.NextCursor()
	if cursor == "" || strings.HasPrefix(cursor, "c1") {
		t.Fatalf("cursor is guessable: %q", cursor)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatalf("cursor is not an opaque encoded token: %v", err)
	}
	if bytes.Contains(raw, []byte("cursor-secret-a")) {
		t.Fatal("cursor disclosed raw namespace scope")
	}
	forged := cursor[:len(cursor)-1] + string([]byte{cursor[len(cursor)-1] ^ 1})
	forgedRequest, err := policyengine.NewListRevisionsRequest("cursor-secret-a", forged, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ListRevisions(ctx, forgedRequest); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("forged cursor error = %v", err)
	}
	wrongScope, err := policyengine.NewListRevisionsRequest("cursor-secret-b", cursor, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ListRevisions(ctx, wrongScope); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("wrong-scope cursor error = %v", err)
	}
	storeType := reflect.TypeOf(adapter).Elem()
	if _, ok := storeType.FieldByName("cursors"); ok {
		t.Fatal("Store retains an unbounded cursor registry")
	}
	if _, ok := storeType.FieldByName("cursorIDs"); ok {
		t.Fatal("Store retains an unbounded reverse cursor registry")
	}
}

func TestCursorRejectsMalformedCrossDomainCrossStoreAndCrossSlotTokens(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	namespace := "cursor-scope"
	writes := []storecontract.RevisionWrite{
		revisionWriteAt(t, namespace, "entity first {}", time.Unix(1, 0).UTC()),
		revisionWriteAt(t, namespace, "entity second {}", time.Unix(2, 0).UTC()),
	}
	for _, write := range writes {
		if _, err := adapter.PutRevision(ctx, write); err != nil {
			t.Fatal(err)
		}
	}
	revisionRequest, _ := policyengine.NewListRevisionsRequest(namespace, "", 1)
	revisionPage, err := adapter.ListRevisions(ctx, revisionRequest)
	if err != nil {
		t.Fatal(err)
	}
	revisionCursor := revisionPage.NextCursor()
	raw, err := base64.RawURLEncoding.DecodeString(revisionCursor)
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string]string{
		"truncated":  revisionCursor[:len(revisionCursor)/2],
		"extra-byte": base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw...), 0)),
	}
	wrongVersion := append([]byte(nil), raw...)
	wrongVersion[0]++
	malformed["wrong-version"] = base64.RawURLEncoding.EncodeToString(wrongVersion)
	wrongDomain := append([]byte(nil), raw...)
	wrongDomain[1]++
	malformed["wrong-domain-byte"] = base64.RawURLEncoding.EncodeToString(wrongDomain)
	for name, token := range malformed {
		t.Run(name, func(t *testing.T) {
			request, requestErr := policyengine.NewListRevisionsRequest(namespace, token, 1)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			if _, callErr := adapter.ListRevisions(ctx, request); errorCategory(callErr) != policyengine.ErrorInvalidArgument {
				t.Fatalf("malformed cursor error = %v, want INVALID_ARGUMENT", callErr)
			}
		})
	}
	foreignStore := MustNew()
	crossStore, _ := policyengine.NewListRevisionsRequest(namespace, revisionCursor, 1)
	if _, err := foreignStore.ListRevisions(ctx, crossStore); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("cross-store cursor error = %v", err)
	}
	eventsRequest, _ := policyengine.NewListEventsRequest(namespace, revisionCursor, 1)
	if _, err := adapter.ListEvents(ctx, eventsRequest); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("cross-domain cursor error = %v", err)
	}

	activation, _ := policyengine.NewActivateRequest(namespace, "primary", writes[0].Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	first, err := adapter.Activate(ctx, activation)
	if err != nil {
		t.Fatal(err)
	}
	expectation, _ := policyengine.NewActiveSlotExpectation(first.Activation().RevisionID(), first.Activation().Generation())
	activation, _ = policyengine.NewActivateRequest(namespace, "primary", writes[1].Metadata().ID(), expectation)
	if _, err := adapter.Activate(ctx, activation); err != nil {
		t.Fatal(err)
	}
	historyRequest, _ := policyengine.NewListActivationHistoryRequest(namespace, "primary", "", 1)
	historyPage, err := adapter.ListActivationHistory(ctx, historyRequest)
	if err != nil {
		t.Fatal(err)
	}
	historyCursor := historyPage.NextCursor()
	historyRaw, _ := base64.RawURLEncoding.DecodeString(historyCursor)
	if bytes.Contains(historyRaw, []byte(namespace)) || bytes.Contains(historyRaw, []byte("primary")) {
		t.Fatal("history cursor disclosed raw namespace or slot scope")
	}
	wrongSlot, _ := policyengine.NewListActivationHistoryRequest(namespace, "secondary", historyCursor, 1)
	if _, err := adapter.ListActivationHistory(ctx, wrongSlot); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("wrong-slot cursor error = %v", err)
	}
	adapter.mu.Lock()
	_, oversizedErr := adapter.cursorStateLocked(strings.Repeat("A", policyengine.MaxIdentifierBytes+1), "revision", namespace, "")
	adapter.mu.Unlock()
	if errorCategory(oversizedErr) != policyengine.ErrorInvalidArgument {
		t.Fatalf("oversized cursor error = %v", oversizedErr)
	}
}

func TestInvalidEventCursorIsRejectedBeforeClockOrRetentionWork(t *testing.T) {
	clock := &countingClock{now: time.Unix(10_000, 0).UTC()}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewListEventsRequest("invalid-event-cursor", strings.Repeat("A", 20), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ListEvents(context.Background(), request); errorCategory(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("invalid event cursor error = %v, want INVALID_ARGUMENT", err)
	}
	if calls := clock.Calls(); calls != 0 {
		t.Fatalf("invalid event cursor called clock %d times, want zero", calls)
	}
}

func TestEventCursorExpiresAfterCountPruningAndEmptyCursorResyncs(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	clock := &countingClock{now: now}
	adapter, err := NewWithClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	var firstCursor string
	adapter.mu.Lock()
	for generation := 1; generation <= eventRetentionLimit+1; generation++ {
		event, eventErr := adapter.newEventLocked(policyengine.StateEventInput{
			Namespace: "event-count", Kind: policyengine.StateEventDataWritten, DataGeneration: uint64(generation),
		}, now)
		if eventErr != nil {
			adapter.mu.Unlock()
			t.Fatal(eventErr)
		}
		if generation == 1 {
			firstCursor = event.value.Cursor()
		}
		adapter.appendEventLocked(event, now)
	}
	adapter.mu.Unlock()
	expiredRequest, _ := policyengine.NewListEventsRequest("event-count", firstCursor, 1)
	if _, err := adapter.ListEvents(context.Background(), expiredRequest); errorCategory(err) != policyengine.ErrorCursorExpired {
		t.Fatalf("count-pruned event cursor error = %v, want CURSOR_EXPIRED", err)
	}
	resyncRequest, _ := policyengine.NewListEventsRequest("event-count", "", 1)
	page, err := adapter.ListEvents(context.Background(), resyncRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events()) != 1 {
		t.Fatalf("empty cursor resync page length = %d, want 1", len(page.Events()))
	}
}

func errorCategory(err error) policyengine.ErrorCategory {
	if engineErr, ok := err.(*policyengine.EngineError); ok {
		return engineErr.Category()
	}
	return policyengine.ErrorCategory("")
}

type countingClock struct {
	mu    sync.Mutex
	now   time.Time
	calls int
}

func (c *countingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.now
}

func (c *countingClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *countingClock) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func revisionWrite(t testing.TB, namespace, source string) storecontract.RevisionWrite {
	return revisionWriteAt(t, namespace, source, time.Unix(10, 0).UTC())
}

func revisionWriteAt(t testing.TB, namespace, source string, publishedAt time.Time) storecontract.RevisionWrite {
	t.Helper()
	artifact, err := dsl.CompileArtifact("memory-test.dsl", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := policyengine.NewRevisionMetadata(namespace, id, publishedAt)
	if err != nil {
		t.Fatal(err)
	}
	write, err := storecontract.NewRevisionWrite(metadata, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return write
}

func TestRejectedWriteDoesNotRetainAbsentNamespaceState(t *testing.T) {
	adapter := MustNew()
	revision := revisionWrite(t, "present-write", "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	request := newMemoryAttributeWrite(t, "absent-write", revision.Metadata().ID(), 0, "rejected", "value")
	if _, err := adapter.WriteData(context.Background(), request); errorCategory(err) != policyengine.ErrorNotFound {
		t.Fatalf("rejected write error = %v, want NOT_FOUND", err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if _, ok := adapter.data["absent-write"]; ok {
		t.Fatal("rejected write retained empty namespace data state")
	}
}

func TestOpenSnapshotGenerationZeroDoesNotPersistNamespaceState(t *testing.T) {
	adapter := MustNew()
	request, err := storecontract.NewSnapshotRequest("empty-snapshot", 0, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	view, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if _, ok := adapter.data["empty-snapshot"]; ok {
		t.Fatal("generation-zero snapshot persisted absent namespace data state")
	}
}

func TestCanceledMinimumGenerationWaitDoesNotRetainAbsentNamespaces(t *testing.T) {
	adapter := MustNew()
	for index := range 16 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		request, err := storecontract.NewSnapshotRequest(
			"absent-wait-"+string(rune('a'+index)),
			1,
			time.Unix(1, 0).UTC(),
		)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, err = adapter.OpenSnapshot(ctx, request)
		cancel()
		if errorCategory(err) != policyengine.ErrorDeadlineExceeded {
			t.Fatalf("minimum-generation wait error = %v", err)
		}
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if len(adapter.data) != 0 {
		t.Fatalf("canceled absent-namespace waits retained %d data states", len(adapter.data))
	}
	if len(adapter.waiters) != 0 {
		t.Fatalf("canceled absent-namespace waits retained %d registrations", len(adapter.waiters))
	}
}

func TestAttributeTrieReplacementDeletionPruningAndStructuredPaths(t *testing.T) {
	entity := dsl.EntityRef{Type: "document", ID: "doc"}
	child, err := policyengine.NewAttributePath(entity, []string{"region", "country"}, mustStringValue(t, "old"))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := attributeSet(nil, child)
	if !ok {
		t.Fatal("initial nested attribute insert conflicted")
	}
	replacement, err := policyengine.NewAttributePath(entity, child.Path(), mustStringValue(t, "new"))
	if err != nil {
		t.Fatal(err)
	}
	replaced, ok := attributeSet(root, replacement)
	if !ok {
		t.Fatal("exact replacement conflicted")
	}
	key, _ := policyengine.NewAttributeKeyPath(entity, child.Path())
	oldValue, oldFound := attributeGet(root, key)
	newValue, newFound := attributeGet(replaced, key)
	oldText, _ := oldValue.Value().StringValue()
	newText, _ := newValue.Value().StringValue()
	if !oldFound || !newFound || oldText != "old" || newText != "new" {
		t.Fatalf("immutable exact replacement old/new = %q/%q", oldText, newText)
	}

	deleted := attributeDelete(replaced, key)
	if deleted != nil {
		t.Fatal("deleting an entity's final attribute did not prune the entity and trie")
	}
	if _, found := attributeGet(replaced, key); !found {
		t.Fatal("delete mutated the prior immutable root")
	}
	parent, err := policyengine.NewAttribute(entity, "region", mustStringValue(t, "parent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := attributeSet(deleted, parent); !ok {
		t.Fatal("pruned descendant left a false parent-prefix conflict")
	}

	first, _ := policyengine.NewAttributePath(entity, []string{"ab", "c"}, mustStringValue(t, "first"))
	second, _ := policyengine.NewAttributePath(entity, []string{"a", "bc"}, mustStringValue(t, "second"))
	structured, ok := attributeSet(nil, first)
	if !ok {
		t.Fatal("first structured path insert conflicted")
	}
	structured, ok = attributeSet(structured, second)
	if !ok {
		t.Fatal("distinct path segmentation was flattened into a conflict")
	}
	for _, attribute := range []policyengine.Attribute{first, second} {
		pathKey, _ := policyengine.NewAttributeKeyPath(entity, attribute.Path())
		if _, found := attributeGet(structured, pathKey); !found {
			t.Fatalf("structured path %v was lost", attribute.Path())
		}
	}
}

type cancelOnThirdErrContext struct {
	context.Context
	mu    sync.Mutex
	calls int
	done  <-chan struct{}
}

func (c *cancelOnThirdErrContext) Done() <-chan struct{} { return c.done }

func (c *cancelOnThirdErrContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls >= 3 {
		return context.Canceled
	}
	return nil
}

type cancelAtErrContext struct {
	context.Context
	mu       sync.Mutex
	calls    int
	cancelAt int
}

func (c *cancelAtErrContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestQueryTuplesChecksContextPeriodicallyWithinLargeValidBucket(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	revision := revisionWrite(t, "query-context", "entity document {}")
	if _, err := adapter.PutRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	tuples := make([]policyengine.RelationshipTuple, 128)
	for index := range tuples {
		value, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: resource,
			Relation: "viewer",
			Subject:  dsl.SubjectRef{Type: "user", ID: "subject-" + strings.Repeat("a", index+1)},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		tuples[index] = value
	}
	write, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "query-context", ValidationRevisionID: revision.Metadata().ID(),
		IdempotencyKey: "bucket", TupleWrites: tuples,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.WriteData(ctx, write); err != nil {
		t.Fatal(err)
	}
	request, _ := storecontract.NewSnapshotRequest("query-context", 1, time.Unix(20, 0).UTC())
	view, err := adapter.OpenSnapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	query, _ := storecontract.NewTupleQuery(resource, "viewer", len(tuples))
	canceled := make(chan struct{})
	close(canceled)
	hostile := &cancelOnThirdErrContext{Context: ctx, done: canceled}
	if _, err := view.QueryTuples(hostile, query); errorCategory(err) != policyengine.ErrorCanceled {
		t.Fatalf("large-bucket cancellation error = %v, want CANCELED", err)
	}
}

func TestQueryTuplesBoundsWorkAcrossExpiredExactBucket(t *testing.T) {
	const namespace = "query-expired-work-bound"
	adapter := MustNew()
	resource := dsl.EntityRef{Type: "document", ID: "target"}
	readAt := time.Unix(100, 0).UTC()
	expiresAt := readAt.Add(-time.Nanosecond)
	values := make([]policyengine.RelationshipTuple, policyengine.MaxAggregateWorkItems+1)
	for index := range values {
		value, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: resource,
			Relation: "viewer",
			Subject: dsl.SubjectRef{
				Type: "user",
				ID:   fmt.Sprintf("expired-%06d", index),
			},
		}, &expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		values[index] = value
	}
	var buildBalanced func(int, int) *tupleNode
	buildBalanced = func(start, end int) *tupleNode {
		if start == end {
			return nil
		}
		middle := start + (end-start)/2
		return newTupleNode(
			values[middle].Tuple(),
			values[middle],
			buildBalanced(start, middle),
			buildBalanced(middle+1, end),
		)
	}
	// The direct balanced construction keeps the regression fast. Every value is
	// a legal tuple and the same state is reachable through bounded WriteData
	// batches; only the setup bypasses those repeated commits.
	version := &dataVersion{generation: 1, tuples: buildBalanced(0, len(values))}
	adapter.mu.Lock()
	adapter.data[namespace] = &dataState{
		generation:  1,
		current:     version,
		idempotency: map[string]idempotencyState{},
	}
	adapter.mu.Unlock()
	request, _ := storecontract.NewSnapshotRequest(namespace, 1, readAt)
	view, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	_, err = view.QueryTuples(context.Background(), query)
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr.Category() != policyengine.ErrorResourceExhausted {
		t.Fatalf("expired bucket error = %T/%v, want direct RESOURCE_EXHAUSTED", err, err)
	}
	// One initial check plus floor(MaxAggregateWorkItems/64) periodic checks
	// occur before the work bound. If a final check ran before the bound error,
	// this context would cancel it; RESOURCE_EXHAUSTED intentionally wins.
	cancelAtFinal := &cancelAtErrContext{
		Context:  context.Background(),
		cancelAt: 2 + policyengine.MaxAggregateWorkItems/64,
	}
	_, err = view.QueryTuples(cancelAtFinal, query)
	if errorCategory(err) != policyengine.ErrorResourceExhausted {
		t.Fatalf("work-bound/final-cancellation precedence error = %v, want RESOURCE_EXHAUSTED", err)
	}
}

type closeSnapshotOnFinalErrContext struct {
	context.Context
	snapshot *snapshot
	done     <-chan struct{}

	mu    sync.Mutex
	calls int
}

func (c *closeSnapshotOnFinalErrContext) Done() <-chan struct{} { return c.done }

func (c *closeSnapshotOnFinalErrContext) Err() error {
	c.mu.Lock()
	c.calls++
	calls := c.calls
	c.mu.Unlock()

	c.snapshot.lifecycle.Lock()
	active := c.snapshot.active
	c.snapshot.lifecycle.Unlock()
	if calls >= 2 && (active > 0 || calls >= 3) {
		_ = c.snapshot.Close()
		return context.Canceled
	}
	return nil
}

func TestSnapshotFinalContextMappingMayReenterClose(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(context.Context, storecontract.Snapshot) error
	}{
		{
			name: "tuple",
			call: func(ctx context.Context, view storecontract.Snapshot) error {
				resource := dsl.EntityRef{Type: "document", ID: "doc"}
				query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
				_, err := view.QueryTuples(ctx, query)
				return err
			},
		},
		{
			name: "attribute",
			call: func(ctx context.Context, view storecontract.Snapshot) error {
				key, _ := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "doc"}, "classification")
				_, err := view.GetAttribute(ctx, key)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := MustNew()
			request, _ := storecontract.NewSnapshotRequest("snapshot-final-reentry-"+test.name, 0, time.Unix(20, 0).UTC())
			view, err := adapter.OpenSnapshot(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			closedDone := make(chan struct{})
			close(closedDone)
			ctx := &closeSnapshotOnFinalErrContext{
				Context: context.Background(), snapshot: view.(*snapshot), done: closedDone,
			}
			done := make(chan error, 1)
			go func() { done <- test.call(ctx, view) }()
			select {
			case callErr := <-done:
				if errorCategory(callErr) != policyengine.ErrorCanceled {
					t.Fatalf("snapshot read error = %v, want CANCELED", callErr)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("snapshot read deadlocked when final context Err reentered Close")
			}
			concrete := view.(*snapshot)
			concrete.lifecycle.Lock()
			active, owner, version := concrete.active, concrete.owner, concrete.version
			concrete.lifecycle.Unlock()
			if active != 0 || owner != nil || version != nil {
				t.Fatalf("reentrant Close left snapshot active/owner/version = %d/%p/%p", active, owner, version)
			}
		})
	}
}

func TestSnapshotLateReadsFailPromptlyAndFinalReaderClearsReferencesOnce(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	request, _ := storecontract.NewSnapshotRequest("snapshot-lifecycle", 0, time.Unix(20, 0).UTC())
	view, err := adapter.OpenSnapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	concrete := view.(*snapshot)
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	key, _ := policyengine.NewAttributeKey(resource, "classification")
	pause := adapter.pauseNextSnapshotRead()
	released := false
	release := func() {
		if !released {
			pause.release()
			released = true
		}
	}
	defer release()
	readDone := make(chan error, 1)
	go func() {
		_, callErr := view.QueryTuples(ctx, query)
		readDone <- callErr
	}()
	select {
	case <-pause.entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot read was not admitted")
	}
	closeDone := make(chan error, 4)
	for range 4 {
		go func() { closeDone <- view.Close() }()
	}
	deadline := time.Now().Add(time.Second)
	for {
		concrete.lifecycle.Lock()
		closing := concrete.closing
		active := concrete.active
		owner, version := concrete.owner, concrete.version
		concrete.lifecycle.Unlock()
		if closing {
			if active != 1 || owner == nil || version == nil {
				t.Fatalf("closing snapshot active/owner/version = %d/%p/%p", active, owner, version)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not flip admission")
		}
		time.Sleep(time.Millisecond)
	}
	lateTuple := make(chan error, 1)
	lateAttribute := make(chan error, 1)
	go func() { _, callErr := view.QueryTuples(ctx, query); lateTuple <- callErr }()
	go func() { _, callErr := view.GetAttribute(ctx, key); lateAttribute <- callErr }()
	for name, result := range map[string]<-chan error{"tuple": lateTuple, "attribute": lateAttribute} {
		select {
		case callErr := <-result:
			if errorCategory(callErr) != policyengine.ErrorFailedPrecondition {
				t.Fatalf("late %s read error = %v, want FAILED_PRECONDITION", name, callErr)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("late %s read waited behind Close", name)
		}
	}
	select {
	case <-closeDone:
		t.Fatal("Close returned before admitted reader")
	default:
	}
	release()
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
	}
	concrete.lifecycle.Lock()
	active, owner, version := concrete.active, concrete.owner, concrete.version
	concrete.lifecycle.Unlock()
	if active != 0 || owner != nil || version != nil {
		t.Fatalf("closed snapshot active/owner/version = %d/%p/%p", active, owner, version)
	}
	if view.Namespace() != "snapshot-lifecycle" || view.Generation() != 0 || view.MinimumGeneration() != 0 || !view.ReadAt().Equal(time.Unix(20, 0).UTC()) {
		t.Fatal("snapshot metadata changed after Close")
	}
	if got := fmt.Sprintf("%v %#v", view, view); strings.Contains(got, "snapshot-lifecycle") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("post-close formatting = %q", got)
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdmittedSnapshotReadObeysItsOwnContextDuringClose(t *testing.T) {
	adapter := MustNew()
	request, _ := storecontract.NewSnapshotRequest("snapshot-context", 0, time.Unix(20, 0).UTC())
	view, err := adapter.OpenSnapshot(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	pause := adapter.pauseNextSnapshotRead()
	defer pause.release()
	readCtx, cancel := context.WithCancel(context.Background())
	readDone := make(chan error, 1)
	go func() { _, callErr := view.QueryTuples(readCtx, query); readDone <- callErr }()
	select {
	case <-pause.entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot read was not admitted")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- view.Close() }()
	cancel()
	select {
	case callErr := <-readDone:
		if errorCategory(callErr) != policyengine.ErrorCanceled {
			t.Fatalf("admitted read error = %v, want CANCELED", callErr)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted read ignored its own context")
	}
	select {
	case callErr := <-closeDone:
		if callErr != nil {
			t.Fatal(callErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after canceled admitted read")
	}
}

func TestOpenSnapshotPinsExactImmutableVersionInConstantWork(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	revision := revisionWrite(t, "indexed-a", "entity document {}")
	if _, err := adapter.PutRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "one"}, "classification", mustStringValue(t, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "indexed-a", ValidationRevisionID: revision.Metadata().ID(), IdempotencyKey: "first",
		AttributeWrites: []policyengine.Attribute{attribute},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.WriteData(ctx, request); err != nil {
		t.Fatal(err)
	}
	snapshotRequest, err := storecontract.NewSnapshotRequest("indexed-a", 0, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	view, err := adapter.OpenSnapshot(ctx, snapshotRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	concrete := view.(*snapshot)
	adapter.mu.Lock()
	current := adapter.data["indexed-a"].current
	adapter.mu.Unlock()
	if concrete.version != current {
		t.Fatal("OpenSnapshot did not pin the exact immutable current version")
	}
}

func mustStringValue(t testing.TB, text string) policyengine.Value {
	t.Helper()
	value, err := policyengine.NewStringValue(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type reentrantErrContext struct {
	context.Context
	store *Store

	mu         sync.Mutex
	calls      int
	reentryErr error
}

func (c *reentrantErrContext) Err() error {
	c.mu.Lock()
	c.calls++
	reenter := c.calls == 2
	c.mu.Unlock()
	if reenter {
		request, _ := policyengine.NewGetDataGenerationRequest("context-reentry-probe")
		_, err := c.store.GetDataGeneration(context.Background(), request)
		c.mu.Lock()
		c.reentryErr = err
		c.mu.Unlock()
	}
	return nil
}

func (c *reentrantErrContext) result() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.reentryErr
}

type reentrantOperationFixture struct {
	store          *Store
	revision       storecontract.RevisionWrite
	secondRevision storecontract.RevisionWrite
	getRevision    policyengine.GetRevisionRequest
	listRevisions  policyengine.ListRevisionsRequest
	activate       policyengine.ActivateRequest
	resolve        policyengine.ResolveRequest
	history        policyengine.ListActivationHistoryRequest
	generation     policyengine.GetDataGenerationRequest
	open           storecontract.SnapshotRequest
	writeData      policyengine.WriteDataRequest
	listEvents     policyengine.ListEventsRequest
	eventCursor    string
	query          storecontract.TupleQuery
	attributeKey   policyengine.AttributeKey
}

func newReentrantOperationFixture(t testing.TB) reentrantOperationFixture {
	t.Helper()
	const namespace = "context-reentry"
	ctx := context.Background()
	adapter := MustNew()
	revision := revisionWrite(t, namespace, "entity document {}")
	if _, err := adapter.PutRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	activate, err := policyengine.NewActivateRequest(
		namespace,
		"primary",
		revision.Metadata().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := adapter.Activate(ctx, activate)
	if err != nil {
		t.Fatal(err)
	}
	write := newMemoryAttributeWrite(t, namespace, revision.Metadata().ID(), 0, "initial", "one")
	if _, err := adapter.WriteData(ctx, write); err != nil {
		t.Fatal(err)
	}
	expectation, err := policyengine.NewActiveSlotExpectation(
		activated.Activation().RevisionID(),
		activated.Activation().Generation(),
	)
	if err != nil {
		t.Fatal(err)
	}
	activate, err = policyengine.NewActivateRequest(namespace, "primary", revision.Metadata().ID(), expectation)
	if err != nil {
		t.Fatal(err)
	}
	getRevision, _ := policyengine.NewGetRevisionRequest(namespace, revision.Metadata().ID())
	listRevisions, _ := policyengine.NewListRevisionsRequest(namespace, "", 1)
	resolve, _ := policyengine.NewResolveRequest(namespace, "primary")
	history, _ := policyengine.NewListActivationHistoryRequest(namespace, "primary", "", 1)
	generation, _ := policyengine.NewGetDataGenerationRequest(namespace)
	open, _ := storecontract.NewSnapshotRequest(namespace, 1, time.Unix(20, 0).UTC())
	writeData := newMemoryAttributeWrite(t, namespace, revision.Metadata().ID(), 1, "second", "two")
	listEvents, _ := policyengine.NewListEventsRequest(namespace, "", 1)
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	attributeKey, _ := policyengine.NewAttributeKey(resource, "classification")
	adapter.mu.Lock()
	eventCursor := adapter.events[namespace].values[0].value.Cursor()
	adapter.mu.Unlock()
	return reentrantOperationFixture{
		store: adapter, revision: revision,
		secondRevision: revisionWrite(t, namespace, "entity folder {}"),
		getRevision:    getRevision, listRevisions: listRevisions, activate: activate,
		resolve: resolve, history: history, generation: generation, open: open,
		writeData: writeData, listEvents: listEvents, eventCursor: eventCursor,
		query: query, attributeKey: attributeKey,
	}
}

func TestCallerContextNeverRunsWhileStoreLocksAreHeld(t *testing.T) {
	tests := map[string]func(context.Context, reentrantOperationFixture) error{
		"PutRevision": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.PutRevision(ctx, fixture.secondRevision)
			return err
		},
		"GetRevision": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.GetRevision(ctx, fixture.getRevision)
			return err
		},
		"ListRevisions": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.ListRevisions(ctx, fixture.listRevisions)
			return err
		},
		"Activate": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.Activate(ctx, fixture.activate)
			return err
		},
		"Resolve": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.Resolve(ctx, fixture.resolve)
			return err
		},
		"ListActivationHistory": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.ListActivationHistory(ctx, fixture.history)
			return err
		},
		"GetDataGeneration": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.GetDataGeneration(ctx, fixture.generation)
			return err
		},
		"OpenSnapshot": func(ctx context.Context, fixture reentrantOperationFixture) error {
			view, err := fixture.store.OpenSnapshot(ctx, fixture.open)
			if err == nil {
				err = view.Close()
			}
			return err
		},
		"WriteData": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.WriteData(ctx, fixture.writeData)
			return err
		},
		"ListEvents": func(ctx context.Context, fixture reentrantOperationFixture) error {
			_, err := fixture.store.ListEvents(ctx, fixture.listEvents)
			return err
		},
		"expireEvents": func(ctx context.Context, fixture reentrantOperationFixture) error {
			return fixture.store.expireEvents(ctx, "context-reentry", fixture.eventCursor)
		},
		"SnapshotQueryTuples": func(ctx context.Context, fixture reentrantOperationFixture) error {
			view, err := fixture.store.OpenSnapshot(context.Background(), fixture.open)
			if err != nil {
				return err
			}
			defer func() { _ = view.Close() }()
			_, err = view.QueryTuples(ctx, fixture.query)
			return err
		},
		"SnapshotGetAttribute": func(ctx context.Context, fixture reentrantOperationFixture) error {
			view, err := fixture.store.OpenSnapshot(context.Background(), fixture.open)
			if err != nil {
				return err
			}
			defer func() { _ = view.Close() }()
			_, err = view.GetAttribute(ctx, fixture.attributeKey)
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newReentrantOperationFixture(t)
			ctx := &reentrantErrContext{Context: context.Background(), store: fixture.store}
			done := make(chan error, 1)
			go func() { done <- call(ctx, fixture) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
				calls, reentryErr := ctx.result()
				if calls < 2 || reentryErr != nil {
					t.Fatalf("context Err calls/reentry error = %d/%v, want reentrant second check", calls, reentryErr)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("operation deadlocked when context Err reentered a Store read")
			}
		})
	}
}

type panicErrContext struct{ context.Context }

func (panicErrContext) Err() error { panic("hostile context Err") }

type panicDoneContext struct{ context.Context }

func (panicDoneContext) Done() <-chan struct{} { panic("hostile context Done") }

func requireDirectInternalWithoutPanic(t testing.TB, call func() error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("hostile context panic escaped: %v", recovered)
		}
	}()
	if err := call(); errorCategory(err) != policyengine.ErrorInternal {
		t.Fatalf("hostile context error = %T/%v, want direct INTERNAL", err, err)
	}
}

func TestHostileContextPanicsAreContainedAtEveryOperationBoundary(t *testing.T) {
	adapter := MustNew()
	ctx := context.Background()
	revision := revisionWrite(t, "hostile-a", "entity document {}")
	if _, err := adapter.PutRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	get, _ := policyengine.NewGetRevisionRequest("hostile-a", revision.Metadata().ID())
	list, _ := policyengine.NewListRevisionsRequest("hostile-a", "", 1)
	activate, _ := policyengine.NewActivateRequest("hostile-a", "primary", revision.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	resolve, _ := policyengine.NewResolveRequest("hostile-a", "primary")
	history, _ := policyengine.NewListActivationHistoryRequest("hostile-a", "primary", "", 1)
	head, _ := policyengine.NewGetDataGenerationRequest("hostile-a")
	open, _ := storecontract.NewSnapshotRequest("hostile-a", 0, time.Unix(20, 0).UTC())
	write := newMemoryAttributeWrite(t, "hostile-a", revision.Metadata().ID(), 0, "hostile-write", "one")
	events, _ := policyengine.NewListEventsRequest("hostile-a", "", 1)
	hostile := panicErrContext{Context: ctx}
	calls := map[string]func() error{
		"PutRevision":           func() error { _, err := adapter.PutRevision(hostile, revision); return err },
		"GetRevision":           func() error { _, err := adapter.GetRevision(hostile, get); return err },
		"ListRevisions":         func() error { _, err := adapter.ListRevisions(hostile, list); return err },
		"Activate":              func() error { _, err := adapter.Activate(hostile, activate); return err },
		"Resolve":               func() error { _, err := adapter.Resolve(hostile, resolve); return err },
		"ListActivationHistory": func() error { _, err := adapter.ListActivationHistory(hostile, history); return err },
		"GetDataGeneration":     func() error { _, err := adapter.GetDataGeneration(hostile, head); return err },
		"OpenSnapshot":          func() error { _, err := adapter.OpenSnapshot(hostile, open); return err },
		"WriteData":             func() error { _, err := adapter.WriteData(hostile, write); return err },
		"ListEvents":            func() error { _, err := adapter.ListEvents(hostile, events); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { requireDirectInternalWithoutPanic(t, call) })
	}

	view, err := adapter.OpenSnapshot(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	key, _ := policyengine.NewAttributeKey(resource, "classification")
	t.Run("SnapshotQueryTuples", func(t *testing.T) {
		requireDirectInternalWithoutPanic(t, func() error { _, callErr := view.QueryTuples(hostile, query); return callErr })
	})
	t.Run("SnapshotGetAttribute", func(t *testing.T) {
		requireDirectInternalWithoutPanic(t, func() error { _, callErr := view.GetAttribute(hostile, key); return callErr })
	})
}

func TestHostileContextDonePanicIsContainedAtEveryWait(t *testing.T) {
	adapter := MustNew()
	ctx := panicDoneContext{Context: context.Background()}
	wait, _ := storecontract.NewSnapshotRequest("hostile-wait", 1, time.Unix(20, 0).UTC())
	requireDirectInternalWithoutPanic(t, func() error { _, err := adapter.OpenSnapshot(ctx, wait); return err })

	open, _ := storecontract.NewSnapshotRequest("hostile-wait", 0, time.Unix(20, 0).UTC())
	view, err := adapter.OpenSnapshot(context.Background(), open)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.Close() }()
	resource := dsl.EntityRef{Type: "document", ID: "doc"}
	query, _ := storecontract.NewTupleQuery(resource, "viewer", 1)
	key, _ := policyengine.NewAttributeKey(resource, "classification")
	adapter.armNextSnapshotReadBlock()
	requireDirectInternalWithoutPanic(t, func() error { _, callErr := view.QueryTuples(ctx, query); return callErr })
	adapter.armNextSnapshotReadBlock()
	requireDirectInternalWithoutPanic(t, func() error { _, callErr := view.GetAttribute(ctx, key); return callErr })

	readPause := adapter.pauseNextSnapshotRead()
	defer readPause.release()
	requireDirectInternalWithoutPanic(t, func() error { _, callErr := view.QueryTuples(ctx, query); return callErr })

	revision := revisionWrite(t, "hostile-data-wait", "entity document {}")
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		t.Fatal(err)
	}
	write := newMemoryAttributeWrite(t, "hostile-data-wait", revision.Metadata().ID(), 0, "hostile-pause", "value")
	dataPause := adapter.pauseNextDataCommit()
	defer dataPause.release()
	requireDirectInternalWithoutPanic(t, func() error { _, callErr := adapter.WriteData(ctx, write); return callErr })
}

func newMemoryAttributeWrite(t testing.TB, namespace, revisionID string, expected uint64, idempotencyKey, value string) policyengine.WriteDataRequest {
	t.Helper()
	attribute, err := policyengine.NewAttribute(
		dsl.EntityRef{Type: "document", ID: "doc"},
		"classification",
		mustStringValue(t, value),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: namespace, ValidationRevisionID: revisionID, ExpectedGeneration: expected,
		IdempotencyKey: idempotencyKey, AttributeWrites: []policyengine.Attribute{attribute},
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestStoreConformance(t *testing.T) {
	conformance.Run(t, func(testing.TB) conformance.Fixture {
		adapter := MustNew()
		return conformance.Fixture{
			Store:                      adapter,
			ActivationHistoryRetention: activationHistoryRetention,
			ExpireEvents:               adapter.expireEvents,
			ArmNextEventAppendFailure:  adapter.armNextEventFailure,
			ArmNextSnapshotReadBlock:   adapter.armNextSnapshotReadBlock,
			PauseNextSnapshotRead: func() conformance.SnapshotReadPause {
				pause := adapter.pauseNextSnapshotRead()
				return conformance.SnapshotReadPause{Entered: pause.entered, Release: pause.release}
			},
			PauseNextDataCommit: func() conformance.DataCommitPause {
				pause := adapter.pauseNextDataCommit()
				return conformance.DataCommitPause{Entered: pause.entered, Release: pause.release}
			},
			PauseNextRevisionCommit: func() conformance.RevisionCommitPause {
				pause := adapter.pauseNextRevisionCommit()
				return conformance.RevisionCommitPause{
					Entered: pause.entered, Contended: pause.contended,
					WaiterWoke: pause.waiterWoke, Release: pause.release,
					ResumeWaiter: pause.resumeWaiter,
				}
			},
		}
	})
}
