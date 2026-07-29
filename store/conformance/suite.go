// Package conformance provides reusable black-box tests for local store adapters.
package conformance

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

// Factory creates one fresh isolated adapter fixture per conformance case.
type Factory func(testing.TB) Fixture

// ArmHook deterministically arms one adapter test fault for the next matching
// operation. It is conformance-only and must not be part of production APIs.
type ArmHook func()

// SnapshotReadPause controls one admitted snapshot read. Entered closes only
// after the read owns its pinned resource; Release lets that read continue.
type SnapshotReadPause struct {
	Entered <-chan struct{}
	Release func()
}

// PauseSnapshotReadHook pauses the next admitted tuple or attribute read.
type PauseSnapshotReadHook func() SnapshotReadPause

// DataCommitPause controls one valid WriteData call after it has entered the
// adapter's transaction/commit path but before authoritative CAS and commit.
type DataCommitPause struct {
	Entered <-chan struct{}
	Release func()
}

// PauseDataCommitHook pauses the next valid WriteData commit path.
type PauseDataCommitHook func() DataCommitPause

// Fixture contains a fresh adapter and deterministic black-box test hooks.
// ExpireEvents expires retention through the supplied namespace cursor.
// ArmNextEventAppendFailure makes the next mutation fail atomically with
// UNAVAILABLE while appending its event. ArmNextSnapshotReadBlock makes the
// next snapshot tuple or attribute read wait until its context completes.
// PauseNextSnapshotRead exposes admission and release for Close/read races.
// PauseNextDataCommit exposes transaction-entry and release for commit-order
// races without wrapping or delaying the adapter call itself.
type Fixture struct {
	Store                      store.Store
	ActivationHistoryRetention int
	ExpireEvents               func(context.Context, string, string) error
	ArmNextEventAppendFailure  ArmHook
	ArmNextSnapshotReadBlock   ArmHook
	PauseNextSnapshotRead      PauseSnapshotReadHook
	PauseNextDataCommit        PauseDataCommitHook
}

type testCase struct {
	name string
	run  func(*testing.T, Fixture)
}

var cases = [...]testCase{
	{name: "contexts-and-forged-values", run: testContextsAndForgedValues},
	{name: "immutable-revisions-and-pagination", run: testImmutableRevisionsAndPagination},
	{name: "slot-cas-history-and-race", run: testSlotCASHistoryAndRace},
	{name: "atomic-data-generations-and-snapshots", run: testAtomicDataGenerationsAndSnapshots},
	{name: "minimum-generation-cancellation", run: testMinimumGenerationCancellation},
	{name: "scalable-snapshot-queries", run: testScalableSnapshotQueries},
	{name: "snapshot-close-waits-for-admitted-reads", run: testSnapshotCloseWaitsForAdmittedReads},
	{name: "data-cas-noop-and-race", run: testDataCASNoopAndRace},
	{name: "persisted-attribute-prefix-conflicts", run: testPersistedAttributePrefixConflicts},
	{name: "mutation-event-failure-rollback", run: testMutationEventFailureRollback},
	{name: "idempotency-replay-conflict-and-race", run: testIdempotencyReplayConflictAndRace},
	{name: "event-atomicity-order-and-expiry", run: testEventAtomicityOrderAndExpiry},
	{name: "commit-order-not-call-start-order", run: testCommitOrderNotCallStartOrder},
	{name: "independent-slot-data-domains", run: testIndependentSlotDataDomains},
}

// CaseNames returns a defensive copy of the stable conformance case manifest.
func CaseNames() []string {
	names := make([]string, len(cases))
	for index, test := range cases {
		names[index] = test.name
	}
	return names
}

// Run registers and executes the complete adapter conformance contract.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	if factory == nil {
		t.Fatal("conformance factory is nil")
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := factory(t)
			if nilInterface(fixture.Store) {
				t.Fatal("factory returned nil store")
			}
			if fixture.ActivationHistoryRetention < 2 || fixture.ActivationHistoryRetention > policyengine.MaxPageResponseItems {
				t.Fatal("factory must expose activation-history retention in [2, public page maximum]")
			}
			if fixture.ExpireEvents == nil || fixture.ArmNextEventAppendFailure == nil || fixture.ArmNextSnapshotReadBlock == nil || fixture.PauseNextSnapshotRead == nil || fixture.PauseNextDataCommit == nil {
				t.Fatal("factory must configure every deterministic conformance hook")
			}
			test.run(t, fixture)
		})
	}
}

func testContextsAndForgedValues(t *testing.T, fixture Fixture) {
	adapter := fixture.Store
	artifact := newRevisionInput(t, "scope-context", "entity user {}", 1)
	get, err := policyengine.NewGetRevisionRequest("scope-context", artifact.write.Metadata().ID())
	requireNoError(t, err)
	list, err := policyengine.NewListRevisionsRequest("scope-context", "", 1)
	requireNoError(t, err)
	activate, err := policyengine.NewActivateRequest("scope-context", "primary", artifact.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	requireNoError(t, err)
	resolve, err := policyengine.NewResolveRequest("scope-context", "primary")
	requireNoError(t, err)
	history, err := policyengine.NewListActivationHistoryRequest("scope-context", "primary", "", 1)
	requireNoError(t, err)
	head, err := policyengine.NewGetDataGenerationRequest("scope-context")
	requireNoError(t, err)
	read, err := store.NewSnapshotRequest("scope-context", 0, time.Unix(2, 0).UTC())
	requireNoError(t, err)
	write := newAttributeWrite(t, "scope-context", artifact.write.Metadata().ID(), 0, "context-key", "context-value")
	events, err := policyengine.NewListEventsRequest("scope-context", "", 1)
	requireNoError(t, err)

	calls := map[string]func(context.Context) error{
		"PutRevision":           func(ctx context.Context) error { _, err := adapter.PutRevision(ctx, artifact.write); return err },
		"GetRevision":           func(ctx context.Context) error { _, err := adapter.GetRevision(ctx, get); return err },
		"ListRevisions":         func(ctx context.Context) error { _, err := adapter.ListRevisions(ctx, list); return err },
		"Activate":              func(ctx context.Context) error { _, err := adapter.Activate(ctx, activate); return err },
		"Resolve":               func(ctx context.Context) error { _, err := adapter.Resolve(ctx, resolve); return err },
		"ListActivationHistory": func(ctx context.Context) error { _, err := adapter.ListActivationHistory(ctx, history); return err },
		"GetDataGeneration":     func(ctx context.Context) error { _, err := adapter.GetDataGeneration(ctx, head); return err },
		"OpenSnapshot":          func(ctx context.Context) error { _, err := adapter.OpenSnapshot(ctx, read); return err },
		"WriteData":             func(ctx context.Context) error { _, err := adapter.WriteData(ctx, write); return err },
		"ListEvents":            func(ctx context.Context) error { _, err := adapter.ListEvents(ctx, events); return err },
	}
	var nilContext context.Context
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	for name, call := range calls {
		for suffix, test := range map[string]struct {
			ctx  context.Context
			want policyengine.ErrorCategory
		}{
			"nil":      {ctx: nilContext, want: policyengine.ErrorInvalidArgument},
			"canceled": {ctx: canceled, want: policyengine.ErrorCanceled},
			"deadline": {ctx: deadline, want: policyengine.ErrorDeadlineExceeded},
		} {
			t.Run(name+"-"+suffix, func(t *testing.T) { requireCategory(t, call(test.ctx), test.want) })
		}
	}

	ctx := context.Background()
	for name, call := range map[string]func() error{
		"revision": func() error { _, err := adapter.PutRevision(ctx, store.RevisionWrite{}); return err },
		"get":      func() error { _, err := adapter.GetRevision(ctx, policyengine.GetRevisionRequest{}); return err },
		"activate": func() error { _, err := adapter.Activate(ctx, policyengine.ActivateRequest{}); return err },
		"read":     func() error { _, err := adapter.OpenSnapshot(ctx, store.SnapshotRequest{}); return err },
		"write":    func() error { _, err := adapter.WriteData(ctx, policyengine.WriteDataRequest{}); return err },
		"events":   func() error { _, err := adapter.ListEvents(ctx, policyengine.ListEventsRequest{}); return err },
	} {
		t.Run(name+"-zero", func(t *testing.T) { requireCategory(t, call(), policyengine.ErrorInvalidArgument) })
	}
	_, err = adapter.GetRevision(ctx, get)
	requireCategory(t, err, policyengine.ErrorNotFound)
}

func testImmutableRevisionsAndPagination(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	later := newRevisionInput(t, "revision-a", "entity user {}", 20)
	first, err := adapter.PutRevision(ctx, later.write)
	requireNoError(t, err)
	if !first.Valid() || !first.Created() {
		t.Fatalf("first put = %v, want created valid result", first)
	}
	encoded := later.write.Artifact()
	encoded[0] ^= 0xff
	getLater, err := policyengine.NewGetRevisionRequest("revision-a", later.write.Metadata().ID())
	requireNoError(t, err)
	stored, err := adapter.GetRevision(ctx, getLater)
	requireNoError(t, err)
	if !stored.Valid() || stored.Metadata().PublishedAt() != later.write.Metadata().PublishedAt() {
		t.Fatalf("stored record = %v", stored)
	}
	returned := stored.Artifact()
	returned[0] ^= 0xff
	again, err := adapter.GetRevision(ctx, getLater)
	requireNoError(t, err)
	if reflect.DeepEqual(returned, again.Artifact()) {
		t.Fatal("GetRevision returned mutable aliased artifact")
	}

	duplicateMetadata := mustMetadata(t, "revision-a", later.write.Artifact(), time.Unix(99, 0).UTC())
	duplicateWrite, err := store.NewRevisionWrite(duplicateMetadata, later.write.Artifact())
	requireNoError(t, err)
	duplicate, err := adapter.PutRevision(ctx, duplicateWrite)
	requireNoError(t, err)
	if duplicate.Created() || duplicate.Record().Metadata().PublishedAt() != later.write.Metadata().PublishedAt() {
		t.Fatalf("duplicate put = %v, want original record without mutation", duplicate)
	}

	collisionBytes := artifactBytes(t, "entity document {}")
	collision, err := store.NewRevisionWrite(later.write.Metadata(), collisionBytes)
	requireNoError(t, err)
	_, err = adapter.PutRevision(ctx, collision)
	requireCategory(t, err, policyengine.ErrorIntegrity)

	earlier := newRevisionInput(t, "revision-a", "entity group {}", 10)
	putRevision(t, adapter, earlier.write)
	foreign := newRevisionInput(t, "revision-b", "entity user {}", 1)
	putRevision(t, adapter, foreign.write)
	crossLookup, err := policyengine.NewGetRevisionRequest("revision-b", earlier.write.Metadata().ID())
	requireNoError(t, err)
	_, err = adapter.GetRevision(ctx, crossLookup)
	requireCategory(t, err, policyengine.ErrorNotFound)

	pageRequest, err := policyengine.NewListRevisionsRequest("revision-a", "", 1)
	requireNoError(t, err)
	pageOne, err := adapter.ListRevisions(ctx, pageRequest)
	requireNoError(t, err)
	if got := pageOne.Revisions(); len(got) != 1 || got[0].ID() != earlier.write.Metadata().ID() || pageOne.NextCursor() == "" {
		t.Fatalf("first revision page = %v", pageOne)
	}
	pageTwoRequest, err := policyengine.NewListRevisionsRequest("revision-a", pageOne.NextCursor(), 1)
	requireNoError(t, err)
	pageTwo, err := adapter.ListRevisions(ctx, pageTwoRequest)
	requireNoError(t, err)
	if got := pageTwo.Revisions(); len(got) != 1 || got[0].ID() != later.write.Metadata().ID() || pageTwo.NextCursor() != "" {
		t.Fatalf("second revision page = %v", pageTwo)
	}
	foreignCursor, err := policyengine.NewListRevisionsRequest("revision-b", pageOne.NextCursor(), 1)
	requireNoError(t, err)
	_, err = adapter.ListRevisions(ctx, foreignCursor)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)

	eventRequest, err := policyengine.NewListEventsRequest("revision-a", "", 10)
	requireNoError(t, err)
	eventPage, err := adapter.ListEvents(ctx, eventRequest)
	requireNoError(t, err)
	if got := eventPage.Events(); len(got) != 2 || got[0].Kind() != policyengine.StateEventRevisionPublished || got[1].Kind() != policyengine.StateEventRevisionPublished {
		t.Fatalf("revision events = %v, want exactly two created events", got)
	}
}

func testSlotCASHistoryAndRace(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	one := newRevisionInput(t, "slot-a", "entity user {}", 1)
	two := newRevisionInput(t, "slot-a", "entity document {}", 2)
	putRevision(t, adapter, one.write)
	putRevision(t, adapter, two.write)

	firstRequest := mustActivate(t, "slot-a", "primary", one.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	first, err := adapter.Activate(ctx, firstRequest)
	requireNoError(t, err)
	if got := first.Activation(); got.Generation() != 1 || got.RevisionID() != one.write.Metadata().ID() {
		t.Fatalf("first activation = %v", got)
	}
	_, err = adapter.Activate(ctx, firstRequest)
	requireCategory(t, err, policyengine.ErrorConflict)
	wrongExpectation, err := policyengine.NewActiveSlotExpectation(two.write.Metadata().ID(), 1)
	requireNoError(t, err)
	_, err = adapter.Activate(ctx, mustActivate(t, "slot-a", "primary", two.write.Metadata().ID(), wrongExpectation))
	requireCategory(t, err, policyengine.ErrorConflict)

	exact, err := policyengine.NewActiveSlotExpectation(one.write.Metadata().ID(), 1)
	requireNoError(t, err)
	second, err := adapter.Activate(ctx, mustActivate(t, "slot-a", "primary", two.write.Metadata().ID(), exact))
	requireNoError(t, err)
	if second.Activation().Generation() != 2 {
		t.Fatalf("second generation = %d, want 2", second.Activation().Generation())
	}
	resolve, err := policyengine.NewResolveRequest("slot-a", "primary")
	requireNoError(t, err)
	resolved, err := adapter.Resolve(ctx, resolve)
	requireNoError(t, err)
	if resolved.Activation().RevisionID() != two.write.Metadata().ID() || resolved.Activation().Generation() != 2 {
		t.Fatalf("resolved = %v", resolved)
	}

	historyRequest, err := policyengine.NewListActivationHistoryRequest("slot-a", "primary", "", 1)
	requireNoError(t, err)
	historyOne, err := adapter.ListActivationHistory(ctx, historyRequest)
	requireNoError(t, err)
	if got := historyOne.Activations(); len(got) != 1 || got[0].Generation() != 1 || historyOne.NextCursor() == "" {
		t.Fatalf("history page one = %v", historyOne)
	}
	historyRequest, err = policyengine.NewListActivationHistoryRequest("slot-a", "primary", historyOne.NextCursor(), 1)
	requireNoError(t, err)
	historyTwo, err := adapter.ListActivationHistory(ctx, historyRequest)
	requireNoError(t, err)
	if got := historyTwo.Activations(); len(got) != 1 || got[0].Generation() != 2 {
		t.Fatalf("history page two = %v", historyTwo)
	}

	boundedSlot := "bounded"
	currentRevision := ""
	evictedCursor := ""
	for generation := uint64(1); generation <= uint64(fixture.ActivationHistoryRetention+2); generation++ {
		target := one.write.Metadata().ID()
		if generation%2 == 0 {
			target = two.write.Metadata().ID()
		}
		expectation := policyengine.NewUnsetSlotExpectation()
		if generation > 1 {
			expectation, err = policyengine.NewActiveSlotExpectation(currentRevision, generation-1)
			requireNoError(t, err)
		}
		_, err = adapter.Activate(ctx, mustActivate(t, "slot-a", boundedSlot, target, expectation))
		requireNoError(t, err)
		currentRevision = target
		if generation == 2 {
			pageRequest, pageErr := policyengine.NewListActivationHistoryRequest("slot-a", boundedSlot, "", 1)
			requireNoError(t, pageErr)
			page, pageErr := adapter.ListActivationHistory(ctx, pageRequest)
			requireNoError(t, pageErr)
			evictedCursor = page.NextCursor()
			if evictedCursor == "" {
				t.Fatal("bounded history did not return a cursor after its first item")
			}
		}
	}
	expiredRequest, err := policyengine.NewListActivationHistoryRequest("slot-a", boundedSlot, evictedCursor, 1)
	requireNoError(t, err)
	_, err = adapter.ListActivationHistory(ctx, expiredRequest)
	requireCategory(t, err, policyengine.ErrorCursorExpired)
	boundedHistory := collectActivationHistory(t, adapter, "slot-a", boundedSlot, 2)
	if len(boundedHistory) != fixture.ActivationHistoryRetention {
		t.Fatalf("retained history count = %d, want configured bound %d", len(boundedHistory), fixture.ActivationHistoryRetention)
	}
	wantFirstGeneration := uint64(3)
	if boundedHistory[0].Generation() != wantFirstGeneration ||
		boundedHistory[len(boundedHistory)-1].Generation() != uint64(fixture.ActivationHistoryRetention+2) {
		t.Fatalf("retained history generations = %d..%d, want %d..%d",
			boundedHistory[0].Generation(), boundedHistory[len(boundedHistory)-1].Generation(),
			wantFirstGeneration, fixture.ActivationHistoryRetention+2)
	}

	missing := newRevisionInput(t, "slot-b", "entity group {}", 1)
	putRevision(t, adapter, missing.write)
	_, err = adapter.Activate(ctx, mustActivate(t, "slot-a", "missing-target", missing.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation()))
	requireCategory(t, err, policyengine.ErrorNotFound)
	foreignResolve, err := policyengine.NewResolveRequest("slot-b", "primary")
	requireNoError(t, err)
	_, err = adapter.Resolve(ctx, foreignResolve)
	requireCategory(t, err, policyengine.ErrorNotFound)

	start := make(chan struct{})
	type slotRaceResult struct {
		target     string
		activation policyengine.Activation
		err        error
	}
	results := make(chan slotRaceResult, 2)
	for _, target := range []string{one.write.Metadata().ID(), two.write.Metadata().ID()} {
		target := target
		go func() {
			<-start
			response, callErr := adapter.Activate(ctx, mustActivate(t, "slot-a", "race", target, policyengine.NewUnsetSlotExpectation()))
			results <- slotRaceResult{target: target, activation: response.Activation(), err: callErr}
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	winnerTarget := ""
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			winners++
			winnerTarget = result.target
			if result.activation.RevisionID() != result.target || result.activation.Generation() != 1 {
				t.Fatal("slot race success response does not identify its request")
			}
		case hasCategory(result.err, policyengine.ErrorConflict):
			conflicts++
		default:
			t.Fatal("slot race returned a non-contract error")
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("slot race winners/conflicts = %d/%d", winners, conflicts)
	}
	raceResolve, err := policyengine.NewResolveRequest("slot-a", "race")
	requireNoError(t, err)
	resolvedRace, err := adapter.Resolve(ctx, raceResolve)
	requireNoError(t, err)
	if resolvedRace.Activation().RevisionID() != winnerTarget || resolvedRace.Activation().Generation() != 1 {
		t.Fatal("resolved slot race state does not identify the successful request")
	}
	raceHistory := collectActivationHistory(t, adapter, "slot-a", "race", 10)
	if len(raceHistory) != 1 || raceHistory[0].Generation() != 1 || raceHistory[0].RevisionID() != winnerTarget {
		t.Fatalf("slot race history = %v, want one generation-1 winner", raceHistory)
	}
	raceEvents := 0
	for _, event := range collectEvents(t, adapter, "slot-a", 10) {
		if event.Kind() == policyengine.StateEventSlotActivated && event.Slot() == "race" {
			raceEvents++
			if event.RevisionID() != winnerTarget || event.SlotGeneration() != 1 {
				t.Fatal("slot race event does not identify the successful request")
			}
		}
	}
	if raceEvents != 1 {
		t.Fatalf("slot race events = %d, want one", raceEvents)
	}
}

func testAtomicDataGenerationsAndSnapshots(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "data-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	headRequest, err := policyengine.NewGetDataGenerationRequest("data-a")
	requireNoError(t, err)
	head, err := adapter.GetDataGeneration(ctx, headRequest)
	requireNoError(t, err)
	if !head.Valid() || head.Generation() != 0 {
		t.Fatalf("initial generation = %v, want valid zero", head)
	}

	firstWrite, tupleKey, attributeKey := newTupleAttributeWrite(t, "data-a", revision.write.Metadata().ID(), 0, "data-first")
	first, err := adapter.WriteData(ctx, firstWrite)
	requireNoError(t, err)
	if first.Generation() != 1 || first.Replayed() {
		t.Fatalf("first response = %v", first)
	}
	readAt := time.Unix(100, 0).UTC()
	snapshotOne, err := adapter.OpenSnapshot(ctx, mustRead(t, "data-a", 0, readAt))
	requireNoError(t, err)
	requireSnapshotMetadata(t, snapshotOne, "data-a", 1, 0, readAt)
	if got := querySubjects(t, snapshotOne, tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 2); len(got) != 1 || got[0] != tupleKey.Tuple().Subject {
		t.Fatalf("generation one subjects = %v", got)
	}
	if value, found := getAttribute(t, snapshotOne, attributeKey); !found || value.Kind() != policyengine.ValueKindString {
		t.Fatalf("generation one attribute = %v/%v", value, found)
	}

	secondWrite := newDeleteAndWrite(t, "data-a", revision.write.Metadata().ID(), 1, "data-second", tupleKey, attributeKey)
	second, err := adapter.WriteData(ctx, secondWrite)
	requireNoError(t, err)
	if second.Generation() != 2 {
		t.Fatalf("second generation = %d, want 2", second.Generation())
	}
	if got := querySubjects(t, snapshotOne, tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 2); len(got) != 1 {
		t.Fatalf("pinned generation one subjects after generation two = %v", got)
	}
	if _, found := getAttribute(t, snapshotOne, attributeKey); !found {
		t.Fatal("pinned generation one lost attribute after generation two")
	}

	snapshotTwo, err := adapter.OpenSnapshot(ctx, mustRead(t, "data-a", 1, readAt))
	requireNoError(t, err)
	requireSnapshotMetadata(t, snapshotTwo, "data-a", 2, 1, readAt)
	if got := querySubjects(t, snapshotTwo, tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 2); len(got) != 0 {
		t.Fatalf("generation two deleted subjects = %v", got)
	}
	if _, found := getAttribute(t, snapshotTwo, attributeKey); found {
		t.Fatal("generation two retained deleted attribute")
	}
	replacementKey, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "doc"}, "replacement")
	requireNoError(t, err)
	if value, found := getAttribute(t, snapshotTwo, replacementKey); !found || value.Kind() != policyengine.ValueKindBoolean {
		t.Fatalf("generation two replacement = %v/%v", value, found)
	}

	stale := newAttributeWrite(t, "data-a", revision.write.Metadata().ID(), 1, "data-stale", "stale")
	_, err = adapter.WriteData(ctx, stale)
	requireCategory(t, err, policyengine.ErrorConflict)
	afterFailure, err := adapter.OpenSnapshot(ctx, mustRead(t, "data-a", 0, readAt))
	requireNoError(t, err)
	requireSnapshotMetadata(t, afterFailure, "data-a", 2, 0, readAt)
	if _, found := getAttribute(t, afterFailure, replacementKey); !found {
		t.Fatal("failed CAS changed current snapshot")
	}

	foreignHeadRequest, err := policyengine.NewGetDataGenerationRequest("data-b")
	requireNoError(t, err)
	foreignHead, err := adapter.GetDataGeneration(ctx, foreignHeadRequest)
	requireNoError(t, err)
	if foreignHead.Generation() != 0 {
		t.Fatalf("foreign generation = %d, want zero", foreignHead.Generation())
	}
	foreignSnapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, "data-b", 0, readAt))
	requireNoError(t, err)
	requireSnapshotMetadata(t, foreignSnapshot, "data-b", 0, 0, readAt)
	if got := querySubjects(t, foreignSnapshot, tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 1); len(got) != 0 {
		t.Fatalf("foreign snapshot leaked subjects = %v", got)
	}
	if _, found := getAttribute(t, foreignSnapshot, attributeKey); found {
		t.Fatal("foreign snapshot leaked attribute")
	}
	foreignWrite := newAttributeWrite(t, "data-b", revision.write.Metadata().ID(), 0, "foreign-write", "value")
	_, err = adapter.WriteData(ctx, foreignWrite)
	requireCategory(t, err, policyengine.ErrorNotFound)

	for _, snapshot := range []store.Snapshot{snapshotOne, snapshotTwo, afterFailure, foreignSnapshot} {
		requireNoError(t, snapshot.Close())
		requireNoError(t, snapshot.Close())
	}
	query, err := store.NewTupleQuery(tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 1)
	requireNoError(t, err)
	_, err = snapshotOne.QueryTuples(ctx, query)
	requireCategory(t, err, policyengine.ErrorFailedPrecondition)
	_, err = snapshotOne.GetAttribute(ctx, attributeKey)
	requireCategory(t, err, policyengine.ErrorFailedPrecondition)
}

func testMinimumGenerationCancellation(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "minimum-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := adapter.OpenSnapshot(canceled, mustRead(t, "minimum-a", 1, time.Unix(100, 0).UTC()))
	requireCategory(t, err, policyengine.ErrorCanceled)
	deadline, cancelDeadline := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelDeadline()
	_, err = adapter.OpenSnapshot(deadline, mustRead(t, "minimum-a", 1, time.Unix(100, 0).UTC()))
	requireCategory(t, err, policyengine.ErrorDeadlineExceeded)

	waitContext, cancelWait := context.WithTimeout(ctx, 2*time.Second)
	defer cancelWait()
	result := make(chan struct {
		snapshot store.Snapshot
		err      error
	}, 1)
	go func() {
		snapshot, readErr := adapter.OpenSnapshot(waitContext, mustRead(t, "minimum-a", 1, time.Unix(100, 0).UTC()))
		result <- struct {
			snapshot store.Snapshot
			err      error
		}{snapshot: snapshot, err: readErr}
	}()
	select {
	case <-result:
		t.Fatal("minimum read returned before generation existed")
	case <-time.After(20 * time.Millisecond):
	}
	write := newAttributeWrite(t, "minimum-a", revision.write.Metadata().ID(), 0, "minimum-write", "one")
	_, err = adapter.WriteData(ctx, write)
	requireNoError(t, err)
	completed := <-result
	requireNoError(t, completed.err)
	requireSnapshotMetadata(t, completed.snapshot, "minimum-a", 1, 1, time.Unix(100, 0).UTC())
	requireNoError(t, completed.snapshot.Close())
	second := newAttributeWrite(t, "minimum-a", revision.write.Metadata().ID(), 1, "minimum-second", "two")
	_, err = adapter.WriteData(ctx, second)
	requireNoError(t, err)
	lowerBound, err := adapter.OpenSnapshot(ctx, mustRead(t, "minimum-a", 1, time.Unix(100, 0).UTC()))
	requireNoError(t, err)
	requireSnapshotMetadata(t, lowerBound, "minimum-a", 2, 1, time.Unix(100, 0).UTC())
	requireNoError(t, lowerBound.Close())
}

func testScalableSnapshotQueries(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "scale-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)

	attributes := make([]policyengine.Attribute, policyengine.MaxMutationItems)
	for index := range attributes {
		attribute, err := policyengine.NewAttribute(
			dsl.EntityRef{Type: "document", ID: "bulk-" + strconv.Itoa(index)},
			"flag", policyengine.NewBooleanValue(true),
		)
		requireNoError(t, err)
		attributes[index] = attribute
	}
	bulk, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "scale-a", ValidationRevisionID: revision.write.Metadata().ID(),
		IdempotencyKey: "bulk", AttributeWrites: attributes,
	})
	requireNoError(t, err)
	_, err = adapter.WriteData(ctx, bulk)
	requireNoError(t, err)

	readAt := time.Unix(100, 0).UTC()
	resource := dsl.EntityRef{Type: "document", ID: "target"}
	tuple := func(subject dsl.SubjectRef, expiry time.Time) policyengine.RelationshipTuple {
		value, tupleErr := policyengine.NewRelationshipTuple(dsl.Tuple{Resource: resource, Relation: "viewer", Subject: subject}, &expiry)
		requireNoError(t, tupleErr)
		return value
	}
	tuples := []policyengine.RelationshipTuple{
		tuple(dsl.SubjectRef{Type: "user", ID: "before"}, readAt.Add(-time.Nanosecond)),
		tuple(dsl.SubjectRef{Type: "user", ID: "equal"}, readAt),
		tuple(dsl.SubjectRef{Type: "group", ID: "after", Relation: "member"}, readAt.Add(time.Nanosecond)),
		tuple(dsl.SubjectRef{Type: "user", ID: "later"}, readAt.Add(time.Hour)),
	}
	for _, relationship := range []dsl.Tuple{
		{Resource: resource, Relation: "editor", Subject: dsl.SubjectRef{Type: "user", ID: "editor"}},
		{Resource: dsl.EntityRef{Type: "document", ID: "other"}, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "other"}},
	} {
		value, tupleErr := policyengine.NewRelationshipTuple(relationship, nil)
		requireNoError(t, tupleErr)
		tuples = append(tuples, value)
	}
	stringValue, err := policyengine.NewStringValue("text")
	requireNoError(t, err)
	values := []policyengine.Value{stringValue, policyengine.NewIntegerValue(7), policyengine.NewBooleanValue(true), policyengine.NewNullValue()}
	paths := []string{"string_value", "integer_value", "boolean_value", "null_value"}
	pointAttributes := make([]policyengine.Attribute, len(values))
	for index := range values {
		pointAttributes[index], err = policyengine.NewAttribute(resource, paths[index], values[index])
		requireNoError(t, err)
	}
	nestedAttribute, err := policyengine.NewAttributePath(resource, []string{"region", "country"}, stringValue)
	requireNoError(t, err)
	pointAttributes = append(pointAttributes, nestedAttribute)
	second, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "scale-a", ValidationRevisionID: revision.write.Metadata().ID(), ExpectedGeneration: 1,
		IdempotencyKey: "queries", TupleWrites: tuples, AttributeWrites: pointAttributes,
	})
	requireNoError(t, err)
	_, err = adapter.WriteData(ctx, second)
	requireNoError(t, err)

	snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, "scale-a", 2, readAt))
	requireNoError(t, err)
	requireSnapshotMetadata(t, snapshot, "scale-a", 2, 2, readAt)
	requireSnapshotRedaction(t, snapshot, "scale-a", "bulk-0", "target", "region", "country", "after")
	got := querySubjects(t, snapshot, resource, "viewer", 4)
	want := []dsl.SubjectRef{{Type: "group", ID: "after", Relation: "member"}, {Type: "user", ID: "later"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expiry-filtered subjects = %v, want %v", got, want)
	}
	if got := querySubjects(t, snapshot, resource, "editor", 1); !reflect.DeepEqual(got, []dsl.SubjectRef{{Type: "user", ID: "editor"}}) {
		t.Fatalf("relation-filtered subjects = %v", got)
	}
	if got := querySubjects(t, snapshot, dsl.EntityRef{Type: "document", ID: "other"}, "viewer", 1); !reflect.DeepEqual(got, []dsl.SubjectRef{{Type: "user", ID: "other"}}) {
		t.Fatalf("resource-filtered subjects = %v", got)
	}
	overflow, err := store.NewTupleQuery(resource, "viewer", 1)
	requireNoError(t, err)
	_, err = snapshot.QueryTuples(ctx, overflow)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
	for index, path := range paths {
		key, keyErr := policyengine.NewAttributeKey(resource, path)
		requireNoError(t, keyErr)
		value, found := getAttribute(t, snapshot, key)
		if !found || value.Kind() != values[index].Kind() {
			t.Fatalf("attribute %q = %v/%v", path, value, found)
		}
	}
	nestedKey, err := policyengine.NewAttributeKeyPath(resource, []string{"region", "country"})
	requireNoError(t, err)
	if value, found := getAttribute(t, snapshot, nestedKey); !found || value.Kind() != policyengine.ValueKindString {
		t.Fatalf("nested attribute = %v/%v", value, found)
	}
	missing, err := policyengine.NewAttributeKey(resource, "missing")
	requireNoError(t, err)
	if _, found := getAttribute(t, snapshot, missing); found {
		t.Fatal("missing attribute reported found")
	}
	bulkKey, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "bulk-4095"}, "flag")
	requireNoError(t, err)
	if _, found := getAttribute(t, snapshot, bulkKey); !found {
		t.Fatal("accumulated dataset lost an item beyond one mutation batch")
	}
	query, err := store.NewTupleQuery(resource, "viewer", 4)
	requireNoError(t, err)
	var nilContext context.Context
	_, err = snapshot.QueryTuples(nilContext, query)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
	_, err = snapshot.GetAttribute(nilContext, bulkKey)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)
	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	_, err = snapshot.QueryTuples(canceled, query)
	requireCategory(t, err, policyengine.ErrorCanceled)
	_, err = snapshot.GetAttribute(canceled, bulkKey)
	requireCategory(t, err, policyengine.ErrorCanceled)
	expired, cancelExpired := context.WithDeadline(ctx, time.Unix(1, 0))
	defer cancelExpired()
	_, err = snapshot.QueryTuples(expired, query)
	requireCategory(t, err, policyengine.ErrorDeadlineExceeded)
	_, err = snapshot.GetAttribute(expired, bulkKey)
	requireCategory(t, err, policyengine.ErrorDeadlineExceeded)
	fixture.ArmNextSnapshotReadBlock()
	blockedCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	_, err = snapshot.QueryTuples(blockedCtx, query)
	requireCategory(t, err, policyengine.ErrorDeadlineExceeded)
	fixture.ArmNextSnapshotReadBlock()
	blockedAttributeCtx, cancelAttribute := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelAttribute()
	_, err = snapshot.GetAttribute(blockedAttributeCtx, bulkKey)
	requireCategory(t, err, policyengine.ErrorDeadlineExceeded)
	requireNoError(t, snapshot.Close())
}

func testSnapshotCloseWaitsForAdmittedReads(t *testing.T, fixture Fixture) {
	for _, readKind := range []string{"tuples", "attribute"} {
		readKind := readKind
		t.Run(readKind, func(t *testing.T) {
			for iteration := range 3 {
				ctx := context.Background()
				adapter := fixture.Store
				namespace := "close-" + readKind + "-" + strconv.Itoa(iteration)
				revision := newRevisionInput(t, namespace, "entity document {}", 1)
				putRevision(t, adapter, revision.write)
				write, tupleKey, attributeKey := newTupleAttributeWrite(t, namespace, revision.write.Metadata().ID(), 0, "initial")
				_, err := adapter.WriteData(ctx, write)
				requireNoError(t, err)
				snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, namespace, 1, time.Unix(100, 0).UTC()))
				requireNoError(t, err)
				query, err := store.NewTupleQuery(tupleKey.Tuple().Resource, tupleKey.Tuple().Relation, 2)
				requireNoError(t, err)

				pause := fixture.PauseNextSnapshotRead()
				if pause.Entered == nil || pause.Release == nil {
					t.Fatal("snapshot read pause hook returned invalid control")
				}
				readDone := make(chan error, 1)
				go func() {
					if readKind == "tuples" {
						result, readErr := snapshot.QueryTuples(ctx, query)
						if readErr == nil && len(result.Subjects()) != 1 {
							readErr = policyengineErrorForTest(policyengine.ErrorIntegrity)
						}
						readDone <- readErr
						return
					}
					result, readErr := snapshot.GetAttribute(ctx, attributeKey)
					if readErr == nil && !result.Found() {
						readErr = policyengineErrorForTest(policyengine.ErrorIntegrity)
					}
					readDone <- readErr
				}()
				select {
				case <-pause.Entered:
				case <-time.After(time.Second):
					pause.Release()
					t.Fatal("snapshot read did not reach admitted pause")
				}

				closeDone := make(chan error, 2)
				for range 2 {
					go func() { closeDone <- snapshot.Close() }()
				}
				select {
				case <-closeDone:
					pause.Release()
					t.Fatal("Close returned while an admitted snapshot read was active")
				case <-time.After(20 * time.Millisecond):
				}
				lateTuple := make(chan error, 1)
				lateAttribute := make(chan error, 1)
				go func() {
					_, lateErr := snapshot.QueryTuples(ctx, query)
					lateTuple <- lateErr
				}()
				go func() {
					_, lateErr := snapshot.GetAttribute(ctx, attributeKey)
					lateAttribute <- lateErr
				}()
				pause.Release()
				requireNoError(t, <-readDone)
				requireNoError(t, <-closeDone)
				requireNoError(t, <-closeDone)
				requireCategory(t, <-lateTuple, policyengine.ErrorFailedPrecondition)
				requireCategory(t, <-lateAttribute, policyengine.ErrorFailedPrecondition)
				_, err = snapshot.QueryTuples(ctx, query)
				requireCategory(t, err, policyengine.ErrorFailedPrecondition)
				_, err = snapshot.GetAttribute(ctx, attributeKey)
				requireCategory(t, err, policyengine.ErrorFailedPrecondition)
			}
		})
	}
}

func policyengineErrorForTest(category policyengine.ErrorCategory) error {
	err, constructionErr := policyengine.NewEngineError(category)
	if constructionErr != nil {
		return constructionErr
	}
	return err
}

func requireSnapshotRedaction(t testing.TB, snapshot store.Snapshot, canaries ...string) {
	t.Helper()
	values := []any{snapshot, struct{ Snapshot store.Snapshot }{Snapshot: snapshot}}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
			requireNoCanary(t, fmt.Sprintf(format, value), canaries)
		}
		var output bytes.Buffer
		slog.New(slog.NewTextHandler(&output, nil)).Info("snapshot", "value", value)
		requireNoCanary(t, output.String(), canaries)
	}
	requireNoCanary(t, snapshot.String(), canaries)
	requireNoCanary(t, snapshot.GoString(), canaries)
}

func requireNoCanary(t testing.TB, output string, canaries []string) {
	t.Helper()
	for _, canary := range canaries {
		if strings.Contains(output, canary) {
			t.Fatal("privacy-safe representation leaked a dynamic canary")
		}
	}
}

func testDataCASNoopAndRace(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "data-race", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	one := newAttributeWrite(t, "data-race", revision.write.Metadata().ID(), 0, "race-one", "one")
	two := newAttributeWrite(t, "data-race", revision.write.Metadata().ID(), 0, "race-two", "two")
	start := make(chan struct{})
	type dataRaceInput struct {
		request policyengine.WriteDataRequest
		value   string
	}
	type dataRaceResult struct {
		value    string
		response policyengine.WriteDataResponse
		err      error
	}
	results := make(chan dataRaceResult, 2)
	for _, input := range []dataRaceInput{{request: one, value: "one"}, {request: two, value: "two"}} {
		input := input
		go func() {
			<-start
			response, callErr := adapter.WriteData(ctx, input.request)
			results <- dataRaceResult{value: input.value, response: response, err: callErr}
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	winnerValue := ""
	for range 2 {
		result := <-results
		if result.err == nil {
			winners++
			winnerValue = result.value
			if result.response.Generation() != 1 || result.response.Replayed() {
				t.Fatal("data race success response is not the first non-replay commit")
			}
		} else if hasCategory(result.err, policyengine.ErrorConflict) {
			conflicts++
		} else {
			t.Fatal("distinct data CAS race returned a non-contract error")
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("distinct data CAS winners/conflicts = %d/%d", winners, conflicts)
	}

	snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, "data-race", 1, time.Unix(100, 0).UTC()))
	requireNoError(t, err)
	key, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "doc"}, "classification")
	requireNoError(t, err)
	current, found := getAttribute(t, snapshot, key)
	if !found {
		t.Fatal("winning CAS attribute is missing")
	}
	currentText, ok := current.StringValue()
	if !ok || currentText != winnerValue {
		t.Fatalf("winning CAS attribute = %v", current)
	}
	requireNoError(t, snapshot.Close())
	dataEvents := 0
	for _, event := range collectEvents(t, adapter, "data-race", 10) {
		if event.Kind() == policyengine.StateEventDataWritten {
			dataEvents++
		}
	}
	if dataEvents != 1 {
		t.Fatalf("distinct data CAS events = %d, want one", dataEvents)
	}
	same, err := policyengine.NewAttribute(key.Entity(), key.Name(), current)
	requireNoError(t, err)
	noop, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "data-race", ValidationRevisionID: revision.write.Metadata().ID(), ExpectedGeneration: 1,
		IdempotencyKey: "same-value", AttributeWrites: []policyengine.Attribute{same},
	})
	requireNoError(t, err)
	response, err := adapter.WriteData(ctx, noop)
	requireNoError(t, err)
	if response.Generation() != 2 {
		t.Fatalf("same-value new-key commit generation = %d, want 2", response.Generation())
	}
	absent, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "absent"}, "missing")
	requireNoError(t, err)
	deleteAbsent, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "data-race", ValidationRevisionID: revision.write.Metadata().ID(), ExpectedGeneration: 2,
		IdempotencyKey: "delete-absent", AttributeDeletes: []policyengine.AttributeKey{absent},
	})
	requireNoError(t, err)
	response, err = adapter.WriteData(ctx, deleteAbsent)
	requireNoError(t, err)
	if response.Generation() != 3 {
		t.Fatalf("absent-delete new-key commit generation = %d, want 3", response.Generation())
	}
}

func testPersistedAttributePrefixConflicts(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	for _, test := range []struct {
		name         string
		existingPath []string
		conflictPath []string
	}{
		{name: "parent-to-child", existingPath: []string{"region"}, conflictPath: []string{"region", "country"}},
		{name: "child-to-parent", existingPath: []string{"region", "country"}, conflictPath: []string{"region"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := fixture.Store
			namespace := "prefix-" + test.name
			revision := newRevisionInput(t, namespace, "entity document {}", 1)
			putRevision(t, adapter, revision.write)
			entity := dsl.EntityRef{Type: "document", ID: "doc"}
			existing, err := policyengine.NewAttributePath(entity, test.existingPath, policyengine.NewBooleanValue(true))
			requireNoError(t, err)
			initial, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
				Namespace: namespace, ValidationRevisionID: revision.write.Metadata().ID(),
				IdempotencyKey: "initial", AttributeWrites: []policyengine.Attribute{existing},
			})
			requireNoError(t, err)
			_, err = adapter.WriteData(ctx, initial)
			requireNoError(t, err)

			conflicting, err := policyengine.NewAttributePath(entity, test.conflictPath, policyengine.NewBooleanValue(false))
			requireNoError(t, err)
			conflictRequest, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
				Namespace: namespace, ValidationRevisionID: revision.write.Metadata().ID(), ExpectedGeneration: 1,
				IdempotencyKey: "conflicting", AttributeWrites: []policyengine.Attribute{conflicting},
			})
			requireNoError(t, err)
			_, err = adapter.WriteData(ctx, conflictRequest)
			requireCategory(t, err, policyengine.ErrorConflict)

			headRequest, err := policyengine.NewGetDataGenerationRequest(namespace)
			requireNoError(t, err)
			head, err := adapter.GetDataGeneration(ctx, headRequest)
			requireNoError(t, err)
			if head.Generation() != 1 {
				t.Fatalf("prefix conflict generation = %d, want 1", head.Generation())
			}
			snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, namespace, 1, time.Unix(100, 0).UTC()))
			requireNoError(t, err)
			existingKey, err := policyengine.NewAttributeKeyPath(entity, test.existingPath)
			requireNoError(t, err)
			if _, found := getAttribute(t, snapshot, existingKey); !found {
				t.Fatal("prefix conflict removed existing state")
			}
			conflictKey, err := policyengine.NewAttributeKeyPath(entity, test.conflictPath)
			requireNoError(t, err)
			if _, found := getAttribute(t, snapshot, conflictKey); found {
				t.Fatal("prefix conflict persisted conflicting state")
			}
			requireNoError(t, snapshot.Close())
			if events := collectEvents(t, adapter, namespace, 10); len(events) != 2 {
				t.Fatalf("prefix conflict event count = %d, want publish plus initial write", len(events))
			}

			replacement, err := policyengine.NewAttribute(entity, "replacement", policyengine.NewBooleanValue(true))
			requireNoError(t, err)
			retryScope, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
				Namespace: namespace, ValidationRevisionID: revision.write.Metadata().ID(), ExpectedGeneration: 1,
				IdempotencyKey: "conflicting", AttributeWrites: []policyengine.Attribute{replacement},
			})
			requireNoError(t, err)
			response, err := adapter.WriteData(ctx, retryScope)
			requireNoError(t, err)
			if response.Generation() != 2 || response.Replayed() {
				t.Fatalf("reused failed idempotency scope response = %v", response)
			}
		})
	}
}

func testMutationEventFailureRollback(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store

	failedRevision := newRevisionInput(t, "rollback-revision", "entity document {}", 1)
	fixture.ArmNextEventAppendFailure()
	_, err := adapter.PutRevision(ctx, failedRevision.write)
	requireCategory(t, err, policyengine.ErrorUnavailable)
	getFailedRevision, err := policyengine.NewGetRevisionRequest("rollback-revision", failedRevision.write.Metadata().ID())
	requireNoError(t, err)
	_, err = adapter.GetRevision(ctx, getFailedRevision)
	requireCategory(t, err, policyengine.ErrorNotFound)
	if events := collectEvents(t, adapter, "rollback-revision", 10); len(events) != 0 {
		t.Fatalf("failed revision event count = %d, want zero", len(events))
	}
	revisionRetry, err := adapter.PutRevision(ctx, failedRevision.write)
	requireNoError(t, err)
	if !revisionRetry.Created() {
		t.Fatal("revision retry after event failure was not a new commit")
	}

	activationRevision := newRevisionInput(t, "rollback-activation", "entity document {}", 1)
	putRevision(t, adapter, activationRevision.write)
	activationRequest := mustActivate(t, "rollback-activation", "primary", activationRevision.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	fixture.ArmNextEventAppendFailure()
	_, err = adapter.Activate(ctx, activationRequest)
	requireCategory(t, err, policyengine.ErrorUnavailable)
	resolveRequest, err := policyengine.NewResolveRequest("rollback-activation", "primary")
	requireNoError(t, err)
	_, err = adapter.Resolve(ctx, resolveRequest)
	requireCategory(t, err, policyengine.ErrorNotFound)
	if history := collectActivationHistory(t, adapter, "rollback-activation", "primary", 10); len(history) != 0 {
		t.Fatalf("failed activation history count = %d, want zero", len(history))
	}
	if events := collectEvents(t, adapter, "rollback-activation", 10); len(events) != 1 {
		t.Fatalf("failed activation event count = %d, want revision only", len(events))
	}
	activationRetry, err := adapter.Activate(ctx, activationRequest)
	requireNoError(t, err)
	if activationRetry.Activation().Generation() != 1 {
		t.Fatalf("activation retry generation = %d, want 1", activationRetry.Activation().Generation())
	}

	revision := newRevisionInput(t, "rollback-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	request := newAttributeWrite(t, "rollback-a", revision.write.Metadata().ID(), 0, "rollback-key", "value")
	fixture.ArmNextEventAppendFailure()
	_, err = adapter.WriteData(ctx, request)
	requireCategory(t, err, policyengine.ErrorUnavailable)
	headRequest, err := policyengine.NewGetDataGenerationRequest("rollback-a")
	requireNoError(t, err)
	head, err := adapter.GetDataGeneration(ctx, headRequest)
	requireNoError(t, err)
	if head.Generation() != 0 {
		t.Fatalf("failed event append committed generation %d", head.Generation())
	}
	if events := collectEvents(t, adapter, "rollback-a", 10); len(events) != 1 {
		t.Fatalf("failed mutation event count = %d, want publish only", len(events))
	}
	failedAttribute := request.AttributeWrites()[0]
	failedKey, err := policyengine.NewAttributeKeyPath(failedAttribute.Entity(), failedAttribute.Path())
	requireNoError(t, err)
	snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, "rollback-a", 0, time.Unix(100, 0).UTC()))
	requireNoError(t, err)
	requireSnapshotMetadata(t, snapshot, "rollback-a", 0, 0, time.Unix(100, 0).UTC())
	if _, found := getAttribute(t, snapshot, failedKey); found {
		t.Fatal("failed event append leaked attribute state before retry")
	}
	requireNoError(t, snapshot.Close())
	response, err := adapter.WriteData(ctx, request)
	requireNoError(t, err)
	if response.Generation() != 1 || response.Replayed() {
		t.Fatalf("retry after rolled-back idempotency = %v", response)
	}
}

func testIdempotencyReplayConflictAndRace(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "idem-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	request := newAttributeWrite(t, "idem-a", revision.write.Metadata().ID(), 0, "same-key", "one")
	first, err := adapter.WriteData(ctx, request)
	requireNoError(t, err)
	replay, err := adapter.WriteData(ctx, request)
	requireNoError(t, err)
	if first.Generation() != 1 || first.Replayed() || replay.Generation() != 1 || !replay.Replayed() {
		t.Fatalf("first/replay = %v / %v", first, replay)
	}
	changed := newAttributeWrite(t, "idem-a", revision.write.Metadata().ID(), 0, "same-key", "changed")
	_, err = adapter.WriteData(ctx, changed)
	requireCategory(t, err, policyengine.ErrorConflict)

	foreignRevision := newRevisionInput(t, "idem-b", "entity document {}", 1)
	putRevision(t, adapter, foreignRevision.write)
	foreign := newAttributeWrite(t, "idem-b", foreignRevision.write.Metadata().ID(), 0, "same-key", "changed")
	foreignResponse, err := adapter.WriteData(ctx, foreign)
	requireNoError(t, err)
	if foreignResponse.Generation() != 1 {
		t.Fatalf("foreign same-key generation = %d, want 1", foreignResponse.Generation())
	}

	raceRevision := newRevisionInput(t, "idem-race", "entity document {}", 1)
	putRevision(t, adapter, raceRevision.write)
	raceRequest := newAttributeWrite(t, "idem-race", raceRevision.write.Metadata().ID(), 0, "race-key", "one")
	start := make(chan struct{})
	responses := make(chan policyengine.WriteDataResponse, 8)
	errorsChannel := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			response, callErr := adapter.WriteData(ctx, raceRequest)
			responses <- response
			errorsChannel <- callErr
		}()
	}
	close(start)
	originals, replays := 0, 0
	for range 8 {
		requireNoError(t, <-errorsChannel)
		response := <-responses
		if response.Generation() != 1 {
			t.Fatalf("concurrent replay generation = %d, want 1", response.Generation())
		}
		if response.Replayed() {
			replays++
		} else {
			originals++
		}
	}
	if originals != 1 || replays != 7 {
		t.Fatalf("concurrent originals/replays = %d/%d", originals, replays)
	}
	headRequest, err := policyengine.NewGetDataGenerationRequest("idem-race")
	requireNoError(t, err)
	head, err := adapter.GetDataGeneration(ctx, headRequest)
	requireNoError(t, err)
	if head.Generation() != 1 {
		t.Fatalf("concurrent duplicates committed generation %d, want 1", head.Generation())
	}
	dataEvents := 0
	for _, event := range collectEvents(t, adapter, "idem-race", 10) {
		if event.Kind() == policyengine.StateEventDataWritten {
			dataEvents++
		}
	}
	if dataEvents != 1 {
		t.Fatalf("concurrent idempotent replay events = %d, want one", dataEvents)
	}
}

func testEventAtomicityOrderAndExpiry(t *testing.T, fixture Fixture) {
	if fixture.ExpireEvents == nil {
		t.Fatal("fixture ExpireEvents hook is nil")
	}
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "events-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	duplicate, err := adapter.PutRevision(ctx, revision.write)
	requireNoError(t, err)
	if duplicate.Created() {
		t.Fatal("duplicate revision reported created")
	}
	activation := mustActivate(t, "events-a", "primary", revision.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	_, err = adapter.Activate(ctx, activation)
	requireNoError(t, err)
	_, err = adapter.Activate(ctx, activation)
	requireCategory(t, err, policyengine.ErrorConflict)
	write := newAttributeWrite(t, "events-a", revision.write.Metadata().ID(), 0, "events-write", "one")
	_, err = adapter.WriteData(ctx, write)
	requireNoError(t, err)
	_, err = adapter.WriteData(ctx, write)
	requireNoError(t, err)

	events := collectEvents(t, adapter, "events-a", 2)
	if len(events) != 3 {
		t.Fatalf("events count = %d, want exactly 3 committed mutations", len(events))
	}
	wantKinds := []policyengine.StateEventKind{
		policyengine.StateEventRevisionPublished,
		policyengine.StateEventSlotActivated,
		policyengine.StateEventDataWritten,
	}
	seen := make(map[string]struct{}, len(events))
	for index, event := range events {
		if event.Kind() != wantKinds[index] {
			t.Fatalf("event %d kind = %v, want %v", index, event.Kind(), wantKinds[index])
		}
		if _, duplicateCursor := seen[event.Cursor()]; duplicateCursor {
			t.Fatalf("duplicate cursor %q", event.Cursor())
		}
		seen[event.Cursor()] = struct{}{}
	}
	if events[1].SlotGeneration() != 1 || events[2].DataGeneration() != 1 {
		t.Fatalf("event generations = slot %d data %d", events[1].SlotGeneration(), events[2].DataGeneration())
	}

	requireNoError(t, fixture.ExpireEvents(ctx, "events-a", events[0].Cursor()))
	expiredRequest, err := policyengine.NewListEventsRequest("events-a", events[0].Cursor(), 2)
	requireNoError(t, err)
	_, err = adapter.ListEvents(ctx, expiredRequest)
	requireCategory(t, err, policyengine.ErrorCursorExpired)
	retained := collectEvents(t, adapter, "events-a", 2)
	if len(retained) != 2 || retained[0].Cursor() != events[1].Cursor() || retained[1].Cursor() != events[2].Cursor() {
		t.Fatalf("retained events = %v", retained)
	}

	foreignRequest, err := policyengine.NewListEventsRequest("events-b", "", 10)
	requireNoError(t, err)
	foreign, err := adapter.ListEvents(ctx, foreignRequest)
	requireNoError(t, err)
	if len(foreign.Events()) != 0 {
		t.Fatalf("foreign events leaked = %v", foreign.Events())
	}
}

func testCommitOrderNotCallStartOrder(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "order-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	blockedRequest := newAttributeWrite(t, "order-a", revision.write.Metadata().ID(), 1, "started-first", "second-commit")
	firstCommitRequest := newAttributeWrite(t, "order-a", revision.write.Metadata().ID(), 0, "started-second", "first-commit")
	pause := fixture.PauseNextDataCommit()
	if pause.Entered == nil || pause.Release == nil {
		t.Fatal("data commit pause hook returned invalid control")
	}
	released := false
	release := func() {
		if !released {
			pause.Release()
			released = true
		}
	}
	defer release()
	lateResult := make(chan struct {
		response policyengine.WriteDataResponse
		err      error
	}, 1)
	go func() {
		response, callErr := adapter.WriteData(ctx, blockedRequest)
		lateResult <- struct {
			response policyengine.WriteDataResponse
			err      error
		}{response: response, err: callErr}
	}()
	select {
	case <-pause.Entered:
	case <-time.After(time.Second):
		release()
		t.Fatal("started-first write did not enter adapter commit path")
	}
	first, err := adapter.WriteData(ctx, firstCommitRequest)
	requireNoError(t, err)
	if first.Generation() != 1 {
		t.Fatalf("first commit generation = %d, want 1", first.Generation())
	}
	release()
	late := <-lateResult
	requireNoError(t, late.err)
	if late.response.Generation() != 2 {
		t.Fatalf("later commit generation = %d, want 2", late.response.Generation())
	}
	snapshot, err := adapter.OpenSnapshot(ctx, mustRead(t, "order-a", 2, time.Unix(100, 0).UTC()))
	requireNoError(t, err)
	key, err := policyengine.NewAttributeKey(dsl.EntityRef{Type: "document", ID: "doc"}, "classification")
	requireNoError(t, err)
	value, found := getAttribute(t, snapshot, key)
	text, isString := value.StringValue()
	if !found || !isString || text != "second-commit" {
		t.Fatal("final pinned state does not correspond to the generation-2 commit")
	}
	requireNoError(t, snapshot.Close())
	events := collectEvents(t, adapter, "order-a", 10)
	dataGenerations := make([]uint64, 0, 2)
	for _, event := range events {
		if event.Kind() == policyengine.StateEventDataWritten {
			dataGenerations = append(dataGenerations, event.DataGeneration())
		}
	}
	if !reflect.DeepEqual(dataGenerations, []uint64{1, 2}) {
		t.Fatalf("data event commit order = %v, want [1 2]", dataGenerations)
	}
}

func testIndependentSlotDataDomains(t *testing.T, fixture Fixture) {
	ctx := context.Background()
	adapter := fixture.Store
	revision := newRevisionInput(t, "domains-a", "entity document {}", 1)
	putRevision(t, adapter, revision.write)
	activate := mustActivate(t, "domains-a", "primary", revision.write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	write := newAttributeWrite(t, "domains-a", revision.write.Metadata().ID(), 0, "domains-write", "one")
	start := make(chan struct{})
	activationResult := make(chan struct {
		response policyengine.ActivateResponse
		err      error
	}, 1)
	writeResult := make(chan struct {
		response policyengine.WriteDataResponse
		err      error
	}, 1)
	go func() {
		<-start
		response, callErr := adapter.Activate(ctx, activate)
		activationResult <- struct {
			response policyengine.ActivateResponse
			err      error
		}{response: response, err: callErr}
	}()
	go func() {
		<-start
		response, callErr := adapter.WriteData(ctx, write)
		writeResult <- struct {
			response policyengine.WriteDataResponse
			err      error
		}{response: response, err: callErr}
	}()
	close(start)
	activated := <-activationResult
	written := <-writeResult
	requireNoError(t, activated.err)
	requireNoError(t, written.err)
	if activated.response.Activation().Generation() != 1 || written.response.Generation() != 1 {
		t.Fatalf("independent generations = slot %d data %d", activated.response.Activation().Generation(), written.response.Generation())
	}
	events := collectEvents(t, adapter, "domains-a", 10)
	if len(events) != 3 {
		t.Fatalf("independent mutation events = %d, want publish+activate+data", len(events))
	}
	kinds := map[policyengine.StateEventKind]int{}
	for _, event := range events {
		kinds[event.Kind()]++
	}
	if kinds[policyengine.StateEventSlotActivated] != 1 || kinds[policyengine.StateEventDataWritten] != 1 {
		t.Fatalf("independent event kinds = %v", kinds)
	}
}

type revisionInput struct {
	write store.RevisionWrite
}

func newRevisionInput(t testing.TB, namespace, source string, publishedSecond int64) revisionInput {
	t.Helper()
	encoded := artifactBytes(t, source)
	metadata := mustMetadata(t, namespace, encoded, time.Unix(publishedSecond, 0).UTC())
	write, err := store.NewRevisionWrite(metadata, encoded)
	requireNoError(t, err)
	return revisionInput{write: write}
}

func artifactBytes(t testing.TB, source string) []byte {
	t.Helper()
	artifact, err := dsl.CompileArtifact("conformance.dsl", []byte(source))
	requireNoError(t, err)
	encoded, err := artifact.MarshalBinary()
	requireNoError(t, err)
	return encoded
}

func mustMetadata(t testing.TB, namespace string, encoded []byte, publishedAt time.Time) policyengine.RevisionMetadata {
	t.Helper()
	artifact, err := dsl.DecodeArtifact(encoded)
	requireNoError(t, err)
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	requireNoError(t, err)
	metadata, err := policyengine.NewRevisionMetadata(namespace, id, publishedAt)
	requireNoError(t, err)
	return metadata
}

func putRevision(t testing.TB, adapter store.Store, write store.RevisionWrite) store.RevisionRecord {
	t.Helper()
	result, err := adapter.PutRevision(context.Background(), write)
	requireNoError(t, err)
	if !result.Created() || !result.Valid() {
		t.Fatalf("PutRevision() = %v, want new valid record", result)
	}
	return result.Record()
}

func mustActivate(t testing.TB, namespace, slot, revisionID string, expectation policyengine.SlotExpectation) policyengine.ActivateRequest {
	t.Helper()
	request, err := policyengine.NewActivateRequest(namespace, slot, revisionID, expectation)
	requireNoError(t, err)
	return request
}

func mustRead(t testing.TB, namespace string, minimum uint64, readAt time.Time) store.SnapshotRequest {
	t.Helper()
	request, err := store.NewSnapshotRequest(namespace, minimum, readAt)
	requireNoError(t, err)
	return request
}

func requireSnapshotMetadata(t testing.TB, snapshot store.Snapshot, namespace string, generation, minimum uint64, readAt time.Time) {
	t.Helper()
	if nilInterface(snapshot) {
		t.Fatal("snapshot is nil or typed nil")
	}
	if snapshot.Namespace() != namespace || snapshot.Generation() != generation ||
		snapshot.MinimumGeneration() != minimum || !snapshot.ReadAt().Equal(readAt) {
		t.Fatalf("snapshot metadata = %q/%d/%d/%v, want %q/%d/%d/%v",
			snapshot.Namespace(), snapshot.Generation(), snapshot.MinimumGeneration(), snapshot.ReadAt(),
			namespace, generation, minimum, readAt)
	}
}

func querySubjects(t testing.TB, snapshot store.Snapshot, resource dsl.EntityRef, relation string, limit int) []dsl.SubjectRef {
	t.Helper()
	query, err := store.NewTupleQuery(resource, relation, limit)
	requireNoError(t, err)
	result, err := snapshot.QueryTuples(context.Background(), query)
	requireNoError(t, err)
	if !result.Valid() || result.Query() != query {
		t.Fatalf("tuple result is invalid or not request-bound: %v", result)
	}
	return result.Subjects()
}

func getAttribute(t testing.TB, snapshot store.Snapshot, key policyengine.AttributeKey) (policyengine.Value, bool) {
	t.Helper()
	result, err := snapshot.GetAttribute(context.Background(), key)
	requireNoError(t, err)
	if !result.Valid() || result.Key().Entity() != key.Entity() || !reflect.DeepEqual(result.Key().Path(), key.Path()) {
		t.Fatalf("attribute result is invalid or not key-bound: %v", result)
	}
	return result.Value()
}

func newAttributeWrite(t testing.TB, namespace, revisionID string, expected uint64, key, text string) policyengine.WriteDataRequest {
	t.Helper()
	value, err := policyengine.NewStringValue(text)
	requireNoError(t, err)
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc"}, "classification", value)
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            namespace,
		ValidationRevisionID: revisionID,
		ExpectedGeneration:   expected,
		IdempotencyKey:       key,
		AttributeWrites:      []policyengine.Attribute{attribute},
	})
	requireNoError(t, err)
	return request
}

func newTupleAttributeWrite(t testing.TB, namespace, revisionID string, expected uint64, key string) (policyengine.WriteDataRequest, policyengine.TupleKey, policyengine.AttributeKey) {
	t.Helper()
	tupleValue := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "doc"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "user"},
	}
	expiresAt := time.Unix(200, 0).UTC()
	tuple, err := policyengine.NewRelationshipTuple(tupleValue, &expiresAt)
	requireNoError(t, err)
	tupleKey, err := policyengine.NewTupleKey(tupleValue)
	requireNoError(t, err)
	value, err := policyengine.NewStringValue("secret")
	requireNoError(t, err)
	entity := dsl.EntityRef{Type: "document", ID: "doc"}
	attribute, err := policyengine.NewAttribute(entity, "classification", value)
	requireNoError(t, err)
	attributeKey, err := policyengine.NewAttributeKey(entity, "classification")
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            namespace,
		ValidationRevisionID: revisionID,
		ExpectedGeneration:   expected,
		IdempotencyKey:       key,
		TupleWrites:          []policyengine.RelationshipTuple{tuple},
		AttributeWrites:      []policyengine.Attribute{attribute},
	})
	requireNoError(t, err)
	return request, tupleKey, attributeKey
}

func newDeleteAndWrite(t testing.TB, namespace, revisionID string, expected uint64, key string, tupleKey policyengine.TupleKey, attributeKey policyengine.AttributeKey) policyengine.WriteDataRequest {
	t.Helper()
	value := policyengine.NewBooleanValue(true)
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc"}, "replacement", value)
	requireNoError(t, err)
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            namespace,
		ValidationRevisionID: revisionID,
		ExpectedGeneration:   expected,
		IdempotencyKey:       key,
		TupleDeletes:         []policyengine.TupleKey{tupleKey},
		AttributeWrites:      []policyengine.Attribute{attribute},
		AttributeDeletes:     []policyengine.AttributeKey{attributeKey},
	})
	requireNoError(t, err)
	return request
}

func collectEvents(t testing.TB, adapter store.Store, namespace string, limit int) []policyengine.StateEvent {
	t.Helper()
	cursor := ""
	result := []policyengine.StateEvent{}
	seen := map[string]struct{}{}
	for {
		request, err := policyengine.NewListEventsRequest(namespace, cursor, limit)
		requireNoError(t, err)
		page, err := adapter.ListEvents(context.Background(), request)
		requireNoError(t, err)
		for _, event := range page.Events() {
			if _, duplicate := seen[event.Cursor()]; duplicate {
				t.Fatalf("duplicate event cursor %q across pages", event.Cursor())
			}
			seen[event.Cursor()] = struct{}{}
			result = append(result, event)
		}
		next := page.NextCursor()
		if next == "" {
			return result
		}
		if next == cursor {
			t.Fatalf("event cursor did not advance from %q", cursor)
		}
		cursor = next
	}
}

func collectActivationHistory(
	t testing.TB,
	adapter store.Store,
	namespace string,
	slot string,
	limit int,
) []policyengine.Activation {
	t.Helper()
	cursor := ""
	result := []policyengine.Activation{}
	seen := map[uint64]struct{}{}
	for {
		request, err := policyengine.NewListActivationHistoryRequest(namespace, slot, cursor, limit)
		requireNoError(t, err)
		page, err := adapter.ListActivationHistory(context.Background(), request)
		requireNoError(t, err)
		for _, activation := range page.Activations() {
			if _, duplicate := seen[activation.Generation()]; duplicate {
				t.Fatalf("duplicate activation generation %d across pages", activation.Generation())
			}
			seen[activation.Generation()] = struct{}{}
			result = append(result, activation)
		}
		next := page.NextCursor()
		if next == "" {
			return result
		}
		if next == cursor {
			t.Fatalf("activation-history cursor did not advance from %q", cursor)
		}
		cursor = next
	}
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error type %T", err)
	}
}

func requireCategory(t testing.TB, err error, want policyengine.ErrorCategory) {
	t.Helper()
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr == nil || engineErr.Category() != want {
		t.Fatalf("error type/category mismatch, want %s", want)
	}
	if engineErr.Error() != want.String() {
		t.Fatalf("error text = %q, want sanitized %q", engineErr.Error(), want.String())
	}
}

func hasCategory(err error, want policyengine.ErrorCategory) bool {
	engineErr, ok := err.(*policyengine.EngineError)
	return ok && engineErr != nil && engineErr.Category() == want && engineErr.Error() == want.String()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
