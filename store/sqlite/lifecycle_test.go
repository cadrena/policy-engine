package sqlite

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

type sqlitePutResult struct {
	result store.PutRevisionResult
	err    error
}

type sqliteActivateResult struct {
	target     string
	activation policyengine.Activation
	err        error
}

type sqliteMutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *sqliteMutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *sqliteMutableClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

func TestMigratedStoreLoadRejectsMissingOrMalformedCursorKey(t *testing.T) {
	// This catches a runtime opener that silently generates or repairs the
	// durable signing key rather than failing closed on damaged state.
	for _, tc := range []struct {
		name   string
		mutate string
	}{
		{name: "missing", mutate: "DELETE FROM cadrena_meta WHERE key = 'cursor_hmac_key'"},
		{name: "wrong length", mutate: "UPDATE cadrena_meta SET value = X'00' WHERE key = 'cursor_hmac_key'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
			if _, err := ApplyMigrations(context.Background(), config); err != nil {
				t.Fatalf("ApplyMigrations() error = %v", err)
			}
			db := openRawSQLite(t, config.Path)
			mustExecMigrationTest(t, db, tc.mutate)
			if err := db.Close(); err != nil {
				t.Fatalf("close corrupt database: %v", err)
			}

			opened, err := openMigratedStore(context.Background(), config)
			if opened != nil {
				_ = opened.Close()
				t.Fatal("openMigratedStore() returned a store for corrupt cursor key")
			}
			if got := categoryOf(err); got != policyengine.ErrorIntegrity {
				t.Fatalf("openMigratedStore() category = %v, want %v", got, policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestRevisionSurvivesReopenAndFirstWriterProvenanceWins(t *testing.T) {
	// This catches an adapter that retains revision state only in process memory,
	// aliases artifact bytes, or mutates immutable first-writer provenance on an
	// equivalent retry.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	first := newSQLiteRevisionWrite(t, "revision-ns", "first.cdr", []byte("entity user {\n}\n"), time.Unix(20, 0).UTC())
	adapter := openMigratedStoreForTest(t, config)
	created, err := adapter.PutRevision(context.Background(), first)
	if err != nil {
		t.Fatalf("first PutRevision() error = %v", err)
	}
	if !created.Created() {
		t.Fatal("first PutRevision() did not create a revision")
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	reopened := openMigratedStoreForTest(t, config)
	get, err := policyengine.NewGetRevisionRequest("revision-ns", first.Metadata().ID())
	if err != nil {
		t.Fatalf("NewGetRevisionRequest() error = %v", err)
	}
	stored, err := reopened.GetRevision(context.Background(), get)
	if err != nil {
		t.Fatalf("GetRevision() after reopen error = %v", err)
	}
	if got, want := stored.Artifact(), first.Artifact(); !bytes.Equal(got, want) {
		t.Fatalf("stored artifact = %x, want %x", got, want)
	}
	if got, want := stored.Provenance().OriginalSource(), first.Provenance().OriginalSource(); !bytes.Equal(got, want) {
		t.Fatalf("stored provenance = %q, want %q", got, want)
	}

	retry := newSQLiteRevisionWrite(t, "revision-ns", "retry.cdr", []byte("entity user {}"), time.Unix(99, 0).UTC())
	if got, want := retry.Metadata().ID(), first.Metadata().ID(); got != want {
		t.Fatalf("equivalent source revision ID = %q, want %q", got, want)
	}
	reused, err := reopened.PutRevision(context.Background(), retry)
	if err != nil {
		t.Fatalf("equivalent PutRevision() error = %v", err)
	}
	if reused.Created() {
		t.Fatal("equivalent PutRevision() created a duplicate revision")
	}
	if got, want := reused.Record().Provenance().SourceName(), "first.cdr"; got != want {
		t.Fatalf("reused provenance source name = %q, want first writer %q", got, want)
	}
}

func TestRevisionNilLifecycleObserverLeavesPublicationUnchanged(t *testing.T) {
	// The observer is an optional test-only synchronization seam. Its nil
	// production default must leave normal publication, idempotency, and event
	// creation unchanged.
	adapter := openMigratedStoreForTest(t)
	adapter.revisions.mu.Lock()
	observer := adapter.revisions.observer
	adapter.revisions.mu.Unlock()
	if observer != nil {
		t.Fatal("new production-style store unexpectedly has a lifecycle observer")
	}
	write := newSQLiteRevisionWrite(t, "nil-observer", "normal.cdr", []byte("entity user {}"), time.Unix(1, 0).UTC())
	first, err := adapter.PutRevision(context.Background(), write)
	if err != nil || !first.Created() {
		t.Fatalf("first PutRevision() = %+v, %v", first, err)
	}
	retry, err := adapter.PutRevision(context.Background(), write)
	if err != nil || retry.Created() {
		t.Fatalf("idempotent PutRevision() = %+v, %v", retry, err)
	}
	eventsRequest, err := policyengine.NewListEventsRequest("nil-observer", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	events, err := adapter.ListEvents(context.Background(), eventsRequest)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if got := events.Events(); len(got) != 1 || got[0].Kind() != policyengine.StateEventRevisionPublished {
		t.Fatalf("nil-observer publication events = %#v, want one publication", got)
	}
}

func TestRevisionListsPublicationOrderAndRejectsDigestCollision(t *testing.T) {
	// This catches a query ordered by insertion/index direction instead of the
	// public ascending contract, and an identity collision that overwrites bytes.
	adapter := openMigratedStoreForTest(t)
	earlier := newSQLiteRevisionWrite(t, "revision-page", "early.cdr", []byte("entity group {}"), time.Unix(10, 0).UTC())
	later := newSQLiteRevisionWrite(t, "revision-page", "later.cdr", []byte("entity document {}"), time.Unix(20, 0).UTC())
	for _, write := range []store.RevisionWrite{later, earlier} {
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision() error = %v", err)
		}
	}
	request, err := policyengine.NewListRevisionsRequest("revision-page", "", 1)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	first, err := adapter.ListRevisions(context.Background(), request)
	if err != nil {
		t.Fatalf("first ListRevisions() error = %v", err)
	}
	if got := first.Revisions(); len(got) != 1 || got[0].ID() != earlier.Metadata().ID() || first.NextCursor() == "" {
		t.Fatalf("first revision page = %#v, want earlier revision and next cursor", first)
	}
	secondRequest, err := policyengine.NewListRevisionsRequest("revision-page", first.NextCursor(), 1)
	if err != nil {
		t.Fatalf("second NewListRevisionsRequest() error = %v", err)
	}
	second, err := adapter.ListRevisions(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("second ListRevisions() error = %v", err)
	}
	if got := second.Revisions(); len(got) != 1 || got[0].ID() != later.Metadata().ID() || second.NextCursor() != "" {
		t.Fatalf("second revision page = %#v, want later revision without next cursor", second)
	}

	other := newSQLiteRevisionWrite(t, "revision-page", "collision.cdr", []byte("entity collision {}"), time.Unix(30, 0).UTC())
	collision, err := store.NewRevisionWrite(earlier.Metadata(), other.Artifact())
	if err != nil {
		t.Fatalf("NewRevisionWrite() error = %v", err)
	}
	if _, err := adapter.PutRevision(context.Background(), collision); categoryOf(err) != policyengine.ErrorIntegrity {
		t.Fatalf("digest collision category = %v, want %v", categoryOf(err), policyengine.ErrorIntegrity)
	}
}

func TestRevisionFirstPageIncludesPreEpochPublicationTimes(t *testing.T) {
	// This catches a first-page cursor sentinel treated as Unix epoch, which
	// would silently omit valid revisions published before 1970.
	adapter := openMigratedStoreForTest(t)
	preEpoch := newSQLiteRevisionWrite(t, "revision-pre-epoch", "early.cdr", []byte("entity preepoch {}"), time.Unix(-10, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), preEpoch); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request, err := policyengine.NewListRevisionsRequest("revision-pre-epoch", "", 10)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	page, err := adapter.ListRevisions(context.Background(), request)
	if err != nil {
		t.Fatalf("ListRevisions() error = %v", err)
	}
	if got := page.Revisions(); len(got) != 1 || got[0].ID() != preEpoch.Metadata().ID() {
		t.Fatalf("first page = %#v, want pre-epoch revision", got)
	}
}

func TestActivationIsCASABASafeAndRetainsCurrentHead(t *testing.T) {
	// This catches a non-atomic slot update, generation reuse after an ABA
	// transition, or history pruning that can remove the currently active head.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.ActivationHistoryRetention = 2
	adapter := openMigratedStoreForTest(t, config)
	first := newSQLiteRevisionWrite(t, "slot-ns", "first.cdr", []byte("entity user {}"), time.Unix(1, 0).UTC())
	second := newSQLiteRevisionWrite(t, "slot-ns", "second.cdr", []byte("entity document {}"), time.Unix(2, 0).UTC())
	for _, write := range []store.RevisionWrite{first, second} {
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision() error = %v", err)
		}
	}
	unset := policyengine.NewUnsetSlotExpectation()
	activateOne, err := policyengine.NewActivateRequest("slot-ns", "primary", first.Metadata().ID(), unset)
	if err != nil {
		t.Fatalf("NewActivateRequest(unset) error = %v", err)
	}
	one, err := adapter.Activate(context.Background(), activateOne)
	if err != nil {
		t.Fatalf("first Activate() error = %v", err)
	}
	if got := one.Activation(); got.Generation() != 1 || got.RevisionID() != first.Metadata().ID() {
		t.Fatalf("first activation = %#v", got)
	}
	expectedOne, err := policyengine.NewActiveSlotExpectation(first.Metadata().ID(), 1)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation() error = %v", err)
	}
	activateTwo, err := policyengine.NewActivateRequest("slot-ns", "primary", second.Metadata().ID(), expectedOne)
	if err != nil {
		t.Fatalf("NewActivateRequest(second) error = %v", err)
	}
	two, err := adapter.Activate(context.Background(), activateTwo)
	if err != nil {
		t.Fatalf("second Activate() error = %v", err)
	}
	if got := two.Activation(); got.Generation() != 2 || got.RevisionID() != second.Metadata().ID() {
		t.Fatalf("second activation = %#v", got)
	}
	// Returning to the first revision is a normal CAS, not a generation reset.
	expectedTwo, err := policyengine.NewActiveSlotExpectation(second.Metadata().ID(), 2)
	if err != nil {
		t.Fatalf("NewActiveSlotExpectation(second) error = %v", err)
	}
	activateThree, err := policyengine.NewActivateRequest("slot-ns", "primary", first.Metadata().ID(), expectedTwo)
	if err != nil {
		t.Fatalf("NewActivateRequest(third) error = %v", err)
	}
	three, err := adapter.Activate(context.Background(), activateThree)
	if err != nil {
		t.Fatalf("third Activate() error = %v", err)
	}
	if got := three.Activation(); got.Generation() != 3 || got.RevisionID() != first.Metadata().ID() {
		t.Fatalf("third activation = %#v", got)
	}
	if _, err := adapter.Activate(context.Background(), activateTwo); categoryOf(err) != policyengine.ErrorConflict {
		t.Fatalf("stale ABA Activate() category = %v, want %v", categoryOf(err), policyengine.ErrorConflict)
	}

	resolve, err := policyengine.NewResolveRequest("slot-ns", "primary")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	resolved, err := adapter.Resolve(context.Background(), resolve)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := resolved.Activation(); got.Generation() != 3 || got.RevisionID() != first.Metadata().ID() {
		t.Fatalf("resolved head = %#v", got)
	}
	historyRequest, err := policyengine.NewListActivationHistoryRequest("slot-ns", "primary", "", 10)
	if err != nil {
		t.Fatalf("NewListActivationHistoryRequest() error = %v", err)
	}
	history, err := adapter.ListActivationHistory(context.Background(), historyRequest)
	if err != nil {
		t.Fatalf("ListActivationHistory() error = %v", err)
	}
	if got := history.Activations(); len(got) != 2 || got[0].Generation() != 2 || got[1].Generation() != 3 || got[1].RevisionID() != first.Metadata().ID() {
		t.Fatalf("retained history = %#v, want generations 2 and current head 3", got)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened := openMigratedStoreForTest(t, config)
	if resolved, err := reopened.Resolve(context.Background(), resolve); err != nil || resolved.Activation().Generation() != 3 {
		t.Fatalf("Resolve() after reopen = %#v, %v", resolved, err)
	}
}

func TestActivationConcurrentWritersProduceOneCASWinner(t *testing.T) {
	// This catches concurrent writers that both observe an unset head and each
	// commit generation 1 instead of one winning the durable CAS.
	adapter := openMigratedStoreForTest(t)
	first := newSQLiteRevisionWrite(t, "slot-race", "first.cdr", []byte("entity user {}"), time.Unix(1, 0).UTC())
	second := newSQLiteRevisionWrite(t, "slot-race", "second.cdr", []byte("entity document {}"), time.Unix(2, 0).UTC())
	for _, write := range []store.RevisionWrite{first, second} {
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision() error = %v", err)
		}
	}
	start := make(chan struct{})
	results := make(chan sqliteActivateResult, 2)
	for _, target := range []string{first.Metadata().ID(), second.Metadata().ID()} {
		target := target
		go func() {
			<-start
			request, err := policyengine.NewActivateRequest("slot-race", "primary", target, policyengine.NewUnsetSlotExpectation())
			if err != nil {
				results <- sqliteActivateResult{target: target, err: err}
				return
			}
			response, err := adapter.Activate(context.Background(), request)
			results <- sqliteActivateResult{target: target, activation: response.Activation(), err: err}
		}()
	}
	close(start)
	winners, conflicts := 0, 0
	winnerTarget := ""
	for range 2 {
		result := receiveSQLiteActivation(t, results)
		switch {
		case result.err == nil:
			winners++
			winnerTarget = result.target
			if result.activation.RevisionID() != result.target || result.activation.Generation() != 1 {
				t.Fatalf("winner response = %#v, want target %q generation 1", result.activation, result.target)
			}
		case categoryOf(result.err) == policyengine.ErrorConflict:
			conflicts++
		default:
			t.Fatalf("concurrent Activate(%q) error = %v", result.target, result.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("concurrent activation winners/conflicts = %d/%d, want 1/1", winners, conflicts)
	}
	resolve, err := policyengine.NewResolveRequest("slot-race", "primary")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	resolved, err := adapter.Resolve(context.Background(), resolve)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got := resolved.Activation(); got.RevisionID() != winnerTarget || got.Generation() != 1 {
		t.Fatalf("resolved race head = %#v, want target %q generation 1", got, winnerTarget)
	}
	eventsRequest, err := policyengine.NewListEventsRequest("slot-race", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	events, err := adapter.ListEvents(context.Background(), eventsRequest)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	activated := make([]policyengine.StateEvent, 0, 1)
	for _, event := range events.Events() {
		if event.Kind() == policyengine.StateEventSlotActivated && event.Slot() == "primary" {
			activated = append(activated, event)
		}
	}
	if len(activated) != 1 || activated[0].RevisionID() != winnerTarget || activated[0].SlotGeneration() != 1 {
		t.Fatalf("slot race events = %#v, want exactly one generation-1 winner", activated)
	}
}

func TestEventCursorsPersistAuthenticateAndExpire(t *testing.T) {
	// This catches process-local cursor signing, a cursor accepted outside its
	// namespace, or expiry that leaves an obsolete retained cursor usable.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	adapter := openMigratedStoreForTest(t, config)
	for index, source := range [][]byte{[]byte("entity user {}"), []byte("entity document {}")} {
		write := newSQLiteRevisionWrite(t, "event-ns", "event.cdr", source, time.Unix(int64(index+1), 0).UTC())
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision(%d) error = %v", index, err)
		}
	}
	firstRequest, err := policyengine.NewListEventsRequest("event-ns", "", 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	first, err := adapter.ListEvents(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("first ListEvents() error = %v", err)
	}
	if got := first.Events(); len(got) != 1 || got[0].Kind() != policyengine.StateEventRevisionPublished || first.NextCursor() == "" {
		t.Fatalf("first event page = %#v", first)
	}
	firstEventCursor := first.Events()[0].Cursor()
	afterCursor := first.NextCursor()
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened := openMigratedStoreForTest(t, config)
	nextRequest, err := policyengine.NewListEventsRequest("event-ns", afterCursor, 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(after) error = %v", err)
	}
	next, err := reopened.ListEvents(context.Background(), nextRequest)
	if err != nil {
		t.Fatalf("ListEvents() after reopen error = %v", err)
	}
	if got := next.Events(); len(got) != 1 || got[0].Kind() != policyengine.StateEventRevisionPublished {
		t.Fatalf("second event page = %#v", next)
	}
	tampered := tamperSQLiteCursorForTest(afterCursor)
	tamperedRequest, err := policyengine.NewListEventsRequest("event-ns", tampered, 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(tampered) error = %v", err)
	}
	if _, err := reopened.ListEvents(context.Background(), tamperedRequest); categoryOf(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("tampered cursor category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
	}
	wrongNamespace, err := policyengine.NewListEventsRequest("other-ns", afterCursor, 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(wrong namespace) error = %v", err)
	}
	if _, err := reopened.ListEvents(context.Background(), wrongNamespace); categoryOf(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("cross-namespace cursor category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
	}
	if err := reopened.expireEvents(context.Background(), "event-ns", firstEventCursor); err != nil {
		t.Fatalf("expireEvents() error = %v", err)
	}
	expiredRequest, err := policyengine.NewListEventsRequest("event-ns", firstEventCursor, 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(expired) error = %v", err)
	}
	if _, err := reopened.ListEvents(context.Background(), expiredRequest); categoryOf(err) != policyengine.ErrorCursorExpired {
		t.Fatalf("expired cursor category = %v, want %v", categoryOf(err), policyengine.ErrorCursorExpired)
	}
}

func TestEventRetentionExpiresCursorsUsingEffectiveClock(t *testing.T) {
	// This catches a durable event store that prunes only by count, leaving a
	// retained cursor valid forever despite the configured clock advancing past
	// the public 24-hour retention interval.
	start := time.Unix(2_000, 0).UTC()
	clock := &sqliteMutableClock{now: start}
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.Clock = clock
	adapter := openMigratedStoreForTest(t, config)
	for _, source := range [][]byte{[]byte("entity user {}"), []byte("entity document {}")} {
		write := newSQLiteRevisionWrite(t, "event-retention", "retention.cdr", source, start)
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision() error = %v", err)
		}
	}
	firstRequest, err := policyengine.NewListEventsRequest("event-retention", "", 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	first, err := adapter.ListEvents(context.Background(), firstRequest)
	if err != nil || first.NextCursor() == "" {
		t.Fatalf("first ListEvents() = %#v, %v; want a retained cursor", first, err)
	}
	clock.Set(start.Add(24 * time.Hour))
	expiredRequest, err := policyengine.NewListEventsRequest("event-retention", first.NextCursor(), 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(expired) error = %v", err)
	}
	if _, err := adapter.ListEvents(context.Background(), expiredRequest); categoryOf(err) != policyengine.ErrorCursorExpired {
		t.Fatalf("expired cursor error = %v (category %v), want %v", err, categoryOf(err), policyengine.ErrorCursorExpired)
	}
	resyncRequest, err := policyengine.NewListEventsRequest("event-retention", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest(resync) error = %v", err)
	}
	resync, err := adapter.ListEvents(context.Background(), resyncRequest)
	if err != nil {
		t.Fatalf("resync ListEvents() error = %v", err)
	}
	if got := resync.Events(); len(got) != 0 {
		t.Fatalf("expired retained events = %#v, want none", got)
	}
}

func TestRevisionPreEpochEffectiveClockPreservesEventTimestamp(t *testing.T) {
	// This catches an uninitialized effective-time sentinel that converts a
	// valid pre-1970 revision event timestamp to the Unix epoch.
	occurredAt := time.Unix(-72*60*60, 0).UTC()
	clock := &sqliteMutableClock{now: occurredAt}
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.Clock = clock
	adapter := openMigratedStoreForTest(t, config)
	write := newSQLiteRevisionWrite(t, "pre-epoch-revision", "revision.cdr", []byte("entity user {}"), occurredAt)
	if _, err := adapter.PutRevision(context.Background(), write); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request, err := policyengine.NewListEventsRequest("pre-epoch-revision", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	page, err := adapter.ListEvents(context.Background(), request)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if got := page.Events(); len(got) != 1 || !got[0].OccurredAt().Equal(occurredAt) {
		t.Fatalf("revision event = %#v, want occurred at %v", got, occurredAt)
	}
}

func TestActivationPreEpochEffectiveClockPreservesActivationAndEventTimestamp(t *testing.T) {
	// This catches the same sentinel leaking into durable slot activation time
	// and its atomically committed event.
	revisionAt := time.Unix(-72*60*60, 0).UTC()
	activationAt := revisionAt.Add(time.Hour)
	clock := &sqliteMutableClock{now: revisionAt}
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.Clock = clock
	adapter := openMigratedStoreForTest(t, config)
	write := newSQLiteRevisionWrite(t, "pre-epoch-activation", "activation.cdr", []byte("entity user {}"), revisionAt)
	if _, err := adapter.PutRevision(context.Background(), write); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	clock.Set(activationAt)
	request, err := policyengine.NewActivateRequest("pre-epoch-activation", "primary", write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	if err != nil {
		t.Fatalf("NewActivateRequest() error = %v", err)
	}
	response, err := adapter.Activate(context.Background(), request)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if got := response.Activation().ActivatedAt(); !got.Equal(activationAt) {
		t.Fatalf("activation time = %v, want %v", got, activationAt)
	}
	eventsRequest, err := policyengine.NewListEventsRequest("pre-epoch-activation", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	events, err := adapter.ListEvents(context.Background(), eventsRequest)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if got := events.Events(); len(got) != 2 || got[1].Kind() != policyengine.StateEventSlotActivated || !got[1].OccurredAt().Equal(activationAt) {
		t.Fatalf("activation events = %#v, want slot event at %v", got, activationAt)
	}
}

func TestEventRetentionExpiresPreEpochEvents(t *testing.T) {
	// This catches retention using the Unix epoch as the first effective clock,
	// which prevents valid pre-epoch events from ever becoming old enough.
	start := time.Unix(-72*60*60, 0).UTC()
	clock := &sqliteMutableClock{now: start}
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.Clock = clock
	adapter := openMigratedStoreForTest(t, config)
	for _, source := range [][]byte{[]byte("entity user {}"), []byte("entity document {}")} {
		write := newSQLiteRevisionWrite(t, "pre-epoch-retention", "retention.cdr", source, start)
		if _, err := adapter.PutRevision(context.Background(), write); err != nil {
			t.Fatalf("PutRevision() error = %v", err)
		}
	}
	firstRequest, err := policyengine.NewListEventsRequest("pre-epoch-retention", "", 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest() error = %v", err)
	}
	first, err := adapter.ListEvents(context.Background(), firstRequest)
	if err != nil || first.NextCursor() == "" {
		t.Fatalf("first ListEvents() = %#v, %v; want a retained cursor", first, err)
	}
	clock.Set(start.Add(24 * time.Hour))
	expiredRequest, err := policyengine.NewListEventsRequest("pre-epoch-retention", first.NextCursor(), 1)
	if err != nil {
		t.Fatalf("NewListEventsRequest(expired) error = %v", err)
	}
	if _, err := adapter.ListEvents(context.Background(), expiredRequest); categoryOf(err) != policyengine.ErrorCursorExpired {
		t.Fatalf("expired pre-epoch cursor category = %v, want %v", categoryOf(err), policyengine.ErrorCursorExpired)
	}
	resyncRequest, err := policyengine.NewListEventsRequest("pre-epoch-retention", "", 10)
	if err != nil {
		t.Fatalf("NewListEventsRequest(resync) error = %v", err)
	}
	resync, err := adapter.ListEvents(context.Background(), resyncRequest)
	if err != nil {
		t.Fatalf("resync ListEvents() error = %v", err)
	}
	if got := resync.Events(); len(got) != 0 {
		t.Fatalf("expired pre-epoch events = %#v, want none", got)
	}
}

func TestRevisionReservationPausePreservesFirstWriterAndWakesWaiter(t *testing.T) {
	// This catches a same-namespace writer that can overtake a paused first
	// commit, ignores cancellation while reserved, or fails to release waiters.
	adapter, _ := openMigratedStoreWithHooksForTest(t)
	ownerWrite := newSQLiteRevisionWrite(t, "paused-revision", "owner.cdr", []byte("entity user {\n}\n"), time.Unix(1, 0).UTC())
	waiterWrite := newSQLiteRevisionWrite(t, "paused-revision", "waiter.cdr", []byte("entity user {}"), time.Unix(2, 0).UTC())
	if got, want := waiterWrite.Metadata().ID(), ownerWrite.Metadata().ID(); got != want {
		t.Fatalf("canonical-equivalent revision IDs = %q / %q", got, want)
	}
	pause := adapter.pauseNextRevisionCommit()
	ownerDone := make(chan sqlitePutResult, 1)
	go func() {
		result, err := adapter.PutRevision(context.Background(), ownerWrite)
		ownerDone <- sqlitePutResult{result: result, err: err}
	}()
	waitSQLiteSignal(t, "owner entered transaction", pause.entered)
	waiterDone := make(chan sqlitePutResult, 1)
	go func() {
		result, err := adapter.PutRevision(context.Background(), waiterWrite)
		waiterDone <- sqlitePutResult{result: result, err: err}
	}()
	waitSQLiteSignal(t, "waiter contended reservation", pause.contendedSignal)
	select {
	case early := <-waiterDone:
		t.Fatalf("waiter returned before owner released: %+v", early)
	default:
	}
	pause.Release()
	owner := receiveSQLitePut(t, "owner", ownerDone)
	if owner.err != nil || !owner.result.Created() {
		t.Fatalf("owner result = %+v", owner)
	}
	waitSQLiteSignal(t, "waiter woke", pause.waiterWokeSignal)
	pause.ResumeWaiter()
	waiter := receiveSQLitePut(t, "waiter", waiterDone)
	if waiter.err != nil || waiter.result.Created() {
		t.Fatalf("waiter result = %+v", waiter)
	}
	if got, want := waiter.result.Record().Provenance().SourceName(), "owner.cdr"; got != want {
		t.Fatalf("waiter provenance = %q, want first writer %q", got, want)
	}
}

func TestEventAppendFailureRollsBackRevisionAndSequence(t *testing.T) {
	// This catches a partial mutation or a consumed event sequence when the real
	// event INSERT fails inside its surrounding writer transaction.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	adapter, hooks := openMigratedStoreWithHooksForTest(t, config)
	write := newSQLiteRevisionWrite(t, "event-rollback", "rollback.cdr", []byte("entity rollback {}"), time.Unix(1, 0).UTC())
	hooks.armNextEventAppendFailure()
	if _, err := adapter.PutRevision(context.Background(), write); categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("failed PutRevision() category = %v, want %v", categoryOf(err), policyengine.ErrorUnavailable)
	}
	get, err := policyengine.NewGetRevisionRequest("event-rollback", write.Metadata().ID())
	if err != nil {
		t.Fatalf("NewGetRevisionRequest() error = %v", err)
	}
	if _, err := adapter.GetRevision(context.Background(), get); categoryOf(err) != policyengine.ErrorNotFound {
		t.Fatalf("GetRevision() after failed event category = %v, want %v", categoryOf(err), policyengine.ErrorNotFound)
	}
	if result, err := adapter.PutRevision(context.Background(), write); err != nil || !result.Created() {
		t.Fatalf("retry PutRevision() = %+v, %v", result, err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	db := openRawSQLite(t, config.Path)
	var sequence int64
	if err := db.QueryRowContext(context.Background(), "SELECT sequence FROM state_events WHERE namespace = 'event-rollback'").Scan(&sequence); err != nil {
		t.Fatalf("read committed event sequence: %v", err)
	}
	if sequence != 1 {
		t.Fatalf("committed event sequence = %d, want no rollback gap at 1", sequence)
	}
}

func TestActivationEventAppendFailureRollsBackSlotStateAndSequence(t *testing.T) {
	// This catches a partial slot head/history update or consumed event sequence
	// when the event insert fails after the otherwise valid CAS mutation.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	adapter, hooks := openMigratedStoreWithHooksForTest(t, config)
	write := newSQLiteRevisionWrite(t, "activation-rollback", "rollback.cdr", []byte("entity rollback {}"), time.Unix(1, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), write); err != nil {
		t.Fatalf("PutRevision() error = %v", err)
	}
	request, err := policyengine.NewActivateRequest("activation-rollback", "primary", write.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	if err != nil {
		t.Fatalf("NewActivateRequest() error = %v", err)
	}
	hooks.armNextEventAppendFailure()
	if _, err := adapter.Activate(context.Background(), request); categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("failed Activate() category = %v, want %v", categoryOf(err), policyengine.ErrorUnavailable)
	}
	resolve, err := policyengine.NewResolveRequest("activation-rollback", "primary")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	if _, err := adapter.Resolve(context.Background(), resolve); categoryOf(err) != policyengine.ErrorNotFound {
		t.Fatalf("Resolve() after failed activation category = %v, want %v", categoryOf(err), policyengine.ErrorNotFound)
	}
	historyRequest, err := policyengine.NewListActivationHistoryRequest("activation-rollback", "primary", "", 10)
	if err != nil {
		t.Fatalf("NewListActivationHistoryRequest() error = %v", err)
	}
	history, err := adapter.ListActivationHistory(context.Background(), historyRequest)
	if err != nil {
		t.Fatalf("ListActivationHistory() after failed activation error = %v", err)
	}
	if got := history.Activations(); len(got) != 0 {
		t.Fatalf("failed activation history = %#v, want empty", got)
	}
	if response, err := adapter.Activate(context.Background(), request); err != nil || response.Activation().Generation() != 1 {
		t.Fatalf("activation retry = %#v, %v; want generation 1", response, err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	db := openRawSQLite(t, config.Path)
	defer func() { _ = db.Close() }()
	var sequence int64
	if err := db.QueryRowContext(context.Background(), "SELECT sequence FROM state_events WHERE namespace = 'activation-rollback' AND kind = 'slot_activated'").Scan(&sequence); err != nil {
		t.Fatalf("read committed activation event sequence: %v", err)
	}
	if sequence != 2 {
		t.Fatalf("committed activation event sequence = %d, want no rollback gap at 2", sequence)
	}
}

func waitSQLiteSignal(t testing.TB, name string, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("%s was not observed", name)
	}
}

func receiveSQLitePut(t testing.TB, name string, values <-chan sqlitePutResult) sqlitePutResult {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatalf("%s PutRevision() did not return", name)
		return sqlitePutResult{}
	}
}

func receiveSQLiteActivation(t testing.TB, values <-chan sqliteActivateResult) sqliteActivateResult {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("concurrent Activate() did not return")
		return sqliteActivateResult{}
	}
}

// tamperSQLiteCursorForTest changes a fully significant Base64 digit. Raw
// Base64's final digit can have unused bits, so changing that digit may decode
// to the original token and make a supposedly tampered-cursor test flaky.
func tamperSQLiteCursorForTest(value string) string {
	if len(value) == 0 {
		panic("sqlite: cannot tamper an empty cursor")
	}
	if value[0] == 'B' {
		return "C" + value[1:]
	}
	return "B" + value[1:]
}

func newSQLiteRevisionWrite(t testing.TB, namespace, sourceName string, source []byte, publishedAt time.Time) store.RevisionWrite {
	t.Helper()
	artifact, err := dsl.CompileArtifact(sourceName, source)
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		t.Fatalf("Artifact.MarshalBinary() error = %v", err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	metadata, err := policyengine.NewRevisionMetadata(namespace, id, publishedAt)
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	publish, err := policyengine.NewPublishRequest(namespace, sourceName, source)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	provenance, err := store.NewRevisionProvenance(publish)
	if err != nil {
		t.Fatalf("NewRevisionProvenance() error = %v", err)
	}
	write, err := store.NewRevisionWriteWithProvenance(metadata, encoded, provenance)
	if err != nil {
		t.Fatalf("NewRevisionWriteWithProvenance() error = %v", err)
	}
	return write
}

// openMigratedStoreForTest is intentionally package-test-only. Production
// opening remains private until the complete Store adapter exists.
func openMigratedStoreForTest(t testing.TB, configurations ...Config) *Store {
	t.Helper()
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if len(configurations) == 1 {
		config = configurations[0]
	}
	if len(configurations) > 1 {
		t.Fatal("openMigratedStoreForTest accepts at most one configuration")
	}
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	result, err := openMigratedStore(context.Background(), config)
	if err != nil {
		t.Fatalf("openMigratedStore() error = %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
}
