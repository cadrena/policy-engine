package cache

import (
	"errors"
	"testing"
	"time"
)

func TestPointerCacheRequestPinDoesNotSwitchAcrossCommittedUpdate(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(4)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slot := mustSlotKey(t, "tenant-a", "primary")
	first := mustSlotPointer(t, "revision-1", 1)
	second := mustSlotPointer(t, "revision-2", 2)
	fillPointer(t, cache, slot, first)

	requestPinned := make(chan RevisionPin, 1)
	continueRequest := make(chan struct{})
	requestKey := make(chan RevisionKey, 1)
	requestErr := make(chan error, 1)
	go func() {
		pin, ok := cache.Pin(slot)
		if !ok {
			requestErr <- errors.New("unexpected pointer miss")
			return
		}
		requestPinned <- pin
		<-continueRequest
		key, err := pin.RevisionKey("abi-v1")
		if err != nil {
			requestErr <- err
			return
		}
		requestKey <- key
	}()

	select {
	case pin := <-requestPinned:
		if pin.Revision() != first.Revision() {
			t.Fatalf("initial request pin revision = %q, want %q", pin.Revision(), first.Revision())
		}
	case err := <-requestErr:
		t.Fatalf("Pin() error = %v", err)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for request pin")
	}
	if err := cache.UpdateCommitted(slot, second); err != nil {
		t.Fatalf("UpdateCommitted(second) error = %v", err)
	}
	close(continueRequest)
	select {
	case key := <-requestKey:
		if got, want := key.Revision(), first.Revision(); got != want {
			t.Fatalf("in-flight request revision = %q, want pinned %q", got, want)
		}
	case err := <-requestErr:
		t.Fatalf("RevisionKey() error = %v", err)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for in-flight request key")
	}

	latest, ok := cache.Pin(slot)
	if !ok {
		t.Fatal("latest Pin() missed")
	}
	if got, want := latest.Revision(), second.Revision(); got != want {
		t.Fatalf("latest pin revision = %q, want %q", got, want)
	}
	if got, want := latest.Generation(), second.Generation(); got != want {
		t.Fatalf("latest pin generation = %d, want %d", got, want)
	}
}

func TestPointerCacheAcceptsOnlyMonotonicCommittedState(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(2)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slot := mustSlotKey(t, "tenant-a", "primary")
	current := mustSlotPointer(t, "revision-2", 2)
	fillPointer(t, cache, slot, current)
	if err := cache.UpdateCommitted(slot, mustSlotPointer(t, "revision-1", 1)); err == nil {
		t.Fatal("UpdateCommitted(stale) error = nil")
	}
	if err := cache.UpdateCommitted(slot, mustSlotPointer(t, "revision-other", 2)); err == nil {
		t.Fatal("UpdateCommitted(conflicting generation) error = nil")
	}
	got, ok := cache.Pin(slot)
	if !ok {
		t.Fatal("Pin() missed current pointer")
	}
	if got.Revision() != current.Revision() || got.Generation() != current.Generation() {
		t.Fatalf("Pin() = (%q,%d), want (%q,%d)",
			got.Revision(), got.Generation(), current.Revision(), current.Generation())
	}
}

func TestPointerCacheBoundedEvictionDegradesToMiss(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	firstSlot := mustSlotKey(t, "tenant-a", "primary")
	secondSlot := mustSlotKey(t, "tenant-a", "canary")
	fillPointer(t, cache, firstSlot, mustSlotPointer(t, "revision-1", 1))
	fillPointer(t, cache, secondSlot, mustSlotPointer(t, "revision-2", 1))
	if _, ok := cache.Pin(firstSlot); ok {
		t.Fatal("evicted pointer unexpectedly hit")
	}
	if _, ok := cache.Pin(secondSlot); !ok {
		t.Fatal("resident pointer unexpectedly missed")
	}
	fillPointer(t, cache, firstSlot, mustSlotPointer(t, "revision-3", 2))
	reloaded, ok := cache.Pin(firstSlot)
	if !ok || reloaded.Revision() != "revision-3" {
		t.Fatalf("reloaded Pin() = (%q,%v), want (revision-3,true)", reloaded.Revision(), ok)
	}
}

func TestPointerCacheDelayedUpdateAfterEvictionPreservesMiss(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slotA := mustSlotKey(t, "tenant-a", "primary")
	slotB := mustSlotKey(t, "tenant-a", "canary")
	fillPointer(t, cache, slotA, mustSlotPointer(t, "revision-a2", 2))
	fillPointer(t, cache, slotB, mustSlotPointer(t, "revision-b1", 1))
	if err := cache.UpdateCommitted(slotA, mustSlotPointer(t, "revision-a1", 1)); err != nil {
		t.Fatalf("delayed UpdateCommitted(A generation 1) error = %v", err)
	}
	if pin, ok := cache.Pin(slotA); ok {
		t.Fatalf("delayed update resurrected evicted pointer (%q,%d)", pin.Revision(), pin.Generation())
	}
	current := mustSlotPointer(t, "revision-a3", 3)
	fillPointer(t, cache, slotA, current)
	if err := cache.UpdateCommitted(slotA, mustSlotPointer(t, "revision-conflict", 3)); err == nil {
		t.Fatal("same-generation conflicting update error = nil")
	}
	pin, ok := cache.Pin(slotA)
	if !ok {
		t.Fatal("authoritatively refilled pointer missed")
	}
	if pin.Revision() != current.Revision() || pin.Generation() != current.Generation() {
		t.Fatalf("refilled Pin() = (%q,%d), want (%q,%d)",
			pin.Revision(), pin.Generation(), current.Revision(), current.Generation())
	}
}

func TestPointerCacheCommittedUpdateSupersedesOutstandingAuthoritativeFill(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slot := mustSlotKey(t, "tenant-a", "primary")
	authoritativeRead := mustSlotPointer(t, "revision-2", 2)
	newerCommit := mustSlotPointer(t, "revision-3", 3)

	fill, err := cache.BeginAuthoritativeFill(slot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill() error = %v", err)
	}
	if err := cache.UpdateCommitted(slot, newerCommit); err != nil {
		t.Fatalf("UpdateCommitted(generation 3) error = %v", err)
	}
	if err := fill.Complete(authoritativeRead); err != nil {
		t.Fatalf("Complete(generation 2) error = %v", err)
	}

	pin, ok := cache.Pin(slot)
	if !ok {
		t.Fatal("superseding committed pointer missed")
	}
	if pin.Revision() != newerCommit.Revision() || pin.Generation() != newerCommit.Generation() {
		t.Fatalf("Pin() = (%q,%d), want superseding commit (%q,%d)",
			pin.Revision(), pin.Generation(), newerCommit.Revision(), newerCommit.Generation())
	}
}

func TestPointerCacheAuthoritativeFillConflictPreservesMiss(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slot := mustSlotKey(t, "tenant-a", "primary")
	fill, err := cache.BeginAuthoritativeFill(slot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill() error = %v", err)
	}
	if err := cache.UpdateCommitted(slot, mustSlotPointer(t, "revision-new", 3)); err != nil {
		t.Fatalf("UpdateCommitted() error = %v", err)
	}
	if err := fill.Complete(mustSlotPointer(t, "revision-conflict", 3)); err == nil {
		t.Fatal("Complete(conflicting generation) error = nil")
	}
	if _, ok := cache.Pin(slot); ok {
		t.Fatal("conflicting authoritative fill was admitted")
	}
}

func TestPointerCacheCanceledFillReleasesCapacityAndRejectsLateComplete(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	resident := mustSlotKey(t, "tenant-a", "resident")
	abandoned := mustSlotKey(t, "tenant-a", "abandoned")
	replacement := mustSlotKey(t, "tenant-a", "replacement")
	fillPointer(t, cache, resident, mustSlotPointer(t, "revision-resident", 1))

	abandonedFill, err := cache.BeginAuthoritativeFill(abandoned)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(abandoned) error = %v", err)
	}
	if _, ok := cache.Pin(resident); ok {
		t.Fatal("active fill reservation did not evict resident capacity")
	}
	if _, err := cache.BeginAuthoritativeFill(replacement); err == nil {
		t.Fatal("BeginAuthoritativeFill(replacement) exceeded active fill capacity")
	}
	abandonedFill.Cancel()
	if err := abandonedFill.Complete(mustSlotPointer(t, "revision-late", 1)); err == nil {
		t.Fatal("late Complete() after Cancel() error = nil")
	}

	replacementFill, err := cache.BeginAuthoritativeFill(replacement)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(replacement) after cancel error = %v", err)
	}
	if err := replacementFill.Complete(mustSlotPointer(t, "revision-replacement", 1)); err != nil {
		t.Fatalf("Complete(replacement) error = %v", err)
	}
	if _, ok := cache.Pin(replacement); !ok {
		t.Fatal("replacement pointer missed after released capacity")
	}
}

func TestPointerCacheInvalidCompleteReleasesReservationCapacity(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	invalidSlot := mustSlotKey(t, "tenant-a", "invalid")
	replacementSlot := mustSlotKey(t, "tenant-a", "replacement")
	fill, err := cache.BeginAuthoritativeFill(invalidSlot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(invalid) error = %v", err)
	}
	if err := fill.Complete(SlotPointer{}); err == nil {
		t.Fatal("Complete(invalid pointer) error = nil")
	}

	replacement, err := cache.BeginAuthoritativeFill(replacementSlot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(replacement) error = %v", err)
	}
	if err := replacement.Complete(mustSlotPointer(t, "revision-replacement", 1)); err != nil {
		t.Fatalf("Complete(replacement) error = %v", err)
	}
	if _, ok := cache.Pin(replacementSlot); !ok {
		t.Fatal("replacement pointer missed after invalid completion")
	}
}

func TestPointerCacheStaleCopiedTokenCannotConsumeNewReservation(t *testing.T) {
	t.Parallel()

	cache, err := NewPointerCache(1)
	if err != nil {
		t.Fatalf("NewPointerCache() error = %v", err)
	}
	slot := mustSlotKey(t, "tenant-a", "primary")
	stale, err := cache.BeginAuthoritativeFill(slot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(stale) error = %v", err)
	}
	staleCopy := stale
	stale.Cancel()

	current, err := cache.BeginAuthoritativeFill(slot)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill(current) error = %v", err)
	}
	if err := staleCopy.Complete(SlotPointer{}); err != errPointerFillClosed {
		t.Fatalf("stale Complete() error = %v, want %v", err, errPointerFillClosed)
	}
	pointer := mustSlotPointer(t, "revision-current", 1)
	if err := current.Complete(pointer); err != nil {
		t.Fatalf("current Complete() error = %v", err)
	}
	pin, ok := cache.Pin(slot)
	if !ok || pin.Revision() != pointer.Revision() {
		t.Fatalf("Pin() = (%q,%v), want (%q,true)", pin.Revision(), ok, pointer.Revision())
	}
}

func mustSlotKey(t *testing.T, namespace, slot string) SlotKey {
	t.Helper()
	key, err := NewSlotKey(namespace, slot)
	if err != nil {
		t.Fatalf("NewSlotKey() error = %v", err)
	}
	return key
}

func mustSlotPointer(t *testing.T, revision string, generation uint64) SlotPointer {
	t.Helper()
	pointer, err := NewSlotPointer(revision, generation)
	if err != nil {
		t.Fatalf("NewSlotPointer() error = %v", err)
	}
	return pointer
}

func fillPointer(t *testing.T, cache *PointerCache, key SlotKey, pointer SlotPointer) {
	t.Helper()
	fill, err := cache.BeginAuthoritativeFill(key)
	if err != nil {
		t.Fatalf("BeginAuthoritativeFill() error = %v", err)
	}
	if err := fill.Complete(pointer); err != nil {
		t.Fatalf("AuthoritativeFill.Complete() error = %v", err)
	}
}
