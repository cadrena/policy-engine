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
	if err := cache.FillAuthoritative(slot, first); err != nil {
		t.Fatalf("FillAuthoritative(first) error = %v", err)
	}

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
	if err := cache.FillAuthoritative(slot, current); err != nil {
		t.Fatalf("FillAuthoritative(current) error = %v", err)
	}
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
	if err := cache.FillAuthoritative(firstSlot, mustSlotPointer(t, "revision-1", 1)); err != nil {
		t.Fatalf("FillAuthoritative(first) error = %v", err)
	}
	if err := cache.FillAuthoritative(secondSlot, mustSlotPointer(t, "revision-2", 1)); err != nil {
		t.Fatalf("FillAuthoritative(second) error = %v", err)
	}
	if _, ok := cache.Pin(firstSlot); ok {
		t.Fatal("evicted pointer unexpectedly hit")
	}
	if _, ok := cache.Pin(secondSlot); !ok {
		t.Fatal("resident pointer unexpectedly missed")
	}
	if err := cache.FillAuthoritative(firstSlot, mustSlotPointer(t, "revision-3", 2)); err != nil {
		t.Fatalf("authoritative reload FillAuthoritative() error = %v", err)
	}
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
	if err := cache.FillAuthoritative(slotA, mustSlotPointer(t, "revision-a2", 2)); err != nil {
		t.Fatalf("FillAuthoritative(A generation 2) error = %v", err)
	}
	if err := cache.FillAuthoritative(slotB, mustSlotPointer(t, "revision-b1", 1)); err != nil {
		t.Fatalf("FillAuthoritative(B generation 1) error = %v", err)
	}
	if err := cache.UpdateCommitted(slotA, mustSlotPointer(t, "revision-a1", 1)); err != nil {
		t.Fatalf("delayed UpdateCommitted(A generation 1) error = %v", err)
	}
	if pin, ok := cache.Pin(slotA); ok {
		t.Fatalf("delayed update resurrected evicted pointer (%q,%d)", pin.Revision(), pin.Generation())
	}
	current := mustSlotPointer(t, "revision-a3", 3)
	if err := cache.FillAuthoritative(slotA, current); err != nil {
		t.Fatalf("authoritative refill error = %v", err)
	}
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
