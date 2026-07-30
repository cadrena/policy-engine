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
	if err := cache.UpdateCommitted(slot, first); err != nil {
		t.Fatalf("UpdateCommitted(first) error = %v", err)
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
	if err := cache.UpdateCommitted(slot, current); err != nil {
		t.Fatalf("UpdateCommitted(current) error = %v", err)
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
	if err := cache.UpdateCommitted(firstSlot, mustSlotPointer(t, "revision-1", 1)); err != nil {
		t.Fatalf("UpdateCommitted(first) error = %v", err)
	}
	if err := cache.UpdateCommitted(secondSlot, mustSlotPointer(t, "revision-2", 1)); err != nil {
		t.Fatalf("UpdateCommitted(second) error = %v", err)
	}
	if _, ok := cache.Pin(firstSlot); ok {
		t.Fatal("evicted pointer unexpectedly hit")
	}
	if _, ok := cache.Pin(secondSlot); !ok {
		t.Fatal("resident pointer unexpectedly missed")
	}
	if err := cache.UpdateCommitted(firstSlot, mustSlotPointer(t, "revision-3", 2)); err != nil {
		t.Fatalf("authoritative reload UpdateCommitted() error = %v", err)
	}
	reloaded, ok := cache.Pin(firstSlot)
	if !ok || reloaded.Revision() != "revision-3" {
		t.Fatalf("reloaded Pin() = (%q,%v), want (revision-3,true)", reloaded.Revision(), ok)
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
