package cache

import (
	"container/list"
	"errors"
	"sync"
)

var (
	errInvalidSlotKey     = errors.New("cache: invalid slot key")
	errInvalidSlotPointer = errors.New("cache: invalid slot pointer")
	errStalePointer       = errors.New("cache: stale slot pointer")
	errPointerConflict    = errors.New("cache: conflicting slot pointer generation")
)

// SlotKey identifies one namespace-local slot pointer.
type SlotKey struct {
	namespace string
	slot      string
}

// NewSlotKey constructs an exact namespace and slot key.
func NewSlotKey(namespace, slot string) (SlotKey, error) {
	if namespace == "" || slot == "" {
		return SlotKey{}, errInvalidSlotKey
	}
	return SlotKey{namespace: namespace, slot: slot}, nil
}

// Namespace returns the tenant namespace bound to the slot.
func (k SlotKey) Namespace() string { return k.namespace }

// Slot returns the namespace-local slot name.
func (k SlotKey) Slot() string { return k.slot }

func (k SlotKey) valid() bool { return k.namespace != "" && k.slot != "" }

// SlotPointer is one exact committed slot state.
type SlotPointer struct {
	revision   string
	generation uint64
}

// NewSlotPointer constructs an active committed slot state.
func NewSlotPointer(revision string, generation uint64) (SlotPointer, error) {
	if revision == "" || generation == 0 {
		return SlotPointer{}, errInvalidSlotPointer
	}
	return SlotPointer{revision: revision, generation: generation}, nil
}

// Revision returns the exact committed revision ID.
func (p SlotPointer) Revision() string { return p.revision }

// Generation returns the exact committed slot generation.
func (p SlotPointer) Generation() uint64 { return p.generation }

func (p SlotPointer) valid() bool { return p.revision != "" && p.generation != 0 }

// RevisionPin is an immutable per-request snapshot of one slot selection.
type RevisionPin struct {
	namespace  string
	slot       string
	revision   string
	generation uint64
}

// Namespace returns the tenant namespace captured by the request.
func (p RevisionPin) Namespace() string { return p.namespace }

// Slot returns the slot captured by the request.
func (p RevisionPin) Slot() string { return p.slot }

// Revision returns the exact revision captured by the request.
func (p RevisionPin) Revision() string { return p.revision }

// Generation returns the exact slot generation captured by the request.
func (p RevisionPin) Generation() uint64 { return p.generation }

// RevisionKey binds the pinned revision to one evaluator ABI for compiled load.
func (p RevisionPin) RevisionKey(evaluatorABI string) (RevisionKey, error) {
	return NewRevisionKey(p.namespace, p.revision, evaluatorABI)
}

type pointerEntry struct {
	key     SlotKey
	pointer SlotPointer
	recency *list.Element
}

// PointerCache is a bounded optional optimization for committed slot state.
type PointerCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[SlotKey]*pointerEntry
	recency    *list.List
}

// NewPointerCache constructs an entry-bounded slot-pointer cache. A zero bound
// disables admission and makes every lookup a correctness-safe miss.
func NewPointerCache(maxEntries int) (*PointerCache, error) {
	if maxEntries < 0 {
		return nil, errInvalidLimits
	}
	return &PointerCache{
		maxEntries: maxEntries,
		entries:    make(map[SlotKey]*pointerEntry),
		recency:    list.New(),
	}, nil
}

// UpdateCommitted refreshes a resident pointer after its authoritative CAS has
// committed. An update never fills a miss, so delayed best-effort delivery
// cannot resurrect an evicted generation.
func (c *PointerCache) UpdateCommitted(key SlotKey, pointer SlotPointer) error {
	if !key.valid() {
		return errInvalidSlotKey
	}
	if !pointer.valid() {
		return errInvalidSlotPointer
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.entries[key]
	if !ok {
		return nil
	}
	return c.updateResidentLocked(existing, pointer)
}

// FillAuthoritative admits pointer state returned by an authoritative lookup
// after a cache miss. A concurrent resident update still retains the monotonic
// generation and conflict checks.
func (c *PointerCache) FillAuthoritative(key SlotKey, pointer SlotPointer) error {
	if !key.valid() {
		return errInvalidSlotKey
	}
	if !pointer.valid() {
		return errInvalidSlotPointer
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		return c.updateResidentLocked(existing, pointer)
	}
	if c.maxEntries == 0 {
		return nil
	}
	if len(c.entries) == c.maxEntries {
		c.evictOldestLocked()
	}
	entry := &pointerEntry{key: key, pointer: pointer}
	entry.recency = c.recency.PushFront(entry)
	c.entries[key] = entry
	return nil
}

func (c *PointerCache) updateResidentLocked(existing *pointerEntry, pointer SlotPointer) error {
	switch {
	case pointer.generation < existing.pointer.generation:
		return errStalePointer
	case pointer.generation == existing.pointer.generation &&
		pointer.revision != existing.pointer.revision:
		return errPointerConflict
	case pointer.generation == existing.pointer.generation:
		c.recency.MoveToFront(existing.recency)
		return nil
	default:
		existing.pointer = pointer
		c.recency.MoveToFront(existing.recency)
		return nil
	}
}

// Pin returns an immutable request-local snapshot. Later committed updates do
// not mutate a returned pin.
func (c *PointerCache) Pin(key SlotKey) (RevisionPin, bool) {
	if !key.valid() {
		return RevisionPin{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return RevisionPin{}, false
	}
	c.recency.MoveToFront(entry.recency)
	return RevisionPin{
		namespace:  key.namespace,
		slot:       key.slot,
		revision:   entry.pointer.revision,
		generation: entry.pointer.generation,
	}, true
}

func (c *PointerCache) evictOldestLocked() {
	oldest := c.recency.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*pointerEntry)
	delete(c.entries, entry.key)
	c.recency.Remove(oldest)
}
