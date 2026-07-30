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
	errPointerFillHit     = errors.New("cache: slot pointer fill no longer needed")
	errPointerFillBusy    = errors.New("cache: slot pointer fill already active")
	errPointerFillLimit   = errors.New("cache: slot pointer fill limit reached")
	errPointerFillClosed  = errors.New("cache: slot pointer fill is closed")
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

type pointerFillState struct {
	pending    SlotPointer
	hasPending bool
	conflicted bool
}

// AuthoritativeFill reserves one bounded cache-miss resolution. Complete or
// Cancel closes the reservation; it cannot become an unbounded generation
// tombstone.
type AuthoritativeFill struct {
	cache *PointerCache
	key   SlotKey
	state *pointerFillState
}

// PointerCache is a bounded optional optimization for committed slot state.
type PointerCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[SlotKey]*pointerEntry
	fills      map[SlotKey]*pointerFillState
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
		fills:      make(map[SlotKey]*pointerFillState),
		recency:    list.New(),
	}, nil
}

// UpdateCommitted refreshes a resident pointer after its authoritative CAS has
// committed. During one active authoritative miss resolution, a newer update
// is retained only in that bounded reservation so it can supersede the fill.
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
	if ok {
		return c.updateResidentLocked(existing, pointer)
	}
	if fill, filling := c.fills[key]; filling {
		return updatePendingFill(fill, pointer)
	}
	return nil
}

// BeginAuthoritativeFill reserves bounded state for one authoritative lookup
// after a pointer-cache miss.
func (c *PointerCache) BeginAuthoritativeFill(key SlotKey) (AuthoritativeFill, error) {
	if !key.valid() {
		return AuthoritativeFill{}, errInvalidSlotKey
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return AuthoritativeFill{}, errPointerFillHit
	}
	if c.maxEntries == 0 {
		return AuthoritativeFill{}, errPointerFillLimit
	}
	if _, filling := c.fills[key]; filling {
		return AuthoritativeFill{}, errPointerFillBusy
	}
	if len(c.entries)+len(c.fills) == c.maxEntries {
		if len(c.entries) == 0 {
			return AuthoritativeFill{}, errPointerFillLimit
		}
		c.evictOldestLocked()
	}
	state := &pointerFillState{}
	c.fills[key] = state
	return AuthoritativeFill{cache: c, key: key, state: state}, nil
}

// Complete admits an authoritative lookup result unless a newer committed
// update superseded it while the bounded fill reservation was active.
func (f AuthoritativeFill) Complete(pointer SlotPointer) error {
	if f.cache == nil || f.state == nil || !f.key.valid() {
		return errPointerFillClosed
	}
	if !pointer.valid() {
		return errInvalidSlotPointer
	}

	c := f.cache
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, ok := c.fills[f.key]; !ok || current != f.state {
		return errPointerFillClosed
	}
	delete(c.fills, f.key)
	if f.state.conflicted {
		return errPointerConflict
	}
	selected, err := selectNewestPointer(pointer, f.state)
	if err != nil {
		return err
	}
	c.admitPointerLocked(f.key, selected)
	return nil
}

// Cancel abandons an active authoritative fill and releases its bounded
// reservation. It is safe to call more than once.
func (f AuthoritativeFill) Cancel() {
	if f.cache == nil || f.state == nil {
		return
	}
	f.cache.mu.Lock()
	if current, ok := f.cache.fills[f.key]; ok && current == f.state {
		delete(f.cache.fills, f.key)
	}
	f.cache.mu.Unlock()
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

func updatePendingFill(fill *pointerFillState, pointer SlotPointer) error {
	if fill.conflicted {
		return errPointerConflict
	}
	if !fill.hasPending || pointer.generation > fill.pending.generation {
		fill.pending = pointer
		fill.hasPending = true
		return nil
	}
	if pointer.generation < fill.pending.generation {
		return errStalePointer
	}
	if pointer.revision != fill.pending.revision {
		fill.conflicted = true
		return errPointerConflict
	}
	return nil
}

func selectNewestPointer(authoritative SlotPointer, fill *pointerFillState) (SlotPointer, error) {
	if !fill.hasPending || authoritative.generation > fill.pending.generation {
		return authoritative, nil
	}
	if authoritative.generation < fill.pending.generation {
		return fill.pending, nil
	}
	if authoritative.revision != fill.pending.revision {
		return SlotPointer{}, errPointerConflict
	}
	return authoritative, nil
}

func (c *PointerCache) admitPointerLocked(key SlotKey, pointer SlotPointer) {
	if c.maxEntries == 0 {
		return
	}
	if len(c.entries)+len(c.fills) == c.maxEntries {
		c.evictOldestLocked()
	}
	entry := &pointerEntry{key: key, pointer: pointer}
	entry.recency = c.recency.PushFront(entry)
	c.entries[key] = entry
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
