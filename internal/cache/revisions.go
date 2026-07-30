// Package cache provides bounded, process-local runtime caches.
package cache

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/conductera/dsl"
)

var (
	errInvalidRevisionKey = errors.New("cache: invalid revision key")
	errInvalidLimits      = errors.New("cache: invalid limits")
	errInvalidArtifact    = errors.New("cache: invalid compiled artifact")
	errNilLoader          = errors.New("cache: nil revision loader")
	errLoaderPanic        = errors.New("cache: revision loader panicked")
)

// RevisionKey identifies one compiled program exactly.
type RevisionKey struct {
	namespace    string
	revision     string
	evaluatorABI string
}

// NewRevisionKey constructs an exact namespace, revision, and evaluator ABI key.
func NewRevisionKey(namespace, revision, evaluatorABI string) (RevisionKey, error) {
	if namespace == "" || revision == "" || evaluatorABI == "" {
		return RevisionKey{}, errInvalidRevisionKey
	}
	return RevisionKey{
		namespace:    namespace,
		revision:     revision,
		evaluatorABI: evaluatorABI,
	}, nil
}

// Namespace returns the tenant namespace bound to the key.
func (k RevisionKey) Namespace() string { return k.namespace }

// Revision returns the exact immutable revision bound to the key.
func (k RevisionKey) Revision() string { return k.revision }

// EvaluatorABI returns the evaluator compatibility identity bound to the key.
func (k RevisionKey) EvaluatorABI() string { return k.evaluatorABI }

func (k RevisionKey) valid() bool {
	return k.namespace != "" && k.revision != "" && k.evaluatorABI != ""
}

// RevisionLimits are hard cache admission bounds. A zero bound disables
// admission while preserving cold-load behavior.
type RevisionLimits struct {
	MaxEntries int
	MaxBytes   int64
}

// HydratedRevision holds one opaque immutable DSL artifact and program.
type HydratedRevision struct {
	artifact         *dsl.Artifact
	approximateBytes int64
}

// Artifact returns the opaque immutable compiled artifact.
func (r HydratedRevision) Artifact() *dsl.Artifact { return r.artifact }

// Program returns the immutable executable program.
func (r HydratedRevision) Program() *dsl.Program {
	if r.artifact == nil {
		return nil
	}
	return r.artifact.Program()
}

// ApproximateBytes returns the bounded accounting weight of the hydrated value.
func (r HydratedRevision) ApproximateBytes() int64 { return r.approximateBytes }

type revisionEntry struct {
	key     RevisionKey
	value   HydratedRevision
	active  bool
	recency *list.Element
}

type revisionCall struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	waiters   int
	abandoned bool
	value     HydratedRevision
	err       error
}

// RevisionCache stores immutable hydrated revisions by exact identity.
type RevisionCache struct {
	mu       sync.Mutex
	limits   RevisionLimits
	entries  map[RevisionKey]*revisionEntry
	inflight map[RevisionKey]*revisionCall
	recency  *list.List
	bytes    int64
}

// NewRevisionCache constructs an empty bounded compiled-revision cache.
func NewRevisionCache(limits RevisionLimits) (*RevisionCache, error) {
	if limits.MaxEntries < 0 || limits.MaxBytes < 0 {
		return nil, errInvalidLimits
	}
	return &RevisionCache{
		limits:   limits,
		entries:  make(map[RevisionKey]*revisionEntry),
		inflight: make(map[RevisionKey]*revisionCall),
		recency:  list.New(),
	}, nil
}

// GetOrLoad returns a warm immutable revision or loads and admits a cold one.
func (c *RevisionCache) GetOrLoad(
	ctx context.Context,
	key RevisionKey,
	loader func(context.Context) (*dsl.Artifact, error),
) (HydratedRevision, error) {
	if err := ctx.Err(); err != nil {
		return HydratedRevision{}, err
	}
	if !key.valid() {
		return HydratedRevision{}, errInvalidRevisionKey
	}
	if loader == nil {
		return HydratedRevision{}, errNilLoader
	}

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok {
		c.recency.MoveToFront(entry.recency)
		c.mu.Unlock()
		return entry.value, nil
	}
	if call, exists := c.inflight[key]; exists {
		call.waiters++
		c.mu.Unlock()
		return c.waitForRevision(ctx, key, call)
	}
	loadCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &revisionCall{
		ctx:     loadCtx,
		cancel:  cancel,
		done:    make(chan struct{}),
		waiters: 1,
	}
	c.inflight[key] = call
	c.mu.Unlock()

	go c.loadRevision(key, call, loader)
	return c.waitForRevision(ctx, key, call)
}

func (c *RevisionCache) loadRevision(
	key RevisionKey,
	call *revisionCall,
	loader func(context.Context) (*dsl.Artifact, error),
) {
	var value HydratedRevision
	var loadErr error
	defer func() {
		if recover() != nil {
			value = HydratedRevision{}
			loadErr = errLoaderPanic
		}
		c.completeRevisionLoad(key, call, value, loadErr)
	}()

	var artifact *dsl.Artifact
	artifact, loadErr = loader(call.ctx)
	if loadErr == nil {
		value, loadErr = hydrateRevision(key, artifact)
	}
}

func (c *RevisionCache) completeRevisionLoad(
	key RevisionKey,
	call *revisionCall,
	value HydratedRevision,
	loadErr error,
) {
	defer call.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	current, currentExists := c.inflight[key]
	if currentExists && current == call {
		delete(c.inflight, key)
	}
	if loadErr == nil && !call.abandoned {
		value = c.admitLocked(key, value)
	}
	call.value = value
	call.err = loadErr
	close(call.done)
}

func (c *RevisionCache) waitForRevision(
	ctx context.Context,
	key RevisionKey,
	call *revisionCall,
) (HydratedRevision, error) {
	select {
	case <-call.done:
		return call.value, call.err
	case <-ctx.Done():
		c.mu.Lock()
		if current, exists := c.inflight[key]; exists && current == call {
			call.waiters--
			if call.waiters == 0 {
				call.abandoned = true
				delete(c.inflight, key)
				call.cancel()
			}
		}
		c.mu.Unlock()
		return HydratedRevision{}, ctx.Err()
	}
}

func (c *RevisionCache) admitLocked(key RevisionKey, value HydratedRevision) HydratedRevision {
	if existing, exists := c.entries[key]; exists {
		c.recency.MoveToFront(existing.recency)
		return existing.value
	}
	if c.limits.MaxEntries == 0 || c.limits.MaxBytes == 0 ||
		value.approximateBytes > c.limits.MaxBytes {
		return value
	}
	for len(c.entries) >= c.limits.MaxEntries ||
		c.bytes > c.limits.MaxBytes-value.approximateBytes {
		c.evictOneLocked()
	}
	entry := &revisionEntry{key: key, value: value}
	entry.recency = c.recency.PushFront(entry)
	c.entries[key] = entry
	c.bytes += value.approximateBytes
	return value
}

// SetActive changes the eviction preference for one resident exact revision.
// Active entries remain evictable when required to honor a hard bound.
func (c *RevisionCache) SetActive(key RevisionKey, active bool) {
	if !key.valid() {
		return
	}
	c.mu.Lock()
	if entry, exists := c.entries[key]; exists {
		entry.active = active
	}
	c.mu.Unlock()
}

func (c *RevisionCache) evictOneLocked() {
	candidate := c.recency.Back()
	for element := c.recency.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*revisionEntry)
		if !entry.active {
			candidate = element
			break
		}
	}
	if candidate == nil {
		return
	}
	entry := candidate.Value.(*revisionEntry)
	delete(c.entries, entry.key)
	c.recency.Remove(candidate)
	c.bytes -= entry.value.approximateBytes
}

func hydrateRevision(key RevisionKey, artifact *dsl.Artifact) (HydratedRevision, error) {
	if artifact == nil || artifact.Program() == nil {
		return HydratedRevision{}, errInvalidArtifact
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		return HydratedRevision{}, errInvalidArtifact
	}
	return HydratedRevision{
		artifact:         artifact,
		approximateBytes: approximateRevisionBytes(key, len(encoded)),
	}, nil
}
