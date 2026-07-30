package cache

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/conductera/dsl"
)

func TestRevisionCacheKeyUsesExactNamespaceRevisionAndEvaluatorABI(t *testing.T) {
	t.Parallel()

	cache, err := NewRevisionCache(RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewRevisionCache() error = %v", err)
	}
	keys := []RevisionKey{
		mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1"),
		mustRevisionKey(t, "tenant-b", "revision-1", "abi-v1"),
		mustRevisionKey(t, "tenant-a", "revision-2", "abi-v1"),
		mustRevisionKey(t, "tenant-a", "revision-1", "abi-v2"),
	}
	loads := 0
	for _, key := range keys {
		got, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
			loads++
			return mustArtifact(t, "entity user {}"), nil
		})
		if err != nil {
			t.Fatalf("GetOrLoad(%+v) error = %v", key, err)
		}
		if got.Program() == nil {
			t.Fatalf("GetOrLoad(%+v).Program() = nil", key)
		}
	}
	for _, key := range keys {
		if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
			loads++
			return mustArtifact(t, "entity unexpected {}"), nil
		}); err != nil {
			t.Fatalf("warm GetOrLoad(%+v) error = %v", key, err)
		}
	}
	if loads != len(keys) {
		t.Fatalf("loader calls = %d, want %d exact identities", loads, len(keys))
	}
}

func TestHydratedRevisionIsImmutableAtCacheBoundary(t *testing.T) {
	t.Parallel()

	artifact := mustArtifact(t, "entity document {}")
	cache, err := NewRevisionCache(RevisionLimits{MaxEntries: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("NewRevisionCache() error = %v", err)
	}
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	first, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
		return artifact, nil
	})
	if err != nil {
		t.Fatalf("GetOrLoad() error = %v", err)
	}
	before, err := first.Artifact().MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	poisoned := first.Artifact().CanonicalIR()
	for index := range poisoned {
		poisoned[index] ^= 0xff
	}

	second, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
		t.Fatal("warm GetOrLoad() called loader")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("warm GetOrLoad() error = %v", err)
	}
	after, err := second.Artifact().MarshalBinary()
	if err != nil {
		t.Fatalf("warm MarshalBinary() error = %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("cached artifact changed through an accessor-returned byte slice")
	}
	if second.Program() == nil {
		t.Fatal("warm Program() = nil")
	}
}

func TestRevisionCacheCollapsesSameKeyConcurrentLoads(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	artifact := mustArtifact(t, "entity user {}")
	const callers = 12
	start := make(chan struct{})
	arrived := make(chan struct{}, callers)
	loaderEntered := make(chan struct{})
	releaseLoader := make(chan struct{})
	results := make(chan *dsl.Program, callers)
	errs := make(chan error, callers)
	var calls atomic.Int32
	var enteredOnce sync.Once

	for range callers {
		go func() {
			<-start
			arrived <- struct{}{}
			value, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
				calls.Add(1)
				enteredOnce.Do(func() { close(loaderEntered) })
				<-releaseLoader
				return artifact, nil
			})
			if err != nil {
				errs <- err
				return
			}
			results <- value.Program()
		}()
	}
	close(start)
	for range callers {
		awaitSignal(t, arrived, "caller arrival")
	}
	awaitClosed(t, loaderEntered, "loader entry")
	awaitFlightWaiters(t, cache, key, callers)
	close(releaseLoader)

	for range callers {
		select {
		case err := <-errs:
			t.Fatalf("GetOrLoad() error = %v", err)
		case program := <-results:
			if program == nil {
				t.Fatal("GetOrLoad().Program() = nil")
			}
		case <-time.After(testTimeout):
			t.Fatal("timed out waiting for collapsed load result")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}
}

func TestRevisionCacheDoesNotCoalesceAcrossNamespaces(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	tenantA := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	tenantB := mustRevisionKey(t, "tenant-b", "revision-1", "abi-v1")
	artifactA := mustArtifact(t, "entity tenant_a {}")
	artifactB := mustArtifact(t, "entity tenant_b {}")
	aEntered := make(chan struct{})
	releaseA := make(chan struct{})
	aResult := make(chan HydratedRevision, 1)
	aErr := make(chan error, 1)
	go func() {
		value, err := cache.GetOrLoad(context.Background(), tenantA, func(context.Context) (*dsl.Artifact, error) {
			close(aEntered)
			<-releaseA
			return artifactA, nil
		})
		if err != nil {
			aErr <- err
			return
		}
		aResult <- value
	}()
	awaitClosed(t, aEntered, "tenant A loader entry")

	bDone := make(chan HydratedRevision, 1)
	bErr := make(chan error, 1)
	go func() {
		value, err := cache.GetOrLoad(context.Background(), tenantB, func(context.Context) (*dsl.Artifact, error) {
			return artifactB, nil
		})
		if err != nil {
			bErr <- err
			return
		}
		bDone <- value
	}()
	select {
	case err := <-bErr:
		t.Fatalf("tenant B GetOrLoad() error = %v", err)
	case value := <-bDone:
		if got, want := value.Artifact().Digest(), artifactB.Digest(); got != want {
			t.Fatalf("tenant B digest = %x, want %x", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("tenant B load coalesced with blocked tenant A load")
	}
	close(releaseA)
	select {
	case err := <-aErr:
		t.Fatalf("tenant A GetOrLoad() error = %v", err)
	case value := <-aResult:
		if got, want := value.Artifact().Digest(), artifactA.Digest(); got != want {
			t.Fatalf("tenant A digest = %x, want %x", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for tenant A result")
	}
}

func TestRevisionCacheCrossNamespaceCancellationDoesNotLeak(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	tenantA := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	tenantB := mustRevisionKey(t, "tenant-b", "revision-1", "abi-v1")
	artifactB := mustArtifact(t, "entity tenant_b {}")
	ctxA, cancelA := context.WithCancel(context.Background())
	aEntered := make(chan struct{})
	aCanceled := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		_, err := cache.GetOrLoad(ctxA, tenantA, func(ctx context.Context) (*dsl.Artifact, error) {
			close(aEntered)
			<-ctx.Done()
			close(aCanceled)
			return nil, errors.New("tenant A load failed after cancellation")
		})
		aDone <- err
	}()
	awaitClosed(t, aEntered, "tenant A loader entry")

	releaseB := make(chan struct{})
	bEntered := make(chan struct{})
	bDone := make(chan error, 1)
	go func() {
		_, err := cache.GetOrLoad(context.Background(), tenantB, func(ctx context.Context) (*dsl.Artifact, error) {
			close(bEntered)
			select {
			case <-releaseB:
				return artifactB, nil
			case <-ctx.Done():
				return nil, errors.New("tenant B load inherited tenant A cancellation")
			}
		})
		bDone <- err
	}()
	awaitClosed(t, bEntered, "tenant B loader entry")
	cancelA()
	if err := awaitError(t, aDone, "tenant A cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("tenant A error = %v, want context.Canceled", err)
	}
	awaitClosed(t, aCanceled, "tenant A loader cancellation")
	close(releaseB)
	if err := awaitError(t, bDone, "tenant B result"); err != nil {
		t.Fatalf("tenant B GetOrLoad() error = %v", err)
	}
}

func TestRevisionCacheSharesConcurrentLoadErrorAndRetries(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	loadErr := errors.New("compile failed")
	entered := make(chan struct{})
	release := make(chan struct{})
	start := make(chan struct{})
	arrived := make(chan struct{}, 2)
	errs := make(chan error, 2)
	var calls atomic.Int32
	var enteredOnce sync.Once
	for range 2 {
		go func() {
			<-start
			arrived <- struct{}{}
			_, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
				calls.Add(1)
				enteredOnce.Do(func() { close(entered) })
				<-release
				return nil, loadErr
			})
			errs <- err
		}()
	}
	close(start)
	awaitSignal(t, arrived, "first caller arrival")
	awaitSignal(t, arrived, "second caller arrival")
	awaitClosed(t, entered, "failing loader entry")
	awaitFlightWaiters(t, cache, key, 2)
	close(release)
	for range 2 {
		if err := awaitError(t, errs, "shared load error"); !errors.Is(err, loadErr) {
			t.Fatalf("GetOrLoad() error = %v, want %v", err, loadErr)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("failing loader calls = %d, want 1", got)
	}

	artifact := mustArtifact(t, "entity retry {}")
	value, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
		calls.Add(1)
		return artifact, nil
	})
	if err != nil {
		t.Fatalf("retry GetOrLoad() error = %v", err)
	}
	if value.Program() == nil {
		t.Fatal("retry GetOrLoad().Program() = nil")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("loader calls after retry = %d, want 2", got)
	}
}

func TestRevisionCacheCancellationIsPerWaiter(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	artifact := mustArtifact(t, "entity user {}")
	loaderEntered := make(chan struct{})
	releaseLoader := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.GetOrLoad(context.Background(), key, func(ctx context.Context) (*dsl.Artifact, error) {
			close(loaderEntered)
			select {
			case <-releaseLoader:
				return artifact, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		firstDone <- err
	}()
	awaitClosed(t, loaderEntered, "shared loader entry")

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := cache.GetOrLoad(waiterCtx, key, func(context.Context) (*dsl.Artifact, error) {
			return nil, errors.New("waiter unexpectedly invoked loader")
		})
		waiterDone <- err
	}()
	awaitFlightWaiters(t, cache, key, 2)
	cancelWaiter()
	if err := awaitError(t, waiterDone, "canceled waiter"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
	}
	close(releaseLoader)
	if err := awaitError(t, firstDone, "remaining waiter"); err != nil {
		t.Fatalf("remaining waiter error = %v", err)
	}
}

func TestRevisionCacheCancelsLoadAfterAllWaitersLeave(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	ctx, cancel := context.WithCancel(context.Background())
	loaderEntered := make(chan struct{})
	loaderCanceled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := cache.GetOrLoad(ctx, key, func(loadCtx context.Context) (*dsl.Artifact, error) {
			close(loaderEntered)
			<-loadCtx.Done()
			close(loaderCanceled)
			return nil, loadCtx.Err()
		})
		done <- err
	}()
	awaitClosed(t, loaderEntered, "loader entry")
	cancel()
	if err := awaitError(t, done, "canceled caller"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetOrLoad() error = %v, want context.Canceled", err)
	}
	awaitClosed(t, loaderCanceled, "shared loader cancellation")
}

func TestRevisionCacheDisabledAdmissionReloadsSequentialMisses(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 0, MaxBytes: 1 << 20})
	key := mustRevisionKey(t, "tenant-a", "revision-1", "abi-v1")
	artifact := mustArtifact(t, "entity user {}")
	loads := 0
	for range 2 {
		if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
			loads++
			return artifact, nil
		}); err != nil {
			t.Fatalf("GetOrLoad() error = %v", err)
		}
	}
	if loads != 2 {
		t.Fatalf("loader calls = %d, want 2 with admission disabled", loads)
	}
}

func TestRevisionCacheEntryBoundEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()

	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 2, MaxBytes: 1 << 20})
	keyA := mustRevisionKey(t, "tenant-a", "revision-a", "abi-v1")
	keyB := mustRevisionKey(t, "tenant-a", "revision-b", "abi-v1")
	keyC := mustRevisionKey(t, "tenant-a", "revision-c", "abi-v1")
	artifact := mustArtifact(t, "entity user {}")
	loads := map[RevisionKey]int{}
	load := func(key RevisionKey) {
		t.Helper()
		if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
			loads[key]++
			return artifact, nil
		}); err != nil {
			t.Fatalf("GetOrLoad(%s) error = %v", key.Revision(), err)
		}
	}

	load(keyA)
	load(keyB)
	load(keyA)
	load(keyC)
	load(keyC)
	load(keyB)
	if got := loads[keyA]; got != 1 {
		t.Fatalf("revision A loader calls = %d, want 1", got)
	}
	if got := loads[keyC]; got != 1 {
		t.Fatalf("revision C loader calls = %d, want 1 after admission", got)
	}
	if got := loads[keyB]; got != 2 {
		t.Fatalf("revision B loader calls = %d, want 2 after LRU eviction", got)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if got := len(cache.entries); got > 2 {
		t.Fatalf("entry count = %d, exceeds hard limit 2", got)
	}
}

func TestRevisionCacheApproximateByteAccountingAndHardBound(t *testing.T) {
	t.Parallel()

	keyA := mustRevisionKey(t, "tenant-a", "revision-a", "abi-v1")
	keyB := mustRevisionKey(t, "tenant-a", "revision-b", "abi-v1")
	artifactA := mustArtifact(t, "entity a {}")
	artifactB := mustArtifact(t, "entity a {}\nentity b { relation member @a }")
	valueA, err := hydrateRevision(keyA, artifactA)
	if err != nil {
		t.Fatalf("hydrateRevision(A) error = %v", err)
	}
	valueB, err := hydrateRevision(keyB, artifactB)
	if err != nil {
		t.Fatalf("hydrateRevision(B) error = %v", err)
	}
	encodedB, err := artifactB.MarshalBinary()
	if err != nil {
		t.Fatalf("artifactB.MarshalBinary() error = %v", err)
	}
	wantWeightB := approximateRevisionOverhead +
		int64(len(keyB.Namespace())+len(keyB.Revision())+len(keyB.EvaluatorABI())+len(encodedB))
	if got := valueB.ApproximateBytes(); got != wantWeightB {
		t.Fatalf("revision B approximate bytes = %d, want %d", got, wantWeightB)
	}
	byteLimit := max(valueA.ApproximateBytes(), valueB.ApproximateBytes())
	cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 8, MaxBytes: byteLimit})
	loads := map[RevisionKey]int{}
	for _, keyAndArtifact := range []struct {
		key      RevisionKey
		artifact *dsl.Artifact
	}{
		{key: keyA, artifact: artifactA},
		{key: keyB, artifact: artifactB},
		{key: keyB, artifact: artifactB},
	} {
		item := keyAndArtifact
		if _, err := cache.GetOrLoad(context.Background(), item.key, func(context.Context) (*dsl.Artifact, error) {
			loads[item.key]++
			return item.artifact, nil
		}); err != nil {
			t.Fatalf("GetOrLoad(%s) error = %v", item.key.Revision(), err)
		}
	}
	if got := loads[keyB]; got != 1 {
		t.Fatalf("revision B loader calls = %d, want 1 after byte-budget admission", got)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.bytes > byteLimit {
		t.Fatalf("accounted bytes = %d, exceeds hard limit %d", cache.bytes, byteLimit)
	}
	var summed int64
	for _, entry := range cache.entries {
		summed += entry.value.ApproximateBytes()
	}
	if cache.bytes != summed {
		t.Fatalf("accounted bytes = %d, want entry sum %d", cache.bytes, summed)
	}
}

func TestRevisionCacheOversizeEntryIsReturnedButNotAdmitted(t *testing.T) {
	t.Parallel()

	key := mustRevisionKey(t, "tenant-a", "revision-a", "abi-v1")
	artifact := mustArtifact(t, "entity user {}")
	value, err := hydrateRevision(key, artifact)
	if err != nil {
		t.Fatalf("hydrateRevision() error = %v", err)
	}
	cache := mustRevisionCache(t, RevisionLimits{
		MaxEntries: 4,
		MaxBytes:   value.ApproximateBytes() - 1,
	})
	loads := 0
	for range 2 {
		if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
			loads++
			return artifact, nil
		}); err != nil {
			t.Fatalf("GetOrLoad() error = %v", err)
		}
	}
	if loads != 2 {
		t.Fatalf("loader calls = %d, want 2 for oversize non-admission", loads)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) != 0 || cache.bytes != 0 {
		t.Fatalf("oversize admission retained entries=%d bytes=%d", len(cache.entries), cache.bytes)
	}
}

func TestRevisionCachePrefersActiveEntriesButDoesNotPinThem(t *testing.T) {
	t.Parallel()

	t.Run("preference", func(t *testing.T) {
		cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 2, MaxBytes: 1 << 20})
		activeA := mustRevisionKey(t, "tenant-a", "revision-a", "abi-v1")
		inactiveB := mustRevisionKey(t, "tenant-a", "revision-b", "abi-v1")
		keyC := mustRevisionKey(t, "tenant-a", "revision-c", "abi-v1")
		artifact := mustArtifact(t, "entity user {}")
		loads := map[RevisionKey]int{}
		load := func(key RevisionKey) {
			t.Helper()
			if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
				loads[key]++
				return artifact, nil
			}); err != nil {
				t.Fatalf("GetOrLoad(%s) error = %v", key.Revision(), err)
			}
		}

		load(activeA)
		cache.SetActive(activeA, true)
		load(inactiveB)
		load(keyC)
		load(activeA)
		load(inactiveB)
		if got := loads[activeA]; got != 1 {
			t.Fatalf("active revision A loader calls = %d, want 1 after preference", got)
		}
		if got := loads[inactiveB]; got != 2 {
			t.Fatalf("inactive revision B loader calls = %d, want 2 after preferred eviction", got)
		}
	})

	t.Run("not pinned", func(t *testing.T) {
		cache := mustRevisionCache(t, RevisionLimits{MaxEntries: 1, MaxBytes: 1 << 20})
		active := mustRevisionKey(t, "tenant-a", "revision-active", "abi-v1")
		replacement := mustRevisionKey(t, "tenant-a", "revision-replacement", "abi-v1")
		artifact := mustArtifact(t, "entity user {}")
		loads := map[RevisionKey]int{}
		load := func(key RevisionKey) {
			t.Helper()
			if _, err := cache.GetOrLoad(context.Background(), key, func(context.Context) (*dsl.Artifact, error) {
				loads[key]++
				return artifact, nil
			}); err != nil {
				t.Fatalf("GetOrLoad(%s) error = %v", key.Revision(), err)
			}
		}

		load(active)
		cache.SetActive(active, true)
		load(replacement)
		load(active)
		if got := loads[active]; got != 2 {
			t.Fatalf("active revision loader calls = %d, want 2 after eviction", got)
		}
	})
}

func mustRevisionKey(t *testing.T, namespace, revision, evaluatorABI string) RevisionKey {
	t.Helper()
	key, err := NewRevisionKey(namespace, revision, evaluatorABI)
	if err != nil {
		t.Fatalf("NewRevisionKey() error = %v", err)
	}
	return key
}

func mustArtifact(t *testing.T, source string) *dsl.Artifact {
	t.Helper()
	artifact, err := dsl.CompileArtifact("cache-test.cdr", []byte(source))
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	return artifact
}

const testTimeout = 5 * time.Second

func mustRevisionCache(t *testing.T, limits RevisionLimits) *RevisionCache {
	t.Helper()
	cache, err := NewRevisionCache(limits)
	if err != nil {
		t.Fatalf("NewRevisionCache() error = %v", err)
	}
	return cache
}

func awaitClosed(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitError(t *testing.T, result <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}

func awaitFlightWaiters(t *testing.T, cache *RevisionCache, key RevisionKey, want int) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		cache.mu.Lock()
		call := cache.inflight[key]
		got := 0
		if call != nil {
			got = call.waiters
		}
		cache.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight waiters = %d, want at least %d", got, want)
		}
		runtime.Gosched()
	}
}
