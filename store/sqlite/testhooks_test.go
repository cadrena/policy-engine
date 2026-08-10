package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "modernc.org/sqlite"
)

// sqliteLifecycleTestHooks are held by one test connector instance. They are
// never installed in production openers and never alter production code paths.
type sqliteLifecycleTestHooks struct {
	mu                        sync.Mutex
	failNextEvent             bool
	failNextTupleMutation     bool
	failNextAttributeMutation bool
	failNextCommit            bool
	failNextRollback          bool
	blockNextSnapshotRead     bool
	nextSnapshotReadPause     *sqliteSnapshotReadPause
	activeSnapshotReadPause   *sqliteSnapshotReadPause
	readerConnections         int
	readerConnectionCloses    int
}

func (h *sqliteLifecycleTestHooks) armNextEventAppendFailure() {
	h.mu.Lock()
	h.failNextEvent = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeEventAppendFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failNextEvent {
		return false
	}
	h.failNextEvent = false
	return true
}

// armNextAttributeMutationFailure injects one connector-local error only
// after the attribute row has been issued to SQLite. The writer transaction is
// then responsible for rolling back that real mutation.
func (h *sqliteLifecycleTestHooks) armNextAttributeMutationFailure() {
	h.mu.Lock()
	h.failNextAttributeMutation = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeAttributeMutationFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failNextAttributeMutation {
		return false
	}
	h.failNextAttributeMutation = false
	return true
}

func (h *sqliteLifecycleTestHooks) armNextTupleMutationFailure() {
	h.mu.Lock()
	h.failNextTupleMutation = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeTupleMutationFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failNextTupleMutation {
		return false
	}
	h.failNextTupleMutation = false
	return true
}

func (h *sqliteLifecycleTestHooks) armNextCommitFailure() {
	h.mu.Lock()
	h.failNextCommit = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeCommitFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failNextCommit {
		return false
	}
	h.failNextCommit = false
	return true
}

func (h *sqliteLifecycleTestHooks) armNextSnapshotRollbackFailure() {
	h.mu.Lock()
	h.failNextRollback = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeSnapshotRollbackFailure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failNextRollback {
		return false
	}
	h.failNextRollback = false
	return true
}

func (h *sqliteLifecycleTestHooks) readerConnectionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readerConnections
}

func (h *sqliteLifecycleTestHooks) readerConnectionCloseCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readerConnectionCloses
}

func (h *sqliteLifecycleTestHooks) openedConnection(reader bool) {
	if !reader {
		return
	}
	h.mu.Lock()
	h.readerConnections++
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) closedConnection(reader bool) {
	if !reader {
		return
	}
	h.mu.Lock()
	h.readerConnectionCloses++
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) armNextSnapshotReadBlock() {
	h.mu.Lock()
	h.blockNextSnapshotRead = true
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) consumeSnapshotReadBlock() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.blockNextSnapshotRead {
		return false
	}
	h.blockNextSnapshotRead = false
	return true
}

func (h *sqliteLifecycleTestHooks) pauseNextSnapshotRead() *sqliteSnapshotReadPause {
	pause := &sqliteSnapshotReadPause{entered: make(chan struct{}), release: make(chan struct{})}
	h.mu.Lock()
	if h.nextSnapshotReadPause != nil || h.activeSnapshotReadPause != nil {
		h.mu.Unlock()
		panic("sqlite: snapshot read pause already armed")
	}
	h.nextSnapshotReadPause = pause
	h.mu.Unlock()
	return pause
}

func (h *sqliteLifecycleTestHooks) consumeSnapshotReadPause() *sqliteSnapshotReadPause {
	h.mu.Lock()
	pause := h.nextSnapshotReadPause
	h.nextSnapshotReadPause = nil
	if pause != nil {
		h.activeSnapshotReadPause = pause
	}
	h.mu.Unlock()
	return pause
}

func (h *sqliteLifecycleTestHooks) finishSnapshotReadPause(pause *sqliteSnapshotReadPause) {
	h.mu.Lock()
	if h.activeSnapshotReadPause == pause {
		h.activeSnapshotReadPause = nil
	}
	h.mu.Unlock()
}

func (h *sqliteLifecycleTestHooks) reset() {
	h.mu.Lock()
	pendingPause := h.nextSnapshotReadPause
	activePause := h.activeSnapshotReadPause
	h.failNextEvent = false
	h.failNextTupleMutation = false
	h.failNextAttributeMutation = false
	h.failNextCommit = false
	h.failNextRollback = false
	h.blockNextSnapshotRead = false
	h.nextSnapshotReadPause = nil
	h.activeSnapshotReadPause = nil
	h.mu.Unlock()
	if pendingPause != nil {
		pendingPause.Release()
	}
	if activePause != nil {
		activePause.Release()
	}
}

type sqliteSnapshotReadPause struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (p *sqliteSnapshotReadPause) enteredRead() {
	p.enteredOnce.Do(func() { close(p.entered) })
}

func (p *sqliteSnapshotReadPause) Release() {
	p.releaseOnce.Do(func() { close(p.release) })
}

type sqliteLifecycleConnector struct {
	driver.Connector
	hooks  *sqliteLifecycleTestHooks
	reader bool
}

func (c sqliteLifecycleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	c.hooks.openedConnection(c.reader)
	return sqliteLifecycleConn{Conn: conn, hooks: c.hooks, reader: c.reader}, nil
}

type sqliteLifecycleConn struct {
	driver.Conn
	hooks  *sqliteLifecycleTestHooks
	reader bool
}

func (c sqliteLifecycleConn) ExecContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if isStateEventInsert(query) && c.hooks.consumeEventAppendFailure() {
		return nil, sqliteError(policyengine.ErrorUnavailable)
	}
	if isCommit(query) && c.hooks.consumeCommitFailure() {
		return nil, sqliteError(policyengine.ErrorUnavailable)
	}
	if isRollback(query) && c.hooks.consumeSnapshotRollbackFailure() {
		return nil, sqliteError(policyengine.ErrorUnavailable)
	}
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		result, err := execer.ExecContext(ctx, query, arguments)
		if err != nil {
			return result, err
		}
		if (isTupleMutation(query) && c.hooks.consumeTupleMutationFailure()) ||
			(isAttributeMutation(query) && c.hooks.consumeAttributeMutationFailure()) {
			return nil, sqliteError(policyengine.ErrorUnavailable)
		}
		return result, nil
	}
	return nil, driver.ErrSkip
}

func (c sqliteLifecycleConn) Close() error {
	c.hooks.closedConnection(c.reader)
	return c.Conn.Close()
}

func (c sqliteLifecycleConn) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if isSnapshotReadQuery(query) {
		if c.hooks.consumeSnapshotReadBlock() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if pause := c.hooks.consumeSnapshotReadPause(); pause != nil {
			pause.enteredRead()
			select {
			case <-pause.release:
				c.hooks.finishSnapshotReadPause(pause)
			case <-ctx.Done():
				c.hooks.finishSnapshotReadPause(pause)
				return nil, ctx.Err()
			}
		}
	}
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, query, arguments)
	}
	return nil, driver.ErrSkip
}

func isStateEventInsert(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "INSERT INTO STATE_EVENTS")
}

func isAttributeMutation(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "INSERT INTO ATTRIBUTES")
}

func isTupleMutation(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "INSERT INTO TUPLES")
}

func isCommit(query string) bool {
	return strings.EqualFold(strings.TrimSpace(query), "COMMIT")
}

func isRollback(query string) bool {
	return strings.EqualFold(strings.TrimSpace(query), "ROLLBACK")
}

func isSnapshotReadQuery(query string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(query))
	return strings.HasPrefix(normalized, "SELECT TUPLE_KEY, SUBJECT_TYPE, SUBJECT_ID, SUBJECT_RELATION, RELATION, RESOURCE_TYPE, RESOURCE_ID, EXPIRES_AT_NS FROM TUPLES") ||
		strings.HasPrefix(normalized, "SELECT ENTITY_TYPE, ENTITY_ID, PATH, VALUE, EXPIRES_AT_NS FROM ATTRIBUTES") ||
		strings.HasPrefix(normalized, "SELECT ATTRIBUTE.ATTRIBUTE_KEY, ATTRIBUTE.ENTITY_TYPE, ATTRIBUTE.ENTITY_ID, ATTRIBUTE.PATH, ATTRIBUTE.VALUE FROM ATTRIBUTE_ANCESTORS AS ANCESTOR")
}

func lifecycleTestConnectorFactory(hooks *sqliteLifecycleTestHooks) connectorFactory {
	return func(dsn string) (driver.Connector, error) {
		base, err := moderncsqlite.NewConnector(dsn)
		if err != nil {
			return base, err
		}
		return sqliteLifecycleConnector{Connector: base, hooks: hooks, reader: strings.Contains(dsn, "_query_only=1")}, nil
	}
}

func openMigratedStoreWithHooksForTest(t testing.TB, configurations ...Config) (*Store, *sqliteLifecycleTestHooks) {
	t.Helper()
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if len(configurations) == 1 {
		config = configurations[0]
	}
	if len(configurations) > 1 {
		t.Fatal("openMigratedStoreWithHooksForTest accepts at most one configuration")
	}
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	hooks := &sqliteLifecycleTestHooks{}
	database, err := openDatabaseWithConnectorFactory(context.Background(), config, lifecycleTestConnectorFactory(hooks))
	if err != nil {
		t.Fatalf("openDatabaseWithConnectorFactory() error = %v", err)
	}
	result, err := newStoreFromDatabase(context.Background(), database)
	if err != nil {
		_ = database.Close()
		t.Fatalf("newStoreFromDatabase() error = %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	// LIFO cleanup releases a paused reader before closing its pool.
	t.Cleanup(hooks.reset)
	return result, hooks
}

type sqliteRevisionPause struct {
	entered          chan struct{}
	contendedSignal  chan struct{}
	waiterWokeSignal chan struct{}
	release          chan struct{}
	resumeWaiter     chan struct{}
	enteredOnce      sync.Once
	contendedOnce    sync.Once
	wokeOnce         sync.Once
	releaseOnce      sync.Once
	resumeWaiterOnce sync.Once
}

// pauseNextRevisionCommit is package-test-only conformance control. The
// production Store has no pause or fault API; this only installs the private,
// nil-by-default observer for the next real reservation.
func (s *Store) pauseNextRevisionCommit() *sqliteRevisionPause {
	pause := &sqliteRevisionPause{
		entered:          make(chan struct{}),
		contendedSignal:  make(chan struct{}),
		waiterWokeSignal: make(chan struct{}),
		release:          make(chan struct{}),
		resumeWaiter:     make(chan struct{}),
	}
	s.revisions.mu.Lock()
	if s.revisions.observer != nil {
		s.revisions.mu.Unlock()
		panic("sqlite: revision lifecycle observer already armed")
	}
	s.revisions.observer = pause
	s.revisions.mu.Unlock()
	return pause
}

func (p *sqliteRevisionPause) Release() {
	p.releaseOnce.Do(func() { close(p.release) })
}

func (p *sqliteRevisionPause) ResumeWaiter() {
	p.resumeWaiterOnce.Do(func() { close(p.resumeWaiter) })
}

func (p *sqliteRevisionPause) ownerEntered(ctx context.Context) {
	p.enteredOnce.Do(func() { close(p.entered) })
	select {
	case <-p.release:
	case <-ctx.Done():
	}
}

func (p *sqliteRevisionPause) contended() {
	p.contendedOnce.Do(func() { close(p.contendedSignal) })
}

func (p *sqliteRevisionPause) waiterWoke(ctx context.Context) {
	p.wokeOnce.Do(func() { close(p.waiterWokeSignal) })
	select {
	case <-p.resumeWaiter:
	case <-ctx.Done():
	}
}

func (*sqliteRevisionPause) dataPreAdmission(context.Context) {}

type sqliteDataPause struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

// pauseNextDataCommit is package-test-only ordering control. It reuses the
// same private nil-by-default lifecycle seam as revision contention tests and
// only delays a validated WriteData call immediately before writer admission.
func (s *Store) pauseNextDataCommit() *sqliteDataPause {
	pause := &sqliteDataPause{entered: make(chan struct{}), release: make(chan struct{})}
	s.revisions.mu.Lock()
	if s.revisions.observer != nil {
		s.revisions.mu.Unlock()
		panic("sqlite: revision lifecycle observer already armed")
	}
	s.revisions.observer = pause
	s.revisions.mu.Unlock()
	return pause
}

func (p *sqliteDataPause) Release() {
	p.releaseOnce.Do(func() { close(p.release) })
}

func (*sqliteDataPause) ownerEntered(context.Context) {}

func (*sqliteDataPause) contended() {}

func (*sqliteDataPause) waiterWoke(context.Context) {}

func (p *sqliteDataPause) dataPreAdmission(ctx context.Context) {
	p.enteredOnce.Do(func() { close(p.entered) })
	select {
	case <-p.release:
	case <-ctx.Done():
	}
}

// expireEvents is package-test-only conformance control. It applies the same
// durable expired-through watermark used by normal retention, without making
// expiry a production mutation API.
func (s *Store) expireEvents(ctx context.Context, namespace, throughCursor string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	cursor, err := s.decodeCursor(throughCursor, cursorDomainEvent, namespace, "")
	if err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	return s.db.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		head, err := readNamespaceHead(ctx, conn, namespace)
		if errors.Is(err, sql.ErrNoRows) {
			return sqliteError(policyengine.ErrorInvalidArgument)
		}
		if err != nil {
			return err
		}
		if cursor.position > uint64(head.eventSequence) {
			return sqliteError(policyengine.ErrorInvalidArgument)
		}
		if _, err := conn.ExecContext(ctx, "DELETE FROM state_events WHERE namespace = ? AND sequence <= ?", namespace, int64(cursor.position)); err != nil {
			return mapError(ctx, err)
		}
		if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET expired_through = CASE WHEN expired_through < ? THEN ? ELSE expired_through END WHERE namespace = ?", int64(cursor.position), int64(cursor.position), namespace); err != nil {
			return mapError(ctx, err)
		}
		return nil
	})
}
