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
	mu            sync.Mutex
	failNextEvent bool
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

type sqliteLifecycleConnector struct {
	driver.Connector
	hooks *sqliteLifecycleTestHooks
}

func (c sqliteLifecycleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return sqliteLifecycleConn{Conn: conn, hooks: c.hooks}, nil
}

type sqliteLifecycleConn struct {
	driver.Conn
	hooks *sqliteLifecycleTestHooks
}

func (c sqliteLifecycleConn) ExecContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if isStateEventInsert(query) && c.hooks.consumeEventAppendFailure() {
		return nil, sqliteError(policyengine.ErrorUnavailable)
	}
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, query, arguments)
	}
	return nil, driver.ErrSkip
}

func isStateEventInsert(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "INSERT INTO STATE_EVENTS")
}

func lifecycleTestConnectorFactory(hooks *sqliteLifecycleTestHooks) connectorFactory {
	return func(dsn string) (driver.Connector, error) {
		base, err := moderncsqlite.NewConnector(dsn)
		if err != nil || strings.Contains(dsn, "_query_only=1") {
			return base, err
		}
		return sqliteLifecycleConnector{Connector: base, hooks: hooks}, nil
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
