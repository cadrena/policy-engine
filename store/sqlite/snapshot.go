package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

type generationWaitSet struct {
	mu      sync.Mutex
	changed map[string]*generationWaiter
}

type generationWaiter struct {
	changed chan struct{}
	waiters int
}

func (g *generationWaitSet) registerLocked(namespace string) *generationWaiter {
	if g.changed == nil {
		g.changed = make(map[string]*generationWaiter)
	}
	value := g.changed[namespace]
	if value == nil {
		value = &generationWaiter{changed: make(chan struct{})}
		g.changed[namespace] = value
	}
	value.waiters++
	return value
}

func (g *generationWaitSet) unregister(namespace string, waiter *generationWaiter) {
	if waiter == nil {
		return
	}
	g.mu.Lock()
	if g.changed[namespace] == waiter {
		waiter.waiters--
		if waiter.waiters == 0 {
			delete(g.changed, namespace)
		}
	}
	g.mu.Unlock()
}

func (s *Store) notifyGenerationWaiters(namespace string) {
	if s == nil {
		return
	}
	s.generations.mu.Lock()
	if changed := s.generations.changed[namespace]; changed != nil {
		delete(s.generations.changed, namespace)
		close(changed.changed)
	}
	s.generations.mu.Unlock()
}

// OpenSnapshot waits for the requested lower bound and pins one physical
// SQLite read transaction. The namespace head is the first transaction read,
// so all later queries observe the same committed WAL view.
func (s *Store) OpenSnapshot(ctx context.Context, request store.SnapshotRequest) (store.Snapshot, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !request.Valid() {
		return nil, sqliteError(policyengine.ErrorInvalidArgument)
	}
	if s == nil || s.db == nil {
		return nil, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	readAt, readAtNS, ok := sqliteTimestamp(request.ReadAt())
	if !ok {
		return nil, sqliteError(policyengine.ErrorInvalidArgument)
	}

	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		view, err := s.openPinnedSnapshot(ctx, request, readAt, readAtNS)
		if err != nil {
			return nil, err
		}
		if view.generation >= request.MinimumGeneration() {
			if err := contextError(ctx); err != nil {
				_ = view.Close()
				return nil, err
			}
			return view, nil
		}
		view.closePinned()

		// Register before a second observation. A commit that races either
		// observation is then visible through the fresh pinned head or closes
		// this channel, so no generation wake-up can be lost. Do not hold this
		// mutex while acquiring a bounded reader permit: writers notify after
		// commit and must remain independent of saturated snapshot admission.
		s.generations.mu.Lock()
		waiter := s.generations.registerLocked(request.Namespace())
		s.generations.mu.Unlock()
		view, err = s.openPinnedSnapshot(ctx, request, readAt, readAtNS)
		if err != nil {
			s.generations.unregister(request.Namespace(), waiter)
			return nil, err
		}
		if view.generation >= request.MinimumGeneration() {
			s.generations.unregister(request.Namespace(), waiter)
			if err := contextError(ctx); err != nil {
				_ = view.Close()
				return nil, err
			}
			return view, nil
		}
		view.closePinned()

		select {
		case <-waiter.changed:
		case <-s.db.closed:
		case <-ctx.Done():
		}
		s.generations.unregister(request.Namespace(), waiter)
		// A usable context always wins when it races shutdown or notification.
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if s.db.isClosed() {
			return nil, sqliteError(policyengine.ErrorUnavailable)
		}
	}
}

func (s *Store) openPinnedSnapshot(ctx context.Context, request store.SnapshotRequest, readAt time.Time, readAtNS int64) (*snapshot, error) {
	conn, release, err := s.db.acquireReaderConnection(ctx)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			rollbackSnapshotConnection(conn)
			release()
		}
	}()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, mapError(ctx, err)
	}
	head, err := readNamespaceHead(ctx, conn, request.Namespace())
	if errors.Is(err, sql.ErrNoRows) {
		head = namespaceHead{}
	} else if err != nil {
		return nil, err
	}
	view := &snapshot{
		namespace: request.Namespace(), generation: uint64(head.dataGeneration), minimum: request.MinimumGeneration(),
		readAt: readAt, readAtNS: readAtNS, conn: conn, releaseConnection: release, closeDone: make(chan struct{}),
	}
	cleanup = false
	return view, nil
}

type snapshot struct {
	lifecycle sync.Mutex
	queryMu   sync.Mutex
	closing   bool
	active    int
	closeErr  error
	closeDone chan struct{}

	namespace  string
	generation uint64
	minimum    uint64
	readAt     time.Time
	readAtNS   int64

	conn              *sql.Conn
	releaseConnection func()
}

var _ store.Snapshot = (*snapshot)(nil)

func (s *snapshot) Namespace() string         { return s.namespace }
func (s *snapshot) Generation() uint64        { return s.generation }
func (s *snapshot) MinimumGeneration() uint64 { return s.minimum }
func (s *snapshot) ReadAt() time.Time         { return s.readAt }

func (s *snapshot) admit() (*sql.Conn, error) {
	if s == nil {
		return nil, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closing || s.conn == nil {
		return nil, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	s.active++
	return s.conn, nil
}

func (s *snapshot) release() {
	if s == nil {
		return
	}
	var conn *sql.Conn
	var release func()
	s.lifecycle.Lock()
	s.active--
	if s.closing && s.active == 0 {
		conn, release = s.detachLocked()
	}
	s.lifecycle.Unlock()
	if conn != nil || release != nil {
		s.finishClose(conn, release)
	}
}

func (s *snapshot) detachLocked() (*sql.Conn, func()) {
	conn, release := s.conn, s.releaseConnection
	s.conn = nil
	s.releaseConnection = nil
	return conn, release
}

func (s *snapshot) closePinned() {
	if s == nil {
		return
	}
	s.lifecycle.Lock()
	conn, release := s.detachLocked()
	s.closing = true
	s.lifecycle.Unlock()
	s.finishClose(conn, release)
}

func (s *snapshot) finishClose(conn *sql.Conn, release func()) {
	rollbackSnapshotConnection(conn)
	if release != nil {
		release()
	}
	s.lifecycle.Lock()
	select {
	case <-s.closeDone:
	default:
		close(s.closeDone)
	}
	s.lifecycle.Unlock()
}

func rollbackSnapshotConnection(conn *sql.Conn) {
	if conn != nil {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
	}
}

func (s *snapshot) queryConnection(ctx context.Context) (*sql.Conn, func(), error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	conn, err := s.admit()
	if err != nil {
		return nil, nil, err
	}
	s.queryMu.Lock()
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		s.queryMu.Unlock()
		s.release()
	}
	return conn, release, nil
}

// QueryTuples returns the complete active resource/relation result or a bound
// error, never a partial page. The resource index covers this exact shape.
func (s *snapshot) QueryTuples(ctx context.Context, query store.TupleQuery) (store.TupleResult, error) {
	if err := contextError(ctx); err != nil {
		return store.TupleResult{}, err
	}
	if !query.Valid() {
		return store.TupleResult{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	conn, release, err := s.queryConnection(ctx)
	if err != nil {
		return store.TupleResult{}, err
	}
	defer release()
	rows, err := conn.QueryContext(ctx, `SELECT tuple_key, subject_type, subject_id, subject_relation, relation, resource_type, resource_id, expires_at_ns FROM tuples
WHERE namespace = ? AND resource_type = ? AND resource_id = ? AND relation = ?
AND (expires_at_ns IS NULL OR expires_at_ns > ?)
ORDER BY subject_type, subject_id, subject_relation LIMIT ?`,
		s.namespace, query.Resource().Type, query.Resource().ID, query.Relation(), s.readAtNS, query.Limit()+1,
	)
	if err != nil {
		return store.TupleResult{}, mapError(ctx, err)
	}
	defer rows.Close()
	subjects := make([]dsl.SubjectRef, 0, min(query.Limit(), 16))
	for rows.Next() {
		var tupleKey []byte
		var subjectType, subjectID, subjectRelation, relation, resourceType, resourceID string
		var expiresAtNS sql.NullInt64
		if err := rows.Scan(&tupleKey, &subjectType, &subjectID, &subjectRelation, &relation, &resourceType, &resourceID, &expiresAtNS); err != nil {
			return store.TupleResult{}, sqliteError(policyengine.ErrorIntegrity)
		}
		tuple, err := decodeDurableTuple(tupleKey, subjectType, subjectID, subjectRelation, relation, resourceType, resourceID, expiresAtNS)
		if err != nil {
			return store.TupleResult{}, err
		}
		value := tuple.Tuple()
		if value.Resource != query.Resource() || value.Relation != query.Relation() {
			return store.TupleResult{}, sqliteError(policyengine.ErrorIntegrity)
		}
		subjects = append(subjects, value.Subject)
		if len(subjects) > query.Limit() {
			return store.TupleResult{}, sqliteError(policyengine.ErrorResourceExhausted)
		}
	}
	if err := rows.Err(); err != nil {
		return store.TupleResult{}, mapError(ctx, err)
	}
	if err := contextError(ctx); err != nil {
		return store.TupleResult{}, err
	}
	return store.NewTupleResult(query, subjects)
}

// GetAttribute returns one exact active typed value from the pinned view.
func (s *snapshot) GetAttribute(ctx context.Context, key policyengine.AttributeKey) (store.AttributeResult, error) {
	if err := contextError(ctx); err != nil {
		return store.AttributeResult{}, err
	}
	canonical, err := policyengine.NewAttributeKeyPath(key.Entity(), key.Path())
	if err != nil || !reflect.DeepEqual(canonical.Path(), key.Path()) {
		return store.AttributeResult{}, sqliteError(policyengine.ErrorInvalidArgument)
	}
	encoded, err := encodeAttributeKey(canonical)
	if err != nil {
		return store.AttributeResult{}, err
	}
	conn, release, err := s.queryConnection(ctx)
	if err != nil {
		return store.AttributeResult{}, err
	}
	defer release()
	var entityType, entityID string
	var path, value []byte
	var expiresAtNS sql.NullInt64
	err = conn.QueryRowContext(ctx, `SELECT entity_type, entity_id, path, value, expires_at_ns FROM attributes
WHERE namespace = ? AND attribute_key = ? AND (expires_at_ns IS NULL OR expires_at_ns > ?)`, s.namespace, encoded, s.readAtNS).
		Scan(&entityType, &entityID, &path, &value, &expiresAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return store.NewAttributeResult(canonical, policyengine.Value{}, false)
	}
	if err != nil {
		return store.AttributeResult{}, mapError(ctx, err)
	}
	if expiresAtNS.Valid && expiresAtNS.Int64 <= s.readAtNS {
		return store.NewAttributeResult(canonical, policyengine.Value{}, false)
	}
	attribute, err := decodeDurableAttribute(encoded, path, value, entityType, entityID)
	if err != nil {
		return store.AttributeResult{}, err
	}
	if attribute.Entity() != canonical.Entity() || !reflect.DeepEqual(attribute.Path(), canonical.Path()) {
		return store.AttributeResult{}, sqliteError(policyengine.ErrorIntegrity)
	}
	if err := contextError(ctx); err != nil {
		return store.AttributeResult{}, err
	}
	return store.NewAttributeResult(canonical, attribute.Value(), true)
}

// HasAttributeDescendant reports strict active occupancy below one exact
// entity/path boundary without reading an attribute value.
func (s *snapshot) HasAttributeDescendant(ctx context.Context, key policyengine.AttributeKey) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	canonical, err := policyengine.NewAttributeKeyPath(key.Entity(), key.Path())
	if err != nil || !reflect.DeepEqual(canonical.Path(), key.Path()) {
		return false, sqliteError(policyengine.ErrorInvalidArgument)
	}
	encoded, err := encodeAttributeKey(canonical)
	if err != nil {
		return false, err
	}
	conn, release, err := s.queryConnection(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	var attributeKey, path, value []byte
	var entityType, entityID string
	err = conn.QueryRowContext(ctx, `SELECT attribute.attribute_key, attribute.entity_type, attribute.entity_id, attribute.path, attribute.value FROM attribute_ancestors AS ancestor
JOIN attributes AS attribute ON attribute.namespace = ancestor.namespace AND attribute.attribute_key = ancestor.attribute_key
WHERE ancestor.namespace = ? AND ancestor.ancestor_path = ?
	AND (attribute.expires_at_ns IS NULL OR attribute.expires_at_ns > ?) LIMIT 1`, s.namespace, encoded, s.readAtNS).
		Scan(&attributeKey, &entityType, &entityID, &path, &value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapError(ctx, err)
	}
	if err := contextError(ctx); err != nil {
		return false, err
	}
	attribute, err := decodeDurableAttribute(attributeKey, path, value, entityType, entityID)
	if err != nil {
		return false, err
	}
	attributeKeyValue, err := attributeKeyFromAttribute(attribute)
	if err != nil {
		return false, err
	}
	prefixes, err := strictAttributePrefixes(attributeKeyValue)
	if err != nil {
		return false, err
	}
	for _, prefix := range prefixes {
		if bytes.Equal(prefix, encoded) {
			return true, nil
		}
	}
	return false, sqliteError(policyengine.ErrorIntegrity)
}

// Close flips admission first, then waits for all previously admitted reads
// before rolling back and releasing the physical read transaction exactly once.
func (s *snapshot) Close() error {
	if s == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	var conn *sql.Conn
	var release func()
	s.lifecycle.Lock()
	if !s.closing {
		s.closing = true
		if s.active == 0 {
			conn, release = s.detachLocked()
		}
	}
	done := s.closeDone
	s.lifecycle.Unlock()
	if conn != nil || release != nil {
		s.finishClose(conn, release)
	}
	<-done
	s.lifecycle.Lock()
	err := s.closeErr
	s.lifecycle.Unlock()
	return err
}

func (*snapshot) String() string { return "Snapshot{[REDACTED]}" }

func (*snapshot) GoString() string { return "Snapshot{[REDACTED]}" }

func (*snapshot) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("Snapshot{[REDACTED]}"))
}

func (*snapshot) LogValue() slog.Value {
	return slog.GroupValue(slog.String("type", "Snapshot"), slog.String("value", "[REDACTED]"))
}
