package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

const (
	eventRetentionLimit    = policyengine.MaxAggregateWorkItems
	defaultEventRetention  = 24 * time.Hour
	eventRetentionDuration = int64(defaultEventRetention)
)

type namespaceHead struct {
	dataGeneration     int64
	eventSequence      int64
	expiredThrough     int64
	effectiveTimeNS    int64
	effectiveTimeIsSet bool
}

func (s *Store) ensureNamespaceHead(ctx context.Context, conn *sql.Conn, namespace string) (namespaceHead, error) {
	if _, err := conn.ExecContext(ctx, "INSERT INTO namespace_heads(namespace) VALUES (?) ON CONFLICT(namespace) DO NOTHING", namespace); err != nil {
		return namespaceHead{}, mapError(ctx, err)
	}
	return readNamespaceHead(ctx, conn, namespace)
}

func readNamespaceHead(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, namespace string) (namespaceHead, error) {
	var result namespaceHead
	var effectiveTimeNS sql.NullInt64
	err := queryer.QueryRowContext(ctx, "SELECT data_generation, event_sequence, expired_through, effective_time_ns FROM namespace_heads WHERE namespace = ?", namespace).Scan(
		&result.dataGeneration, &result.eventSequence, &result.expiredThrough, &effectiveTimeNS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return namespaceHead{}, sql.ErrNoRows
	}
	if err != nil {
		return namespaceHead{}, mapError(ctx, err)
	}
	if result.dataGeneration < 0 || result.eventSequence < 0 || result.expiredThrough < 0 || result.expiredThrough > result.eventSequence {
		return namespaceHead{}, sqliteError(policyengine.ErrorIntegrity)
	}
	if effectiveTimeNS.Valid {
		result.effectiveTimeNS = effectiveTimeNS.Int64
		result.effectiveTimeIsSet = true
	}
	return result, nil
}

func (s *Store) effectiveNow(ctx context.Context, conn *sql.Conn, namespace string) (time.Time, error) {
	candidate, candidateNS, err := s.now()
	if err != nil {
		return time.Time{}, err
	}
	head, err := s.ensureNamespaceHead(ctx, conn, namespace)
	if err != nil {
		return time.Time{}, err
	}
	effectiveNS := candidateNS
	if head.effectiveTimeIsSet && effectiveNS < head.effectiveTimeNS {
		effectiveNS = head.effectiveTimeNS
	}
	if !head.effectiveTimeIsSet || effectiveNS != head.effectiveTimeNS {
		if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET effective_time_ns = ? WHERE namespace = ?", effectiveNS, namespace); err != nil {
			return time.Time{}, mapError(ctx, err)
		}
	}
	if effectiveNS == candidateNS {
		return candidate, nil
	}
	return time.Unix(0, effectiveNS).UTC(), nil
}

func (s *Store) now() (result time.Time, nanos int64, err error) {
	defer func() {
		if recover() != nil {
			result = time.Time{}
			nanos = 0
			err = sqliteError(policyengine.ErrorInternal)
		}
	}()
	if s == nil || s.db == nil || s.db.config.Clock == nil {
		return time.Time{}, 0, sqliteError(policyengine.ErrorInternal)
	}
	result, nanos, ok := sqliteTimestamp(s.db.config.Clock.Now())
	if !ok {
		return time.Time{}, 0, sqliteError(policyengine.ErrorInternal)
	}
	return result, nanos, nil
}

func sqliteTimestamp(value time.Time) (time.Time, int64, bool) {
	if value.IsZero() {
		return time.Time{}, 0, false
	}
	utc := value.UTC()
	seconds := utc.Unix()
	const nanosPerSecond = int64(time.Second)
	if seconds > math.MaxInt64/nanosPerSecond || seconds < math.MinInt64/nanosPerSecond {
		return time.Time{}, 0, false
	}
	base := seconds * nanosPerSecond
	if base > math.MaxInt64-int64(utc.Nanosecond()) {
		return time.Time{}, 0, false
	}
	nanos := base + int64(utc.Nanosecond())
	canonical := time.Unix(0, nanos).UTC()
	if !canonical.Equal(utc) {
		return time.Time{}, 0, false
	}
	return canonical, nanos, true
}

func (s *Store) nextEventSequence(ctx context.Context, conn *sql.Conn, namespace string) (uint64, uint64, error) {
	head, err := s.ensureNamespaceHead(ctx, conn, namespace)
	if err != nil {
		return 0, 0, err
	}
	if head.eventSequence == math.MaxInt64 {
		return 0, 0, sqliteError(policyengine.ErrorResourceExhausted)
	}
	next := head.eventSequence + 1
	if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET event_sequence = ? WHERE namespace = ?", next, namespace); err != nil {
		return 0, 0, mapError(ctx, err)
	}
	return uint64(next), uint64(head.expiredThrough), nil
}

func (s *Store) appendStateEvent(ctx context.Context, conn *sql.Conn, input policyengine.StateEventInput, occurredAt time.Time) error {
	sequence, boundary, err := s.nextEventSequence(ctx, conn, input.Namespace)
	if err != nil {
		return err
	}
	cursor, err := s.newCursor(cursorState{
		domain: cursorDomainEvent, namespace: input.Namespace, position: sequence, boundary: boundary,
	})
	if err != nil {
		return err
	}
	input.Cursor = cursor
	input.OccurredAt = occurredAt.UTC()
	event, err := policyengine.NewStateEvent(input)
	if err != nil {
		return sqliteError(policyengine.ErrorInternal)
	}
	payload, err := encodeStateEvent(event)
	if err != nil {
		return err
	}
	when, occurredAtNS, ok := sqliteTimestamp(event.OccurredAt())
	if !ok || !when.Equal(event.OccurredAt()) {
		return sqliteError(policyengine.ErrorInternal)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO state_events(namespace, sequence, kind, payload, created_at_ns) VALUES (?, ?, ?, ?, ?)", input.Namespace, int64(sequence), stateEventKindName(event.Kind()), payload, occurredAtNS); err != nil {
		return mapError(ctx, err)
	}
	return pruneEvents(ctx, conn, input.Namespace, occurredAtNS)
}

func stateEventKindName(kind policyengine.StateEventKind) string {
	switch kind {
	case policyengine.StateEventRevisionPublished:
		return "revision_published"
	case policyengine.StateEventSlotActivated:
		return "slot_activated"
	case policyengine.StateEventDataWritten:
		return "data_written"
	default:
		return ""
	}
}

func pruneEvents(ctx context.Context, conn *sql.Conn, namespace string, effectiveNowNS int64) error {
	// Event timestamps are namespace-monotonic, so both time and count
	// retention can delete one durable sequence prefix and advance one watermark.
	timeThreshold := int64(math.MinInt64)
	if effectiveNowNS >= math.MinInt64+eventRetentionDuration {
		timeThreshold = effectiveNowNS - eventRetentionDuration
	}
	var timeCutoff int64
	if err := conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) FROM state_events WHERE namespace = ? AND created_at_ns <= ?", namespace, timeThreshold).Scan(&timeCutoff); err != nil {
		return mapError(ctx, err)
	}
	var countCutoff int64
	err := conn.QueryRowContext(ctx, "SELECT sequence FROM state_events WHERE namespace = ? ORDER BY sequence DESC LIMIT 1 OFFSET ?", namespace, eventRetentionLimit).Scan(&countCutoff)
	if errors.Is(err, sql.ErrNoRows) {
		countCutoff = 0
	} else if err != nil {
		return mapError(ctx, err)
	}
	cutoff := max(timeCutoff, countCutoff)
	if cutoff <= 0 {
		return nil
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM state_events WHERE namespace = ? AND sequence <= ?", namespace, cutoff); err != nil {
		return mapError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET expired_through = CASE WHEN expired_through < ? THEN ? ELSE expired_through END WHERE namespace = ?", cutoff, cutoff, namespace); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

// pruneEventsForRead advances the namespace's effective clock and applies
// retention before a bounded reader observes its event page. Cursor decoding
// remains outside this path so malformed cursors never call the clock or write.
func (s *Store) pruneEventsForRead(ctx context.Context, namespace string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	_, candidateNS, err := s.now()
	if err != nil {
		return err
	}
	return s.db.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		head, err := readNamespaceHead(ctx, conn, namespace)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		effectiveNS := candidateNS
		if head.effectiveTimeIsSet && effectiveNS < head.effectiveTimeNS {
			effectiveNS = head.effectiveTimeNS
		}
		if !head.effectiveTimeIsSet || effectiveNS != head.effectiveTimeNS {
			if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET effective_time_ns = ? WHERE namespace = ?", effectiveNS, namespace); err != nil {
				return mapError(ctx, err)
			}
		}
		return pruneEvents(ctx, conn, namespace, effectiveNS)
	})
}

// ListEvents returns bounded namespace-ordered retained state events.
func (s *Store) ListEvents(ctx context.Context, request policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if _, err := policyengine.NewListEventsRequest(request.Namespace(), request.AfterCursor(), request.Limit()); err != nil {
		return policyengine.ListEventsResponse{}, mapError(ctx, err)
	}
	cursor, err := s.decodeCursor(request.AfterCursor(), cursorDomainEvent, request.Namespace(), "")
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	if err := s.pruneEventsForRead(ctx, request.Namespace()); err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	events := make([]policyengine.StateEvent, 0, request.Limit()+1)
	err = s.read(ctx, func(database *sql.DB) error {
		head, headErr := readNamespaceHead(ctx, database, request.Namespace())
		if errors.Is(headErr, sql.ErrNoRows) {
			head = namespaceHead{}
		} else if headErr != nil {
			return headErr
		}
		if request.AfterCursor() != "" && (cursor.position <= uint64(head.expiredThrough) || cursor.boundary > uint64(head.expiredThrough)) {
			return sqliteError(policyengine.ErrorCursorExpired)
		}
		rows, queryErr := database.QueryContext(ctx, "SELECT sequence, kind, payload, created_at_ns FROM state_events WHERE namespace = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?", request.Namespace(), int64(cursor.position), request.Limit()+1)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		var previous int64
		for rows.Next() {
			var sequence, createdAtNS int64
			var kind string
			var payload []byte
			if err := rows.Scan(&sequence, &kind, &payload, &createdAtNS); err != nil {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			if sequence <= 0 || sequence <= previous {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			previous = sequence
			event, err := decodeStateEvent(payload)
			if err != nil {
				return err
			}
			when := time.Unix(0, createdAtNS).UTC()
			if event.Namespace() != request.Namespace() || stateEventKindName(event.Kind()) != kind || !event.OccurredAt().Equal(when) {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			eventCursor, err := s.decodeCursor(event.Cursor(), cursorDomainEvent, request.Namespace(), "")
			if err != nil || eventCursor.position != uint64(sequence) {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			events = append(events, event)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return policyengine.ListEventsResponse{}, err
	}
	more := len(events) > request.Limit()
	if more {
		events = events[:request.Limit()]
	}
	next := ""
	if more {
		next = events[len(events)-1].Cursor()
	}
	return policyengine.NewListEventsResponse(request, events, next)
}
