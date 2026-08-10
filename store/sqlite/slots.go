package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

// Activate performs an ABA-safe compare-and-swap, persists the new head and
// retained activation history, and appends its state event in one transaction.
func (s *Store) Activate(ctx context.Context, request policyengine.ActivateRequest) (policyengine.ActivateResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.ActivateResponse{}, err
	}
	if _, err := policyengine.NewActivateRequest(request.Namespace(), request.Slot(), request.TargetRevisionID(), request.Expectation()); err != nil {
		return policyengine.ActivateResponse{}, mapError(ctx, err)
	}
	var response policyengine.ActivateResponse
	err := s.db.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		if _, exists, err := readRevision(ctx, conn, request.Namespace(), request.TargetRevisionID()); err != nil {
			return err
		} else if !exists {
			return sqliteError(policyengine.ErrorNotFound)
		}
		current, exists, err := readSlotHead(ctx, conn, request.Namespace(), request.Slot())
		if err != nil {
			return err
		}
		if !activationExpectationMatches(request.Expectation(), current, exists) {
			return sqliteError(policyengine.ErrorConflict)
		}
		generation := uint64(1)
		if exists {
			if current.Generation() >= uint64(math.MaxInt64) {
				return sqliteError(policyengine.ErrorResourceExhausted)
			}
			generation = current.Generation() + 1
		}
		occurredAt, err := s.effectiveNow(ctx, conn, request.Namespace())
		if err != nil {
			return err
		}
		activation, err := policyengine.NewActivation(request.Namespace(), request.Slot(), request.TargetRevisionID(), generation, occurredAt)
		if err != nil {
			return sqliteError(policyengine.ErrorInternal)
		}
		_, occurredAtNS, ok := sqliteTimestamp(activation.ActivatedAt())
		if !ok {
			return sqliteError(policyengine.ErrorInternal)
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO slot_heads(namespace, slot, revision_id, generation, activated_at_ns) VALUES (?, ?, ?, ?, ?) ON CONFLICT(namespace, slot) DO UPDATE SET revision_id = excluded.revision_id, generation = excluded.generation, activated_at_ns = excluded.activated_at_ns", request.Namespace(), request.Slot(), request.TargetRevisionID(), int64(generation), occurredAtNS); err != nil {
			return mapError(ctx, err)
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO activation_history(namespace, slot, generation, revision_id, activated_at_ns) VALUES (?, ?, ?, ?, ?)", request.Namespace(), request.Slot(), int64(generation), request.TargetRevisionID(), occurredAtNS); err != nil {
			return mapError(ctx, err)
		}
		if err := pruneActivationHistory(ctx, conn, request.Namespace(), request.Slot(), s.activationHistoryRetention); err != nil {
			return err
		}
		if err := s.appendStateEvent(ctx, conn, policyengine.StateEventInput{
			Namespace: request.Namespace(), Kind: policyengine.StateEventSlotActivated, RevisionID: request.TargetRevisionID(), Slot: request.Slot(), SlotGeneration: generation,
		}, occurredAt); err != nil {
			return err
		}
		response, err = policyengine.NewActivateResponse(activation)
		if err != nil {
			return sqliteError(policyengine.ErrorInternal)
		}
		return nil
	})
	if err != nil {
		return policyengine.ActivateResponse{}, err
	}
	return response, nil
}

func activationExpectationMatches(expectation policyengine.SlotExpectation, current policyengine.Activation, exists bool) bool {
	if expectation.IsUnset() {
		return !exists
	}
	revisionID, generation, active := expectation.Active()
	return active && exists && current.RevisionID() == revisionID && current.Generation() == generation
}

func readSlotHead(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, namespace, slot string) (policyengine.Activation, bool, error) {
	var revisionID string
	var generation, activatedAtNS int64
	err := queryer.QueryRowContext(ctx, "SELECT revision_id, generation, activated_at_ns FROM slot_heads WHERE namespace = ? AND slot = ?", namespace, slot).Scan(&revisionID, &generation, &activatedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return policyengine.Activation{}, false, nil
	}
	if err != nil {
		return policyengine.Activation{}, false, mapError(ctx, err)
	}
	if generation <= 0 {
		return policyengine.Activation{}, false, sqliteError(policyengine.ErrorIntegrity)
	}
	result, err := policyengine.NewActivation(namespace, slot, revisionID, uint64(generation), time.Unix(0, activatedAtNS).UTC())
	if err != nil {
		return policyengine.Activation{}, false, sqliteError(policyengine.ErrorIntegrity)
	}
	return result, true, nil
}

func pruneActivationHistory(ctx context.Context, conn *sql.Conn, namespace, slot string, retention int) error {
	if retention < 2 {
		return sqliteError(policyengine.ErrorInternal)
	}
	var retainedTail int64
	err := conn.QueryRowContext(ctx, "SELECT generation FROM activation_history WHERE namespace = ? AND slot = ? ORDER BY generation DESC LIMIT 1 OFFSET ?", namespace, slot, retention-1).Scan(&retainedTail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || retainedTail <= 0 {
		if err != nil {
			return mapError(ctx, err)
		}
		return sqliteError(policyengine.ErrorIntegrity)
	}
	if _, err := conn.ExecContext(ctx, "DELETE FROM activation_history WHERE namespace = ? AND slot = ? AND generation < ?", namespace, slot, retainedTail); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

// Resolve returns the exact current slot activation.
func (s *Store) Resolve(ctx context.Context, request policyengine.ResolveRequest) (policyengine.ResolveResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.ResolveResponse{}, err
	}
	if _, err := policyengine.NewResolveRequest(request.Namespace(), request.Slot()); err != nil {
		return policyengine.ResolveResponse{}, mapError(ctx, err)
	}
	var activation policyengine.Activation
	found := false
	err := s.read(ctx, func(database *sql.DB) error {
		value, exists, err := readSlotHead(ctx, database, request.Namespace(), request.Slot())
		if err != nil {
			return err
		}
		activation, found = value, exists
		return nil
	})
	if err != nil {
		return policyengine.ResolveResponse{}, err
	}
	if !found {
		return policyengine.ResolveResponse{}, sqliteError(policyengine.ErrorNotFound)
	}
	return policyengine.NewResolveResponse(activation)
}

// ListActivationHistory returns the retained ascending-generation history page.
func (s *Store) ListActivationHistory(ctx context.Context, request policyengine.ListActivationHistoryRequest) (policyengine.ListActivationHistoryResponse, error) {
	if err := contextError(ctx); err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	if _, err := policyengine.NewListActivationHistoryRequest(request.Namespace(), request.Slot(), request.Cursor(), request.Limit()); err != nil {
		return policyengine.ListActivationHistoryResponse{}, mapError(ctx, err)
	}
	cursor, err := s.decodeCursor(request.Cursor(), cursorDomainHistory, request.Namespace(), request.Slot())
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	values := make([]policyengine.Activation, 0, request.Limit()+1)
	var oldest uint64
	err = s.read(ctx, func(database *sql.DB) error {
		var oldestGeneration int64
		headErr := database.QueryRowContext(ctx, "SELECT generation FROM activation_history WHERE namespace = ? AND slot = ? ORDER BY generation ASC LIMIT 1", request.Namespace(), request.Slot()).Scan(&oldestGeneration)
		if headErr != nil && !errors.Is(headErr, sql.ErrNoRows) {
			return headErr
		}
		if oldestGeneration > 0 {
			oldest = uint64(oldestGeneration)
		}
		if request.Cursor() != "" && oldest > 0 && cursor.position < oldest {
			return sqliteError(policyengine.ErrorCursorExpired)
		}
		rows, err := database.QueryContext(ctx, "SELECT generation, revision_id, activated_at_ns FROM activation_history WHERE namespace = ? AND slot = ? AND generation > ? ORDER BY generation ASC LIMIT ?", request.Namespace(), request.Slot(), int64(cursor.position), request.Limit()+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var previous int64
		for rows.Next() {
			var generation, activatedAtNS int64
			var revisionID string
			if err := rows.Scan(&generation, &revisionID, &activatedAtNS); err != nil {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			if generation <= 0 || generation <= previous {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			previous = generation
			activation, err := policyengine.NewActivation(request.Namespace(), request.Slot(), revisionID, uint64(generation), time.Unix(0, activatedAtNS).UTC())
			if err != nil {
				return sqliteError(policyengine.ErrorIntegrity)
			}
			values = append(values, activation)
		}
		return rows.Err()
	})
	if err != nil {
		return policyengine.ListActivationHistoryResponse{}, err
	}
	more := len(values) > request.Limit()
	if more {
		values = values[:request.Limit()]
	}
	next := ""
	if more {
		boundary := uint64(0)
		if oldest > 1 {
			boundary = oldest - 1
		}
		next, err = s.newCursor(cursorState{
			domain: cursorDomainHistory, namespace: request.Namespace(), slot: request.Slot(), position: values[len(values)-1].Generation(), boundary: boundary,
		})
		if err != nil {
			return policyengine.ListActivationHistoryResponse{}, err
		}
	}
	return policyengine.NewListActivationHistoryResponse(request, values, next)
}
