package sqlite

import (
	"context"
	"database/sql"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
)

const offlinePruneNamespaceBatch = 256

// PruneExpiredEvents applies normal event retention to every namespace in a
// stopped SQLite store. It validates the complete source before changing it,
// holds the exclusive maintenance lock, and commits all watermarks and deletes
// together. It does not erase historical bytes from SQLite pages or WAL files.
func PruneExpiredEvents(ctx context.Context, config Config) error {
	config, err := validateMigrationRequest(ctx, config)
	if err != nil {
		return err
	}
	exists, err := sqliteDatabaseExists(config.Path)
	if err != nil {
		return mapError(ctx, err)
	}
	if !exists {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	lock, err := newAdvisoryLock(config.Path)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := lockIntegrityExclusive(ctx, lock, config.BusyTimeout); err != nil {
		return err
	}
	if err := validateWALFile(ctx, config.Path); err != nil {
		return integrityResultError(ctx, err)
	}
	database, conn, err := openExistingIntegrityConnectionWithConnectorFactory(ctx, config, moderncsqlite.NewConnector)
	if err != nil {
		return integrityResultError(ctx, err)
	}
	defer closeMigrationConnection(database, conn)
	if err := persistIntegrityWAL(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := verifyConnectionPragmas(ctx, conn, config, false); err != nil {
		return integrityResultError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return integrityResultError(ctx, mapError(ctx, err))
	}
	committed := false
	defer func() {
		if !committed {
			_ = rollbackMigration(conn)
		}
	}()
	if err := validateWALFile(ctx, config.Path); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := fullIntegrityCheck(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := validateOfflineEventOrder(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	_, nowNS, err := canonicalClockNow(config.Clock)
	if err != nil {
		return err
	}
	if err := pruneEveryNamespace(ctx, conn, nowNS); err != nil {
		return integrityResultError(ctx, err)
	}
	if err := fullIntegrityCheck(ctx, conn); err != nil {
		return integrityResultError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return mapError(ctx, err)
	}
	committed = true
	return nil
}

func validateOfflineEventOrder(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "SELECT namespace, created_at_ns FROM state_events ORDER BY namespace, sequence")
	if err != nil {
		return mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	var previousNamespace string
	var previousTime int64
	seen := false
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return err
		}
		var namespace string
		var createdAtNS int64
		if err := rows.Scan(&namespace, &createdAtNS); err != nil {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		if seen && namespace == previousNamespace && createdAtNS < previousTime {
			return sqliteError(policyengine.ErrorIntegrity)
		}
		previousNamespace = namespace
		previousTime = createdAtNS
		seen = true
	}
	if err := rows.Err(); err != nil {
		return mapError(ctx, err)
	}
	return nil
}

func pruneEveryNamespace(ctx context.Context, conn *sql.Conn, nowNS int64) error {
	last := ""
	for {
		namespaces, err := readPruneNamespaceBatch(ctx, conn, last)
		if err != nil {
			return err
		}
		if len(namespaces) == 0 {
			return nil
		}
		for _, namespace := range namespaces {
			head, err := readNamespaceHead(ctx, conn, namespace)
			if err != nil {
				return err
			}
			effectiveNS := nowNS
			if head.effectiveTimeIsSet && effectiveNS < head.effectiveTimeNS {
				effectiveNS = head.effectiveTimeNS
			}
			if !head.effectiveTimeIsSet || effectiveNS != head.effectiveTimeNS {
				if _, err := conn.ExecContext(ctx, "UPDATE namespace_heads SET effective_time_ns = ? WHERE namespace = ?", effectiveNS, namespace); err != nil {
					return mapError(ctx, err)
				}
			}
			if err := pruneEvents(ctx, conn, namespace, effectiveNS); err != nil {
				return err
			}
		}
		last = namespaces[len(namespaces)-1]
	}
}

func readPruneNamespaceBatch(ctx context.Context, conn *sql.Conn, last string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT namespace FROM namespace_heads WHERE namespace > ? ORDER BY namespace LIMIT ?", last, offlinePruneNamespaceBatch)
	if err != nil {
		return nil, mapError(ctx, err)
	}
	defer func() { _ = rows.Close() }()
	namespaces := make([]string, 0, offlinePruneNamespaceBatch)
	for rows.Next() {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var namespace string
		if err := rows.Scan(&namespace); err != nil {
			return nil, sqliteError(policyengine.ErrorIntegrity)
		}
		namespaces = append(namespaces, namespace)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(ctx, err)
	}
	return namespaces, nil
}
