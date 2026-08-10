package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestIntegrityFullCheckAcceptsCompleteCanonicalStore(t *testing.T) {
	// This catches an offline checker that validates only an empty schema or
	// rejects the mutually consistent revision, slot, data, event, and replay
	// records produced by the public adapter.
	config := migratedIntegrityConfig(t)
	populateIntegrityFixture(t, config)

	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("FullIntegrityCheck(valid store) error = %v", err)
	}
}

func TestIntegrityFullCheckRejectsIndependentDurableInvariantViolations(t *testing.T) {
	// Each case names a different persisted invariant. A checker that skips one
	// relation, trusts a codec blob, or accepts a changed ledger must fail the
	// corresponding real SQLite fixture rather than a mock.
	for _, tc := range []struct {
		name     string
		populate bool
		mutate   func(t *testing.T, db *sql.DB)
	}{
		{
			name: "migration ledger checksum",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE schema_migrations SET checksum = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version = 1")
			},
		},
		{
			name: "migration ledger shape",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "ALTER TABLE schema_migrations ADD COLUMN altered TEXT")
			},
		},
		{
			name: "foreign key row",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "PRAGMA foreign_keys = OFF")
				mustExecMigrationTest(t, db, "INSERT INTO slot_heads(namespace, slot, revision_id, generation, activated_at_ns) VALUES ('foreign-key', 'primary', 'missing-revision', 1, 1)")
			},
		},
		{
			name: "missing cursor key",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "DELETE FROM cadrena_meta WHERE key = 'cursor_hmac_key'")
			},
		},
		{
			name: "malformed cursor key",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE cadrena_meta SET value = X'00' WHERE key = 'cursor_hmac_key'")
			},
		},
		{
			name:     "namespace head below persisted event sequence",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE namespace_heads SET event_sequence = 0 WHERE namespace = 'integrity-fixture'")
			},
		},
		{
			name:     "slot head with empty activation history",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "DELETE FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary'")
			},
		},
		{
			name:     "activation history missing current head record",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "INSERT INTO activation_history(namespace, slot, generation, revision_id, activated_at_ns) SELECT namespace, slot, 2, revision_id, activated_at_ns FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
				mustExecMigrationTest(t, db, "UPDATE slot_heads SET generation = 3 WHERE namespace = 'integrity-fixture' AND slot = 'primary'")
			},
		},
		{
			name:     "activation history interior generation gap",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "INSERT INTO activation_history(namespace, slot, generation, revision_id, activated_at_ns) SELECT namespace, slot, 3, revision_id, activated_at_ns FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
				mustExecMigrationTest(t, db, "UPDATE slot_heads SET generation = 3 WHERE namespace = 'integrity-fixture' AND slot = 'primary'")
			},
		},
		{
			name:     "activation head history timestamp mismatch",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE activation_history SET activated_at_ns = activated_at_ns + 1 WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
			},
		},
		{
			name:     "idempotency fingerprint decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE idempotency_records SET fingerprint = X'00' WHERE namespace = 'integrity-fixture' AND idempotency_key = 'fixture-tuple'")
			},
		},
		{
			name:     "idempotency response decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE idempotency_records SET response = X'00' WHERE namespace = 'integrity-fixture' AND idempotency_key = 'fixture-attribute'")
			},
		},
		{
			name:     "idempotency response missing successful generation",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "DELETE FROM idempotency_records WHERE namespace = 'integrity-fixture' AND idempotency_key = 'fixture-tuple'")
			},
		},
		{
			name:     "idempotency responses duplicate a successful generation",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "INSERT INTO idempotency_records(namespace, idempotency_key, fingerprint, response) SELECT namespace, 'fixture-duplicate', fingerprint, response FROM idempotency_records WHERE namespace = 'integrity-fixture' AND idempotency_key = 'fixture-tuple'")
			},
		},
		{
			name:     "idempotency responses skip a successful generation",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				response, err := policyengine.NewWriteDataResponse(3, false)
				if err != nil {
					t.Fatalf("NewWriteDataResponse() error = %v", err)
				}
				encoded, err := encodeIdempotencyResponse(response)
				if err != nil {
					t.Fatalf("encodeIdempotencyResponse() error = %v", err)
				}
				mustExecIntegrityTest(t, db, "UPDATE namespace_heads SET data_generation = 3 WHERE namespace = 'integrity-fixture'")
				mustExecIntegrityTest(t, db, "UPDATE idempotency_records SET response = ? WHERE namespace = 'integrity-fixture' AND idempotency_key = 'fixture-attribute'", encoded)
			},
		},
		{
			name:     "revision provenance decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE revisions SET provenance = X'00' WHERE namespace = 'integrity-fixture'")
			},
		},
		{
			name:     "tuple key decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE tuples SET tuple_key = X'00' WHERE namespace = 'integrity-fixture'")
			},
		},
		{
			name:     "attribute value decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE attributes SET value = X'00' WHERE namespace = 'integrity-fixture'")
			},
		},
		{
			name:     "event payload decode",
			populate: true,
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE state_events SET payload = X'00' WHERE namespace = 'integrity-fixture' AND sequence = 1")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := migratedIntegrityConfig(t)
			if tc.populate {
				populateIntegrityFixture(t, config)
			}
			mutateIntegrityDatabase(t, config, tc.mutate)

			if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorIntegrity {
				t.Fatalf("FullIntegrityCheck(%s) category = %v, want %v", tc.name, got, policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestIntegrityFullCheckAllowsContiguousPrunedActivationHistorySuffix(t *testing.T) {
	// Retention may prune an initial prefix, but retained rows must remain a
	// contiguous suffix ending at the durable slot head.
	config := migratedIntegrityConfig(t)
	populateIntegrityFixture(t, config)
	mutateIntegrityDatabase(t, config, func(t *testing.T, db *sql.DB) {
		mustExecMigrationTest(t, db, "INSERT INTO activation_history(namespace, slot, generation, revision_id, activated_at_ns) SELECT namespace, slot, 2, revision_id, activated_at_ns FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
		mustExecMigrationTest(t, db, "INSERT INTO activation_history(namespace, slot, generation, revision_id, activated_at_ns) SELECT namespace, slot, 3, revision_id, activated_at_ns FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
		mustExecMigrationTest(t, db, "DELETE FROM activation_history WHERE namespace = 'integrity-fixture' AND slot = 'primary' AND generation = 1")
		mustExecMigrationTest(t, db, "UPDATE slot_heads SET generation = 3 WHERE namespace = 'integrity-fixture' AND slot = 'primary'")
	})

	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("FullIntegrityCheck(contiguous pruned history) error = %v", err)
	}
}

func TestIntegrityFullCheckRejectsNewerSchemaAsFailedPrecondition(t *testing.T) {
	// This catches a maintenance command that treats a future ledger version as
	// ordinary corruption and might be tempted to operate on an unknown schema.
	config := migratedIntegrityConfig(t)
	mutateIntegrityDatabase(t, config, func(t *testing.T, db *sql.DB) {
		mustExecMigrationTest(t, db, "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (2, 'future', '0000000000000000000000000000000000000000000000000000000000000000', '1970-01-01T00:00:00Z')")
	})
	if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorFailedPrecondition {
		t.Fatalf("FullIntegrityCheck(newer schema) category = %v, want %v", got, policyengine.ErrorFailedPrecondition)
	}
}

func TestIntegrityOpenRunsOnlyBoundedRuntimeValidationAndFullIntegrityScansRows(t *testing.T) {
	// This catches a startup path that scans every tuple/attribute/event/replay
	// row. Open must admit this malformed unused tuple because only the offline
	// maintenance command is authorized to perform the complete value scan.
	config := migratedIntegrityConfig(t)
	mutateIntegrityDatabase(t, config, func(t *testing.T, db *sql.DB) {
		mustExecMigrationTest(t, db, "INSERT INTO namespace_heads(namespace) VALUES ('bounded-startup')")
		mustExecMigrationTest(t, db, "INSERT INTO tuples(namespace, tuple_key, subject_type, subject_id, subject_relation, relation, resource_type, resource_id) VALUES ('bounded-startup', X'00', 'user', 'subject', '', 'viewer', 'document', 'document')")
	})

	opened, err := Open(config)
	if err != nil {
		t.Fatalf("Open(bounded corrupt value) error = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close(bounded runtime store) error = %v", err)
	}
	if got := categoryOf(FullIntegrityCheck(context.Background(), config)); got != policyengine.ErrorIntegrity {
		t.Fatalf("FullIntegrityCheck(full value scan) category = %v, want %v", got, policyengine.ErrorIntegrity)
	}
}

func TestIntegrityOpenRejectsBoundedRuntimeCursorAndHeadViolations(t *testing.T) {
	// This catches a runtime opener that validates only schema DDL while using a
	// malformed signing key or an event head that is already below persisted
	// durable sequence state.
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, db *sql.DB)
	}{
		{
			name: "cursor key",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "UPDATE cadrena_meta SET value = X'00' WHERE key = 'cursor_hmac_key'")
			},
		},
		{
			name: "head watermark",
			mutate: func(t *testing.T, db *sql.DB) {
				mustExecMigrationTest(t, db, "INSERT INTO namespace_heads(namespace, event_sequence, expired_through) VALUES ('runtime-head', 0, 1)")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := migratedIntegrityConfig(t)
			mutateIntegrityDatabase(t, config, tc.mutate)
			if opened, err := Open(config); opened != nil || categoryOf(err) != policyengine.ErrorIntegrity {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("Open(%s) = %v, %v; want nil INTEGRITY", tc.name, opened, err)
			}
		})
	}
}

func TestIntegrityFullCheckPreservesCanceledAndDeadlineContexts(t *testing.T) {
	// This catches a checker that remaps caller cancellation into corruption or
	// tries to acquire an exclusive lock after the public context is unusable.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := categoryOf(FullIntegrityCheck(canceled, config)); got != policyengine.ErrorCanceled {
		t.Fatalf("FullIntegrityCheck(canceled) category = %v, want %v", got, policyengine.ErrorCanceled)
	}

	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if got := categoryOf(FullIntegrityCheck(expired, config)); got != policyengine.ErrorDeadlineExceeded {
		t.Fatalf("FullIntegrityCheck(expired) category = %v, want %v", got, policyengine.ErrorDeadlineExceeded)
	}
}

func migratedIntegrityConfig(t *testing.T) Config {
	t.Helper()
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	return config
}

func mutateIntegrityDatabase(t *testing.T, config Config, mutate func(t *testing.T, db *sql.DB)) {
	t.Helper()
	database := openRawSQLite(t, config.Path)
	mutate(t, database)
	if err := database.Close(); err != nil {
		t.Fatalf("close mutated database: %v", err)
	}
}

func mustExecIntegrityTest(t *testing.T, database *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(), statement, args...); err != nil {
		t.Fatalf("execute %q: %v", statement, err)
	}
}

func populateIntegrityFixture(t *testing.T, config Config) {
	t.Helper()
	adapter, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	revision := newSQLiteRevisionWrite(t, "integrity-fixture", "fixture.cdr", []byte("entity user {}"), time.Unix(10, 0).UTC())
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		_ = adapter.Close()
		t.Fatalf("PutRevision() error = %v", err)
	}
	activation, err := policyengine.NewActivateRequest("integrity-fixture", "primary", revision.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	if err != nil {
		_ = adapter.Close()
		t.Fatalf("NewActivateRequest() error = %v", err)
	}
	if _, err := adapter.Activate(context.Background(), activation); err != nil {
		_ = adapter.Close()
		t.Fatalf("Activate() error = %v", err)
	}
	tupleRequest, _ := newSQLiteTupleWriteRequest(t, "integrity-fixture", revision.Metadata().ID(), "fixture-tuple")
	if _, err := adapter.WriteData(context.Background(), tupleRequest); err != nil {
		_ = adapter.Close()
		t.Fatalf("WriteData(tuple) error = %v", err)
	}
	attributeRequest := newSQLiteDataRequest(t, "integrity-fixture", revision.Metadata().ID(), 1, "fixture-attribute", "classified")
	if _, err := adapter.WriteData(context.Background(), attributeRequest); err != nil {
		_ = adapter.Close()
		t.Fatalf("WriteData(attribute) error = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
