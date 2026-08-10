package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
	"github.com/cadrena/policy-engine/store"
)

const (
	sqliteRecoverySubprocessEnvironment = "CADRENA_SQLITE_RECOVERY_SUBPROCESS"
	sqliteRecoverySubprocessMode        = "CADRENA_SQLITE_RECOVERY_MODE"
	sqliteRecoverySubprocessPath        = "CADRENA_SQLITE_RECOVERY_PATH"
)

// TestSubprocessSQLiteRecovery is a real child process entry point. It is
// inert in the normal test process and exits without running defers after its
// ready/release pipe handshake, intentionally modeling an abrupt process
// death rather than a clean Store.Close.
func TestSubprocessSQLiteRecovery(t *testing.T) {
	if os.Getenv(sqliteRecoverySubprocessEnvironment) != "1" {
		return
	}
	path := os.Getenv(sqliteRecoverySubprocessPath)
	ready := os.NewFile(uintptr(3), "recovery-ready")
	release := os.NewFile(uintptr(4), "recovery-release")
	if path == "" || ready == nil || release == nil {
		t.Fatal("invalid recovery subprocess handshake")
	}
	canonicalPath, err := canonicalDatabasePath(path)
	if err != nil {
		t.Fatalf("canonicalize recovery subprocess database path: %v", err)
	}
	defer func() { _ = ready.Close() }()
	defer func() { _ = release.Close() }()

	config := validConfig(canonicalPath)
	switch os.Getenv(sqliteRecoverySubprocessMode) {
	case "committed":
		if _, err := ApplyMigrations(context.Background(), config); err != nil {
			t.Fatalf("ApplyMigrations() error = %v", err)
		}
		adapter, err := Open(config)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if err := writeSubprocessRecoveryFixture(adapter); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if err := enableSubprocessWALPersistence(adapter); err != nil {
			t.Fatalf("preserve committed helper WAL: %v", err)
		}
		awaitSubprocessRelease(t, ready, release)
		// Deliberately no adapter.Close: the following abrupt exit must retain
		// the committed WAL for the parent recovery process.
		os.Exit(0)
	case "uncommitted":
		database, err := sql.Open(moderncsqlite.DriverName, "file:"+canonicalPath+"?mode=rw")
		if err != nil {
			t.Fatalf("sql.Open() error = %v", err)
		}
		conn, err := database.Conn(context.Background())
		if err != nil {
			t.Fatalf("database.Conn() error = %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatalf("BEGIN IMMEDIATE error = %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), "INSERT INTO namespace_heads(namespace, data_generation, event_sequence, expired_through) VALUES ('precommit-crash', 7, 3, 0)"); err != nil {
			t.Fatalf("stage namespace head: %v", err)
		}
		awaitSubprocessRelease(t, ready, release)
		// Deliberately no rollback/close: process death must expose no staged row.
		os.Exit(0)
	case "hold-raw-writer":
		// This intentionally bypasses Cadrena's advisory sidecar. The parent
		// checker must still receive SQLite BUSY while this external writer holds
		// a real WAL write transaction.
		database, err := sql.Open(moderncsqlite.DriverName, "file:"+canonicalPath+"?mode=rw")
		if err != nil {
			t.Fatalf("sql.Open() error = %v", err)
		}
		conn, err := database.Conn(context.Background())
		if err != nil {
			t.Fatalf("database.Conn() error = %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatalf("BEGIN IMMEDIATE error = %v", err)
		}
		awaitSubprocessRelease(t, ready, release)
		// Abrupt exit releases an external SQLite writer without exercising any
		// Cadrena lock or normal database close path.
		os.Exit(0)
	case "hold-runtime":
		adapter, err := Open(config)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		_ = adapter
		awaitSubprocessRelease(t, ready, release)
		// Abrupt exit verifies kernel advisory-lock cleanup, not close behavior.
		os.Exit(0)
	case "hold-maintenance":
		lock, err := newAdvisoryLock(canonicalPath)
		if err != nil {
			t.Fatalf("newAdvisoryLock() error = %v", err)
		}
		if err := lock.LockExclusive(context.Background()); err != nil {
			t.Fatalf("LockExclusive() error = %v", err)
		}
		_ = lock
		awaitSubprocessRelease(t, ready, release)
		// This models a second offline maintenance process; os.Exit releases the
		// kernel lock without exercising the normal close path.
		os.Exit(0)
	default:
		t.Fatalf("unknown recovery subprocess mode %q", os.Getenv(sqliteRecoverySubprocessMode))
	}
}

// enableSubprocessWALPersistence keeps the deliberately hot WAL sidecar after
// the child uses os.Exit. It is test-fixture setup only: the parent must prove
// that FullIntegrityCheck does not alter those bytes before Open recovers them.
func enableSubprocessWALPersistence(adapter *Store) error {
	if adapter == nil || adapter.db == nil {
		return fmt.Errorf("nil store")
	}
	return adapter.db.write(context.Background(), func(_ context.Context, conn *sql.Conn) error {
		if conn == nil {
			return fmt.Errorf("nil writer connection")
		}
		return conn.Raw(func(driverConn any) error {
			controller, ok := driverConn.(moderncsqlite.FileControl)
			if !ok {
				return fmt.Errorf("writer connection does not expose FileControl")
			}
			mode, err := controller.FileControlPersistWAL("main", 1)
			if err != nil {
				return fmt.Errorf("persist WAL file control: %w", err)
			}
			if mode != 1 {
				return fmt.Errorf("persist WAL file control mode = %d, want 1", mode)
			}
			return nil
		})
	})
}

func awaitSubprocessRelease(t *testing.T, ready, release *os.File) {
	t.Helper()
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatalf("write ready signal: %v", err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(release, signal[:]); err != nil && err != io.EOF {
		t.Fatalf("read release signal: %v", err)
	}
}

type sqliteRecoverySubprocess struct {
	cmd     *exec.Cmd
	ready   *os.File
	release *os.File
	closed  bool
}

func startSQLiteRecoverySubprocess(t *testing.T, mode, path string) *sqliteRecoverySubprocess {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatalf("subprocess path = %q, want absolute", path)
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create ready pipe: %v", err)
	}
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		_ = readyReader.Close()
		_ = readyWriter.Close()
		t.Fatalf("create release pipe: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSubprocessSQLiteRecovery$")
	cmd.ExtraFiles = []*os.File{readyWriter, releaseReader}
	cmd.Env = append(os.Environ(),
		sqliteRecoverySubprocessEnvironment+"=1",
		sqliteRecoverySubprocessMode+"="+mode,
		sqliteRecoverySubprocessPath+"="+path,
	)
	if err := cmd.Start(); err != nil {
		_ = readyReader.Close()
		_ = readyWriter.Close()
		_ = releaseReader.Close()
		_ = releaseWriter.Close()
		t.Fatalf("start recovery subprocess: %v", err)
	}
	if err := readyWriter.Close(); err != nil {
		t.Fatalf("close parent ready writer: %v", err)
	}
	if err := releaseReader.Close(); err != nil {
		t.Fatalf("close parent release reader: %v", err)
	}
	result := &sqliteRecoverySubprocess{cmd: cmd, ready: readyReader, release: releaseWriter}
	t.Cleanup(func() {
		if !result.closed {
			_ = result.release.Close()
			_ = result.ready.Close()
			_ = result.cmd.Wait()
		}
	})
	return result
}

func (p *sqliteRecoverySubprocess) awaitReady(t *testing.T) {
	t.Helper()
	var signal [1]byte
	if _, err := io.ReadFull(p.ready, signal[:]); err != nil {
		t.Fatalf("wait for recovery helper ready: %v", err)
	}
}

func (p *sqliteRecoverySubprocess) releaseAndWait(t *testing.T) {
	t.Helper()
	if p == nil || p.closed {
		t.Fatal("recovery helper released twice")
	}
	if _, err := p.release.Write([]byte{1}); err != nil {
		t.Fatalf("release recovery helper: %v", err)
	}
	if err := p.release.Close(); err != nil {
		t.Fatalf("close recovery release pipe: %v", err)
	}
	if err := p.ready.Close(); err != nil {
		t.Fatalf("close recovery ready pipe: %v", err)
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("recovery helper exit: %v", err)
	}
	p.closed = true
}

// expectedSubprocessRecoveryRevision derives the assertion fixture separately
// from the child writer below, so recovery checks cannot pass by sharing the
// writer's construction path.
func expectedSubprocessRecoveryRevision() (store.RevisionWrite, error) {
	artifact, err := dsl.CompileArtifact("recovery.cdr", []byte("entity user {}"))
	if err != nil {
		return store.RevisionWrite{}, err
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		return store.RevisionWrite{}, err
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		return store.RevisionWrite{}, err
	}
	metadata, err := policyengine.NewRevisionMetadata("crash-recovery", id, time.Unix(10, 0).UTC())
	if err != nil {
		return store.RevisionWrite{}, err
	}
	publish, err := policyengine.NewPublishRequest("crash-recovery", "recovery.cdr", []byte("entity user {}"))
	if err != nil {
		return store.RevisionWrite{}, err
	}
	provenance, err := store.NewRevisionProvenance(publish)
	if err != nil {
		return store.RevisionWrite{}, err
	}
	return store.NewRevisionWriteWithProvenance(metadata, encoded, provenance)
}

func expectedSubprocessRecoveryDataRequest(revisionID string) (policyengine.WriteDataRequest, policyengine.TupleKey, error) {
	tupleValue := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "document"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: "subject"},
	}
	tuple, err := policyengine.NewRelationshipTuple(tupleValue, nil)
	if err != nil {
		return policyengine.WriteDataRequest{}, policyengine.TupleKey{}, err
	}
	key, err := policyengine.NewTupleKey(tupleValue)
	if err != nil {
		return policyengine.WriteDataRequest{}, policyengine.TupleKey{}, err
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "crash-recovery", ValidationRevisionID: revisionID, ExpectedGeneration: 0, IdempotencyKey: "crash-data",
		TupleWrites: []policyengine.RelationshipTuple{tuple},
	})
	if err != nil {
		return policyengine.WriteDataRequest{}, policyengine.TupleKey{}, err
	}
	return request, key, nil
}

func writeSubprocessRecoveryFixture(adapter *Store) error {
	if adapter == nil {
		return fmt.Errorf("nil store")
	}
	// Keep the child write construction independent from the expected fixture
	// above; this makes reopen and crash recovery assertions true oracle checks.
	artifact, err := dsl.CompileArtifact("recovery.cdr", []byte("entity user {}"))
	if err != nil {
		return err
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		return err
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		return err
	}
	metadata, err := policyengine.NewRevisionMetadata("crash-recovery", id, time.Unix(10, 0).UTC())
	if err != nil {
		return err
	}
	publish, err := policyengine.NewPublishRequest("crash-recovery", "recovery.cdr", []byte("entity user {}"))
	if err != nil {
		return err
	}
	provenance, err := store.NewRevisionProvenance(publish)
	if err != nil {
		return err
	}
	revision, err := store.NewRevisionWriteWithProvenance(metadata, encoded, provenance)
	if err != nil {
		return err
	}
	if _, err := adapter.PutRevision(context.Background(), revision); err != nil {
		return err
	}
	activation, err := policyengine.NewActivateRequest("crash-recovery", "primary", revision.Metadata().ID(), policyengine.NewUnsetSlotExpectation())
	if err != nil {
		return err
	}
	if _, err := adapter.Activate(context.Background(), activation); err != nil {
		return err
	}
	tupleValue := dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "document"}, Relation: "viewer",
		Subject: dsl.SubjectRef{Type: "user", ID: "subject"},
	}
	tuple, err := policyengine.NewRelationshipTuple(tupleValue, nil)
	if err != nil {
		return err
	}
	request, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace: "crash-recovery", ValidationRevisionID: revision.Metadata().ID(), ExpectedGeneration: 0, IdempotencyKey: "crash-data",
		TupleWrites: []policyengine.RelationshipTuple{tuple},
	})
	if err != nil {
		return err
	}
	_, err = adapter.WriteData(context.Background(), request)
	return err
}
