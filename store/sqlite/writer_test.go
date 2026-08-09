package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "modernc.org/sqlite"
)

func TestWriterCommitsAcceptedWritesInOrder(t *testing.T) {
	// This catches concurrent or LIFO writer execution: once the first accepted
	// request has begun, the second must commit after it, not interleave with it.
	database := newWriterDatabase(t)
	defer database.Close()
	createWriterTable(t, database)

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
			if _, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "first"); err != nil {
				return err
			}
			close(firstStarted)
			<-releaseFirst
			return nil
		})
	}()
	<-firstStarted

	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondEntered)
		secondDone <- database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "second")
			return err
		})
	}()
	<-secondEntered
	select {
	case err := <-secondDone:
		t.Fatalf("second write completed before first released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first write error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second write error = %v", err)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"first", "second"}) {
		t.Fatalf("committed labels = %q, want %q", got, []string{"first", "second"})
	}
}

func TestWriterRejectsExpiredRequestBeforeAdmission(t *testing.T) {
	// This catches a queue that runs a request after its context expires while a
	// prior transaction holds the one serialized writer lane.
	database := newWriterDatabase(t)
	defer database.Close()
	createWriterTable(t, database)

	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- database.write(context.Background(), func(context.Context, *sql.Conn) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	ran := false
	err := database.write(ctx, func(context.Context, *sql.Conn) error {
		ran = true
		return nil
	})
	if categoryOf(err) != policyengine.ErrorDeadlineExceeded {
		t.Fatalf("expired write category = %v, want %v", categoryOf(err), policyengine.ErrorDeadlineExceeded)
	}
	if ran {
		t.Fatal("expired write callback ran")
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("blocking write error = %v", err)
	}
}

func TestWriterUsesBeginImmediateBeforeInvokingCallback(t *testing.T) {
	// This catches a deferred write transaction: contention must fail before the
	// callback executes, leaving it no opportunity to make a partial mutation.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	config.BusyTimeout = 25 * time.Millisecond
	database, err := openDatabase(context.Background(), config)
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	defer database.Close()
	createWriterTable(t, database)

	connector, err := moderncsqlite.NewConnector(databaseDSN(config, false))
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	other := sql.OpenDB(connector)
	defer other.Close()
	otherConn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatalf("other.Conn() error = %v", err)
	}
	defer otherConn.Close()
	if _, err := otherConn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("other BEGIN IMMEDIATE error = %v", err)
	}
	defer otherConn.ExecContext(context.Background(), "ROLLBACK")

	called := false
	err = database.write(context.Background(), func(context.Context, *sql.Conn) error {
		called = true
		return nil
	})
	if categoryOf(err) != policyengine.ErrorUnavailable {
		t.Fatalf("contended write category = %v, want %v", categoryOf(err), policyengine.ErrorUnavailable)
	}
	if called {
		t.Fatal("callback ran despite BEGIN IMMEDIATE contention")
	}

	if _, err := otherConn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("other ROLLBACK error = %v", err)
	}
	if err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "reused")
		return err
	}); err != nil {
		t.Fatalf("write after contention error = %v", err)
	}
}

func TestWriterRollsBackCallbackFailureAndReusesLane(t *testing.T) {
	// This catches a callback error path that leaks a transaction or returns the
	// callback's untrusted error text instead of a sanitized internal failure.
	database := newWriterDatabase(t)
	defer database.Close()
	createWriterTable(t, database)

	callbackFailure := errors.New("callback failure must not escape")
	err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "rolled-back"); err != nil {
			return err
		}
		return callbackFailure
	})
	if categoryOf(err) != policyengine.ErrorInternal {
		t.Fatalf("callback failure category = %v, want %v", categoryOf(err), policyengine.ErrorInternal)
	}
	if err.Error() != policyengine.ErrorInternal.String() {
		t.Fatalf("callback failure text = %q, want sanitized category", err)
	}
	if got := readWriterLabels(t, database); len(got) != 0 {
		t.Fatalf("labels after callback failure = %q, want none", got)
	}

	if err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "reused")
		return err
	}); err != nil {
		t.Fatalf("write after callback rollback error = %v", err)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"reused"}) {
		t.Fatalf("labels after writer reuse = %q, want %q", got, []string{"reused"})
	}
}

func TestWriterCleansUpFailedCommitAndReusesLane(t *testing.T) {
	// This catches a COMMIT failure that leaves an open transaction or poisons
	// the writer connection, preventing a following request from succeeding.
	database := newWriterDatabase(t)
	defer database.Close()
	createWriterTable(t, database)

	ctx, cancel := context.WithCancel(context.Background())
	err := database.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "uncommitted"); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if categoryOf(err) != policyengine.ErrorCanceled {
		t.Fatalf("commit failure category = %v, want %v", categoryOf(err), policyengine.ErrorCanceled)
	}
	if got := readWriterLabels(t, database); len(got) != 0 {
		t.Fatalf("labels after failed commit = %q, want none", got)
	}

	if err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "committed")
		return err
	}); err != nil {
		t.Fatalf("write after failed commit error = %v", err)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"committed"}) {
		t.Fatalf("labels after commit recovery = %q, want %q", got, []string{"committed"})
	}
}

func newWriterDatabase(t *testing.T) *database {
	t.Helper()
	database, err := openDatabase(context.Background(), validConfig(filepath.Join(t.TempDir(), "policy.db")))
	if err != nil {
		t.Fatalf("openDatabase() error = %v", err)
	}
	return database
}

func createWriterTable(t *testing.T, database *database) {
	t.Helper()
	if err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "CREATE TABLE writer_values (sequence INTEGER PRIMARY KEY, label TEXT NOT NULL)")
		return err
	}); err != nil {
		t.Fatalf("create table error = %v", err)
	}
}

func readWriterLabels(t *testing.T, database *database) []string {
	t.Helper()
	rows, err := database.readers.QueryContext(context.Background(), "SELECT label FROM writer_values ORDER BY sequence")
	if err != nil {
		t.Fatalf("query labels error = %v", err)
	}
	defer rows.Close()

	var labels []string
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatalf("scan label error = %v", err)
		}
		labels = append(labels, label)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate labels error = %v", err)
	}
	return labels
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
