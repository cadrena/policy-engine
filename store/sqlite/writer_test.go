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
	"time"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "github.com/cadrena/policy-engine/internal/sqlitenofollow"
)

func TestWriterCommitsAcceptedWritesInOrder(t *testing.T) {
	// This catches concurrent or LIFO writer execution: two requests accepted
	// while the first transaction is blocked must commit in acceptance order.
	database := newWriterDatabase(t)
	defer func() { _ = database.Close() }()
	createWriterTable(t, database)

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}()
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

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "second")
			return err
		})
	}()
	<-secondStarted
	waitForQueuedWrites(t, database, 1)

	thirdStarted := make(chan struct{})
	thirdDone := make(chan error, 1)
	go func() {
		close(thirdStarted)
		thirdDone <- database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "third")
			return err
		})
	}()
	<-thirdStarted
	waitForQueuedWrites(t, database, 2)

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first write error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second write error = %v", err)
	}
	if err := <-thirdDone; err != nil {
		t.Fatalf("third write error = %v", err)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"first", "second", "third"}) {
		t.Fatalf("committed labels = %q, want %q", got, []string{"first", "second", "third"})
	}
}

func TestWriterRejectsExpiredRequestBeforeAdmission(t *testing.T) {
	// This catches a queue that runs a request after its context expires while a
	// prior transaction holds the one serialized writer lane.
	database := newWriterDatabase(t)
	defer func() { _ = database.Close() }()
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
	defer func() { _ = database.Close() }()
	createWriterTable(t, database)

	connector, err := moderncsqlite.NewConnector(databaseDSN(database.config, false))
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	other := sql.OpenDB(connector)
	defer func() { _ = other.Close() }()
	otherConn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatalf("other.Conn() error = %v", err)
	}
	defer func() { _ = otherConn.Close() }()
	if _, err := otherConn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("other BEGIN IMMEDIATE error = %v", err)
	}
	defer func() { _, _ = otherConn.ExecContext(context.Background(), "ROLLBACK") }()

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
	defer func() { _ = database.Close() }()
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

func TestWriterRollsBackCanceledCallbackAndReusesLane(t *testing.T) {
	// This catches a callback cancellation that leaves an open transaction or
	// prevents a following request from succeeding.
	database := newWriterDatabase(t)
	defer func() { _ = database.Close() }()
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
		t.Fatalf("canceled callback category = %v, want %v", categoryOf(err), policyengine.ErrorCanceled)
	}
	if got := readWriterLabels(t, database); len(got) != 0 {
		t.Fatalf("labels after canceled callback = %q, want none", got)
	}

	if err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "committed")
		return err
	}); err != nil {
		t.Fatalf("write after canceled callback error = %v", err)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"committed"}) {
		t.Fatalf("labels after cancellation recovery = %q, want %q", got, []string{"committed"})
	}
}

func TestWriterReplacesPhysicalConnectionAfterCommitFailure(t *testing.T) {
	// This catches a failed COMMIT path that merely returns a logical sql.Conn to
	// its pool instead of evicting the physical driver connection.
	faults := newWriterFaults()
	database := newFaultWriterDatabase(t, faults)
	defer func() { _ = database.Close() }()
	createWriterTable(t, database)

	faults.failNext("COMMIT", errors.New("commit fault"))
	failedID := 0
	err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		var err error
		failedID, err = writerConnectionID(conn)
		if err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "uncommitted")
		return err
	})
	if categoryOf(err) != policyengine.ErrorInternal {
		t.Fatalf("commit failure category = %v, want %v", categoryOf(err), policyengine.ErrorInternal)
	}
	if got := faults.attempts("COMMIT"); got != 1 {
		t.Fatalf("COMMIT fault attempts = %d, want 1", got)
	}

	replacementID, replacementPragmaErr := writeVerifiedReplacement(t, database)
	if replacementPragmaErr != nil {
		t.Fatal(replacementPragmaErr)
	}
	if replacementID == failedID {
		t.Fatalf("writer physical connection after failed COMMIT = %d, want a replacement for %d", replacementID, failedID)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"reused"}) {
		t.Fatalf("labels after commit recovery = %q, want %q", got, []string{"reused"})
	}
}

func TestWriterReplacesPhysicalConnectionAfterRollbackFailure(t *testing.T) {
	// This catches a failed ROLLBACK path that leaves an active transaction on a
	// pooled physical connection, poisoning the next serialized write.
	faults := newWriterFaults()
	database := newFaultWriterDatabase(t, faults)
	defer func() { _ = database.Close() }()
	createWriterTable(t, database)

	faults.failNext("ROLLBACK", errors.New("rollback fault"))
	callbackFailure := errors.New("callback failure")
	failedID := 0
	err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		var err error
		failedID, err = writerConnectionID(conn)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "rolled-back"); err != nil {
			return err
		}
		return callbackFailure
	})
	if categoryOf(err) != policyengine.ErrorInternal {
		t.Fatalf("rollback failure category = %v, want %v", categoryOf(err), policyengine.ErrorInternal)
	}
	if got := faults.attempts("ROLLBACK"); got != 1 {
		t.Fatalf("ROLLBACK fault attempts = %d, want 1", got)
	}

	replacementID, replacementPragmaErr := writeVerifiedReplacement(t, database)
	if replacementPragmaErr != nil {
		t.Fatal(replacementPragmaErr)
	}
	if replacementID == failedID {
		t.Fatalf("writer physical connection after failed ROLLBACK = %d, want a replacement for %d", replacementID, failedID)
	}
	if got := readWriterLabels(t, database); !equalStrings(got, []string{"reused"}) {
		t.Fatalf("labels after rollback recovery = %q, want %q", got, []string{"reused"})
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

func newFaultWriterDatabase(t *testing.T, faults *writerFaults) *database {
	t.Helper()
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	canonicalConfig, err := canonicalizeDatabaseConfig(config)
	if err != nil {
		t.Fatalf("canonicalize fault writer database path: %v", err)
	}
	writerDSN := databaseDSN(canonicalConfig, false)
	database, err := openDatabaseWithConnectorFactory(context.Background(), config, func(dsn string) (driver.Connector, error) {
		connector, err := moderncsqlite.NewConnector(dsn)
		if err != nil {
			return nil, err
		}
		if dsn != writerDSN {
			return connector, nil
		}
		return &faultConnector{Connector: connector, faults: faults}, nil
	})
	if err != nil {
		t.Fatalf("openDatabaseWithConnectorFactory() error = %v", err)
	}
	return database
}

func writeVerifiedReplacement(t *testing.T, database *database) (int, error) {
	t.Helper()
	replacementID := 0
	var pragmaErr error
	err := database.write(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		var err error
		replacementID, err = writerConnectionID(conn)
		if err != nil {
			return err
		}
		pragmaErr = connectionPragmaError(ctx, conn, database.config.BusyTimeout.Milliseconds(), 0)
		if pragmaErr != nil {
			return pragmaErr
		}
		_, err = conn.ExecContext(ctx, "INSERT INTO writer_values(label) VALUES (?)", "reused")
		return err
	})
	if err != nil {
		t.Fatalf("write on replacement connection error = %v", err)
	}
	return replacementID, pragmaErr
}

func writerConnectionID(conn *sql.Conn) (int, error) {
	var id int
	err := conn.Raw(func(raw any) error {
		faultConn, ok := raw.(*faultConn)
		if !ok {
			return errors.New("writer connection does not expose the fault connector")
		}
		id = faultConn.id
		return nil
	})
	return id, err
}

type writerFaults struct {
	mu               sync.Mutex
	failures         map[string][]error
	faultAttempts    map[string]int
	nextConnectionID int
}

func newWriterFaults() *writerFaults {
	return &writerFaults{
		failures:      make(map[string][]error),
		faultAttempts: make(map[string]int),
	}
}

func (f *writerFaults) failNext(statement string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	statement = normalizedStatement(statement)
	f.failures[statement] = append(f.failures[statement], err)
}

func (f *writerFaults) take(statement string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	statement = normalizedStatement(statement)
	failures := f.failures[statement]
	if len(failures) == 0 {
		return nil
	}
	f.faultAttempts[statement]++
	f.failures[statement] = failures[1:]
	return failures[0]
}

func (f *writerFaults) attempts(statement string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.faultAttempts[normalizedStatement(statement)]
}

func (f *writerFaults) newConnectionID() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextConnectionID++
	return f.nextConnectionID
}

type faultConnector struct {
	driver.Connector
	faults *writerFaults
}

func (c *faultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, faults: c.faults, id: c.faults.newConnectionID()}, nil
}

type faultConn struct {
	driver.Conn
	faults *writerFaults
	id     int
}

func (c *faultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.faults.take(query); err != nil {
		return nil, err
	}
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *faultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

func normalizedStatement(statement string) string {
	return strings.ToUpper(strings.TrimSpace(statement))
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

func waitForQueuedWrites(t *testing.T, database *database, want int) {
	t.Helper()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := len(database.writeRequests); got >= want {
			return
		}
		select {
		case <-tick.C:
		case <-timeout.C:
			t.Fatalf("writer queue length = %d, want at least %d", len(database.writeRequests), want)
		}
	}
}

func readWriterLabels(t *testing.T, database *database) []string {
	t.Helper()
	rows, err := database.readers.QueryContext(context.Background(), "SELECT label FROM writer_values ORDER BY sequence")
	if err != nil {
		t.Fatalf("query labels error = %v", err)
	}
	defer func() { _ = rows.Close() }()

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
