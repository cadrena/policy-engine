package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func TestCursorKeyLoadPreservesQueryErrorCategories(t *testing.T) {
	// This catches a loader that checks its zero-value key length before a
	// failed key query, incorrectly relabeling cancellation, deadline, and
	// operational errors as durable-state corruption.
	for _, tc := range []struct {
		name string
		err  error
		want policyengine.ErrorCategory
	}{
		{name: "canceled", err: context.Canceled, want: policyengine.ErrorCanceled},
		{name: "deadline", err: context.DeadlineExceeded, want: policyengine.ErrorDeadlineExceeded},
		{name: "operational", err: errors.New("cursor key query failed"), want: policyengine.ErrorInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := newCursorKeyQueryErrorDatabase(t, tc.err)
			_, err := loadCursorKey(context.Background(), database)
			if got := categoryOf(err); got != tc.want {
				t.Fatalf("loadCursorKey() category = %v, want %v", got, tc.want)
			}
		})
	}
}

func newCursorKeyQueryErrorDatabase(t testing.TB, queryErr error) *database {
	t.Helper()
	readers := sql.OpenDB(cursorKeyQueryErrorConnector{queryErr: queryErr})
	t.Cleanup(func() { _ = readers.Close() })
	return &database{
		readers:         readers,
		readerAdmission: make(chan struct{}, 1),
		closed:          make(chan struct{}),
	}
}

type cursorKeyQueryErrorConnector struct{ queryErr error }

func (c cursorKeyQueryErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return cursorKeyQueryErrorConn(c), nil
}

func (c cursorKeyQueryErrorConnector) Driver() driver.Driver {
	return cursorKeyQueryErrorDriver(c)
}

type cursorKeyQueryErrorDriver struct{ queryErr error }

func (d cursorKeyQueryErrorDriver) Open(string) (driver.Conn, error) {
	return cursorKeyQueryErrorConn(d), nil
}

type cursorKeyQueryErrorConn struct{ queryErr error }

func (cursorKeyQueryErrorConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (cursorKeyQueryErrorConn) Close() error                        { return nil }
func (cursorKeyQueryErrorConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c cursorKeyQueryErrorConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, c.queryErr
}
