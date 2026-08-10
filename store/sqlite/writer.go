package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

// writeFunc executes inside one explicit BEGIN IMMEDIATE transaction. It must
// not commit or roll back the supplied connection itself.
type writeFunc func(context.Context, *sql.Conn) error

type writeRequest struct {
	ctx    context.Context
	fn     writeFunc
	result chan error
	once   *sync.Once
}

// writerQueueCapacity keeps admission bounded while preserving FIFO order for
// requests accepted behind the active transaction.
const writerQueueCapacity = 2

func (d *database) startWriter(ctx context.Context) error {
	conn, err := d.openWriterConnection(ctx)
	if err != nil {
		return err
	}
	d.writeRequests = make(chan writeRequest, writerQueueCapacity)
	d.writerDone = make(chan struct{})
	go d.writerLoop(conn)
	return nil
}

func (d *database) openWriterConnection(ctx context.Context) (*sql.Conn, error) {
	conn, err := d.writer.Conn(ctx)
	if err != nil {
		return nil, mapError(ctx, err)
	}
	if err := verifyConnectionPragmas(ctx, conn, d.config, false); err != nil {
		discardWriterConnection(conn)
		return nil, err
	}
	return conn, nil
}

func (d *database) write(ctx context.Context, fn writeFunc) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if fn == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	if d.writeRequests == nil {
		return sqliteError(policyengine.ErrorUnavailable)
	}

	request := writeRequest{ctx: ctx, fn: fn, result: make(chan error, 1), once: new(sync.Once)}
	select {
	case <-d.closed:
		return sqliteError(policyengine.ErrorUnavailable)
	case d.writeRequests <- request:
	case <-ctx.Done():
		return contextError(ctx)
	}

	select {
	case err := <-request.result:
		return err
	case <-d.closed:
		select {
		case err := <-request.result:
			return err
		default:
			return sqliteError(policyengine.ErrorUnavailable)
		}
	case <-ctx.Done():
		return contextError(ctx)
	}
}

func (d *database) writerLoop(conn *sql.Conn) {
	defer close(d.writerDone)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	for {
		if conn == nil {
			var err error
			conn, err = d.awaitWriterConnection()
			if err != nil {
				return
			}
		}

		select {
		case <-d.closed:
			return
		case request := <-d.writeRequests:
			if d.isClosed() {
				completeWrite(request, sqliteError(policyengine.ErrorUnavailable))
				return
			}
			discardConnection, result := d.executeWrite(conn, request)
			if discardConnection {
				discardWriterConnection(conn)
				conn = nil
			}
			completeWrite(request, result)
		}
	}
}

func (d *database) awaitWriterConnection() (*sql.Conn, error) {
	for {
		conn, err := d.openWriterConnection(context.Background())
		if err == nil {
			return conn, nil
		}
		select {
		case <-d.closed:
			return nil, sqliteError(policyengine.ErrorUnavailable)
		case <-time.After(lockPollInterval):
		}
	}
}

func (d *database) executeWrite(conn *sql.Conn, request writeRequest) (bool, error) {
	if err := contextError(request.ctx); err != nil {
		return false, err
	}
	if d.isClosed() {
		return false, sqliteError(policyengine.ErrorUnavailable)
	}
	if _, err := conn.ExecContext(request.ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, mapError(request.ctx, err)
	}

	callbackErr := request.fn(request.ctx, conn)
	if callbackErr != nil {
		if err := rollbackWriter(conn); err != nil {
			return true, mapError(request.ctx, callbackErr)
		}
		return false, mapError(request.ctx, callbackErr)
	}
	if err := contextError(request.ctx); err != nil {
		if rollbackErr := rollbackWriter(conn); rollbackErr != nil {
			return true, err
		}
		return false, err
	}
	if _, err := conn.ExecContext(request.ctx, "COMMIT"); err != nil {
		_ = rollbackWriter(conn)
		return true, mapError(request.ctx, err)
	}
	return false, nil
}

func discardWriterConnection(conn *sql.Conn) {
	if conn == nil {
		return
	}
	// Returning driver.ErrBadConn from Raw tells database/sql to close the
	// physical driver connection instead of returning it to the pool.
	_ = conn.Raw(func(any) error {
		return driver.ErrBadConn
	})
	_ = conn.Close()
}

func rollbackWriter(conn *sql.Conn) error {
	_, err := conn.ExecContext(context.Background(), "ROLLBACK")
	return err
}

func (d *database) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func completeWrite(request writeRequest, err error) {
	request.once.Do(func() {
		request.result <- err
	})
}
