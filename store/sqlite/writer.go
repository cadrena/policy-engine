package sqlite

import (
	"context"
	"database/sql"
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

func (d *database) startWriter(ctx context.Context) error {
	conn, err := d.openWriterConnection(ctx)
	if err != nil {
		return err
	}
	d.writeRequests = make(chan writeRequest)
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
		_ = conn.Close()
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
			result, discardConnection := d.executeWrite(conn, request)
			if discardConnection {
				_ = conn.Close()
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

func (d *database) executeWrite(conn *sql.Conn, request writeRequest) (error, bool) {
	if err := contextError(request.ctx); err != nil {
		return err, false
	}
	if d.isClosed() {
		return sqliteError(policyengine.ErrorUnavailable), false
	}
	if _, err := conn.ExecContext(request.ctx, "BEGIN IMMEDIATE"); err != nil {
		return mapError(request.ctx, err), false
	}

	callbackErr := request.fn(request.ctx, conn)
	if callbackErr != nil {
		if err := rollbackWriter(conn); err != nil {
			return mapError(request.ctx, callbackErr), true
		}
		return mapError(request.ctx, callbackErr), false
	}
	if err := contextError(request.ctx); err != nil {
		if rollbackErr := rollbackWriter(conn); rollbackErr != nil {
			return err, true
		}
		return err, false
	}
	if _, err := conn.ExecContext(request.ctx, "COMMIT"); err != nil {
		_ = rollbackWriter(conn)
		return mapError(request.ctx, err), true
	}
	return nil, false
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
