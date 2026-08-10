package sqlite

import (
	"context"
	"database/sql"
	"sync"

	policyengine "github.com/cadrena/policy-engine"
)

func (d *database) acquireReader(ctx context.Context) (func(), error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	select {
	case <-d.closed:
		return nil, sqliteError(policyengine.ErrorUnavailable)
	default:
	}

	select {
	case d.readerAdmission <- struct{}{}:
		select {
		case <-d.closed:
			<-d.readerAdmission
			return nil, sqliteError(policyengine.ErrorUnavailable)
		default:
		}
	case <-d.closed:
		return nil, sqliteError(policyengine.ErrorUnavailable)
	case <-ctx.Done():
		return nil, contextError(ctx)
	}

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			<-d.readerAdmission
		})
	}, nil
}

// acquireReaderConnection holds one bounded reader admission and returns one
// physical connection. Callers that need a pinned SQLite snapshot must retain
// the connection until their transaction closes.
func (d *database) acquireReaderConnection(ctx context.Context) (*sql.Conn, func() error, error) {
	releaseAdmission, err := d.acquireReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	if d.readers == nil {
		releaseAdmission()
		return nil, nil, sqliteError(policyengine.ErrorUnavailable)
	}
	conn, err := d.readers.Conn(ctx)
	if err != nil {
		releaseAdmission()
		return nil, nil, mapError(ctx, err)
	}
	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() {
			releaseErr = conn.Close()
			releaseAdmission()
		})
		return releaseErr
	}
	return conn, release, nil
}
