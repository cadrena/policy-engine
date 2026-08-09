package sqlite

import (
	"context"
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
