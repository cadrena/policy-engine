package sqlite

import (
	"context"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

const lockPollInterval = 10 * time.Millisecond

type advisoryLock interface {
	LockShared(context.Context) error
	LockExclusive(context.Context) error
	Unlock() error
	Close() error
}

func lockFilePath(databasePath string) string { return databasePath + ".lock" }

func unsupportedAdvisoryLock(_ string) (advisoryLock, error) {
	return nil, sqliteError(policyengine.ErrorFailedPrecondition)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return sqliteError(policyengine.ErrorDeadlineExceeded)
		}
		return sqliteError(policyengine.ErrorCanceled)
	}
	return nil
}
