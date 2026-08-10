package sqlite

import (
	"context"
	"errors"
	"io/fs"
	"syscall"

	policyengine "github.com/cadrena/policy-engine"
	moderncsqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func sqliteError(category policyengine.ErrorCategory) error {
	err, errNew := policyengine.NewEngineError(category)
	if errNew == nil && err != nil {
		return err
	}
	fallback, _ := policyengine.NewEngineError(policyengine.ErrorInternal)
	return fallback
}

func mapError(ctx context.Context, err error) error {
	if ctx == nil {
		return sqliteError(policyengine.ErrorInvalidArgument)
	}
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return sqliteError(policyengine.ErrorDeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) {
		return sqliteError(policyengine.ErrorCanceled)
	}
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EPERM) {
		return sqliteError(policyengine.ErrorPermissionDenied)
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return sqliteError(policyengine.ErrorResourceExhausted)
	}
	if errors.Is(err, syscall.EROFS) {
		return sqliteError(policyengine.ErrorPermissionDenied)
	}

	var sqliteErr *moderncsqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return sqliteError(policyengine.ErrorUnavailable)
		case sqlite3.SQLITE_FULL:
			return sqliteError(policyengine.ErrorResourceExhausted)
		case sqlite3.SQLITE_READONLY, sqlite3.SQLITE_PERM:
			return sqliteError(policyengine.ErrorPermissionDenied)
		case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
			return sqliteError(policyengine.ErrorIntegrity)
		}
	}
	return sqliteError(policyengine.ErrorInternal)
}
