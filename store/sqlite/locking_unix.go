//go:build darwin || linux

package sqlite

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

type unixAdvisoryLock struct {
	mu   sync.Mutex
	file *os.File
}

func newAdvisoryLock(databasePath string) (advisoryLock, error) {
	file, err := openOwnerOnlyRegularFile(lockFilePath(databasePath))
	if err != nil {
		return nil, mapError(context.Background(), err)
	}
	return &unixAdvisoryLock{file: file}, nil
}

func (l *unixAdvisoryLock) LockShared(ctx context.Context) error {
	return l.lock(ctx, syscall.LOCK_SH)
}

func (l *unixAdvisoryLock) LockExclusive(ctx context.Context) error {
	return l.lock(ctx, syscall.LOCK_EX)
}

func (l *unixAdvisoryLock) lock(ctx context.Context, mode int) error {
	if err := contextError(ctx); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}

	timer := time.NewTimer(lockPollInterval)
	defer timer.Stop()
	for {
		err := syscall.Flock(int(l.file.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return mapError(ctx, err)
		}

		select {
		case <-ctx.Done():
			return contextError(ctx)
		case <-timer.C:
			timer.Reset(lockPollInterval)
		}
	}
}

func (l *unixAdvisoryLock) Unlock() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		return mapError(context.Background(), err)
	}
	return nil
}

func (l *unixAdvisoryLock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}

	file := l.file
	l.file = nil
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		_ = file.Close()
		return mapError(context.Background(), err)
	}
	if err := file.Close(); err != nil {
		return mapError(context.Background(), err)
	}
	return nil
}
