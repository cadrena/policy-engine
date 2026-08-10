//go:build darwin || linux

package sqlite

import (
	"errors"
	"os"

	policyengine "github.com/cadrena/policy-engine"
	"golang.org/x/sys/unix"
)

// openOwnerOnlyRegularFile opens the final path component without following a
// symlink, then validates the opened descriptor before changing its mode. The
// descriptor check is intentionally authoritative: a path-only precheck would
// leave a time-of-check/time-of-use gap for special files or symlink swaps.
func openOwnerOnlyRegularFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) {
			return nil, sqliteError(policyengine.ErrorFailedPrecondition)
		}
		return nil, err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, sqliteError(policyengine.ErrorInternal)
	}
	return file, nil
}
