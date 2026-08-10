//go:build linux

package sqlite

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func classifyFilesystem(databasePath string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(filepath.Dir(databasePath), &stat); err != nil {
		return err
	}
	if !linuxFilesystemTypeSupported(stat.Type) {
		return errUnsupportedFilesystem
	}
	return nil
}

func linuxFilesystemTypeSupported(filesystemType int64) bool {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}
