//go:build darwin

package sqlite

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func classifyFilesystem(databasePath string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(filepath.Dir(databasePath), &stat); err != nil {
		return err
	}
	if !darwinFilesystemTypeSupported(statfsName(stat.Fstypename[:])) {
		return errUnsupportedFilesystem
	}
	return nil
}

func darwinFilesystemTypeSupported(name string) bool {
	switch strings.ToLower(name) {
	case "apfs", "hfs":
		return true
	default:
		return false
	}
}

func statfsName(value []byte) string {
	bytes := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		bytes = append(bytes, byte(character))
	}
	return string(bytes)
}
