package sqlite

import (
	"errors"
	"os"
	"path/filepath"

	policyengine "github.com/cadrena/policy-engine"
)

// canonicalizeDatabaseConfig resolves only the existing parent directory and
// retains the caller's final database name. SQLite's SQLITE_OPEN_NOFOLLOW
// rejects every symlink it sees while canonicalizing a pathname, including
// benign system ancestors such as Darwin's /var -> /private/var. Resolving the
// parent here gives SQLite a stable physical parent path while preserving its
// authoritative no-follow check of the final database component at connect
// time.
//
// The preflight Lstat is deliberately not relied on for the final component:
// it provides an early failed-precondition result for an already-invalid path,
// while the forked SQLite driver closes a later symlink-swap race.
func canonicalizeDatabaseConfig(config Config) (Config, error) {
	canonicalPath, err := canonicalDatabasePath(config.Path)
	if err != nil {
		return Config{}, err
	}
	config.Path = canonicalPath
	return config, nil
}

func canonicalDatabasePath(path string) (string, error) {
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	parentInfo, err := os.Stat(canonicalParent)
	if err != nil {
		return "", err
	}
	if !parentInfo.IsDir() {
		return "", sqliteError(policyengine.ErrorFailedPrecondition)
	}

	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", sqliteError(policyengine.ErrorFailedPrecondition)
		}
	case errors.Is(err, os.ErrNotExist):
		// The owner-only descriptor opener creates a missing final component.
	default:
		return "", err
	}
	return filepath.Join(canonicalParent, filepath.Base(path)), nil
}
