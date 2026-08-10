package sqlite

import (
	"context"
	"errors"
	"sync"

	policyengine "github.com/cadrena/policy-engine"
)

var errUnsupportedFilesystem = errors.New("unsupported filesystem")

// filesystemClassifier is deliberately private. Package tests replace it to
// exercise every public entry boundary without depending on a machine-specific
// network filesystem mount. Access is synchronized for race-safe test seams.
var (
	filesystemClassifierMu sync.RWMutex
	filesystemClassifier   = classifyFilesystem
)

// validateSupportedFilesystem checks the database parent before any lock or
// SQLite connection is created. A positive platform allowlist protects the
// local-advisory-lock contract; unknown, network, and FUSE filesystems fail
// closed without exposing syscall or path details.
func validateSupportedFilesystem(ctx context.Context, databasePath string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	filesystemClassifierMu.RLock()
	classifier := filesystemClassifier
	filesystemClassifierMu.RUnlock()
	if classifier == nil {
		return sqliteError(policyengine.ErrorFailedPrecondition)
	}
	if err := classifier(databasePath); err != nil {
		if errors.Is(err, errUnsupportedFilesystem) {
			return sqliteError(policyengine.ErrorFailedPrecondition)
		}
		return mapError(ctx, err)
	}
	return nil
}
