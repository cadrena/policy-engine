//go:build !darwin && !linux

package sqlite

import (
	"os"

	policyengine "github.com/cadrena/policy-engine"
)

// Unsupported platforms do not offer the verified no-follow implementation
// required for durable SQLite setup, so they fail closed.
func openOwnerOnlyRegularFile(string) (*os.File, error) {
	return nil, sqliteError(policyengine.ErrorFailedPrecondition)
}
