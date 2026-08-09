//go:build !darwin && !linux

package sqlite

func newAdvisoryLock(databasePath string) (advisoryLock, error) {
	return unsupportedAdvisoryLock(databasePath)
}
