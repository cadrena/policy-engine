package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func TestFilesystemBoundaryRejectsUnsupportedRuntimeAndMaintenanceOperations(t *testing.T) {
	// This catches an entry path that reaches a lock or SQLite connection on an
	// unclassified filesystem. The database is valid before the injected
	// rejection, so none of these calls can pass simply because it is missing or
	// unmigrated.
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("ApplyMigrations(setup) error = %v", err)
	}
	installFilesystemClassifierForTest(t, func(string) error {
		return errUnsupportedFilesystem
	})

	operations := []struct {
		name string
		run  func() error
	}{
		{
			name: "runtime open",
			run: func() error {
				opened, err := Open(config)
				if opened != nil {
					_ = opened.Close()
				}
				return err
			},
		},
		{name: "plan", run: func() error { _, err := PlanMigrations(context.Background(), config); return err }},
		{name: "migrate", run: func() error { _, err := ApplyMigrations(context.Background(), config); return err }},
		{name: "validate", run: func() error { return ValidateSchema(context.Background(), config) }},
		{name: "integrity", run: func() error { return FullIntegrityCheck(context.Background(), config) }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); categoryOf(err) != policyengine.ErrorFailedPrecondition {
				t.Fatalf("%s error = %v, category = %v, want %v", operation.name, err, categoryOf(err), policyengine.ErrorFailedPrecondition)
			}
		})
	}
}

func TestFilesystemBoundarySanitizesClassifierFailures(t *testing.T) {
	// This catches a filesystem probe that returns the syscall/path detail from
	// Statfs instead of one of the public error categories.
	const canary = "CANARY_FILESYSTEM_DETAIL"
	config := validConfig(filepath.Join(t.TempDir(), "policy.db"))
	installFilesystemClassifierForTest(t, func(string) error {
		return errors.New(canary)
	})

	_, err := PlanMigrations(context.Background(), config)
	if got := categoryOf(err); got != policyengine.ErrorInternal {
		t.Fatalf("PlanMigrations() error = %v, category = %v, want %v", err, got, policyengine.ErrorInternal)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("PlanMigrations() leaked classifier detail: %q", err)
	}
}

func installFilesystemClassifierForTest(t *testing.T, classifier func(string) error) {
	t.Helper()
	filesystemClassifierMu.Lock()
	previous := filesystemClassifier
	filesystemClassifier = classifier
	filesystemClassifierMu.Unlock()
	t.Cleanup(func() {
		filesystemClassifierMu.Lock()
		filesystemClassifier = previous
		filesystemClassifierMu.Unlock()
	})
}
