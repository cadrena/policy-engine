//go:build darwin || linux

package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestCanonicalDatabaseConfigUsesBenignParentTargetAcrossEntrypoints(t *testing.T) {
	realParent := t.TempDir()
	canonicalParent, err := filepath.EvalSymlinks(realParent)
	if err != nil {
		t.Fatalf("resolve real parent: %v", err)
	}
	aliasParent := filepath.Join(t.TempDir(), "database-parent")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatalf("create benign parent symlink: %v", err)
	}
	config := validConfig(filepath.Join(aliasParent, "policy.db"))
	wantPath := filepath.Join(canonicalParent, "policy.db")

	if _, err := ApplyMigrations(context.Background(), config); err != nil {
		t.Fatalf("apply migrations through benign parent symlink: %v", err)
	}
	if _, err := PlanMigrations(context.Background(), config); err != nil {
		t.Fatalf("plan migrations through benign parent symlink: %v", err)
	}
	if err := ValidateSchema(context.Background(), config); err != nil {
		t.Fatalf("validate schema through benign parent symlink: %v", err)
	}
	store, err := Open(config)
	if err != nil {
		t.Fatalf("open through benign parent symlink: %v", err)
	}
	if got := store.db.config.Path; got != wantPath {
		_ = store.Close()
		t.Fatalf("runtime canonical database path = %q, want %q", got, wantPath)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close through benign parent symlink: %v", err)
	}
	if err := FullIntegrityCheck(context.Background(), config); err != nil {
		t.Fatalf("full integrity through benign parent symlink: %v", err)
	}

	info, err := os.Lstat(wantPath)
	if err != nil {
		t.Fatalf("stat canonical database: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("canonical database mode = %v, want regular", info.Mode())
	}
}

func TestCanonicalDatabaseConfigSharesCanonicalLockPath(t *testing.T) {
	realParent := t.TempDir()
	canonicalParent, err := filepath.EvalSymlinks(realParent)
	if err != nil {
		t.Fatalf("resolve real parent: %v", err)
	}
	aliasParent := filepath.Join(t.TempDir(), "database-parent")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatalf("create benign parent symlink: %v", err)
	}
	aliasConfig := validConfig(filepath.Join(aliasParent, "policy.db"))
	if _, err := ApplyMigrations(context.Background(), aliasConfig); err != nil {
		t.Fatalf("apply migrations through benign parent symlink: %v", err)
	}

	store, err := Open(aliasConfig)
	if err != nil {
		t.Fatalf("open through benign parent symlink: %v", err)
	}
	defer func() { _ = store.Close() }()
	canonicalConfig := aliasConfig
	canonicalConfig.Path = filepath.Join(canonicalParent, "policy.db")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ApplyMigrations(ctx, canonicalConfig); err == nil {
		t.Fatal("canonical maintenance path acquired an exclusive lock while alias runtime held a shared lock")
	}
}

func TestCanonicalDatabaseConfigRejectsFinalSymlinkWithoutTouchingTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.db")
	before := []byte("CANARY")
	if err := os.WriteFile(target, before, 0o640); err != nil {
		t.Fatalf("write canary: %v", err)
	}
	source := filepath.Join(t.TempDir(), "policy.db")
	if err := os.Symlink(target, source); err != nil {
		t.Fatalf("create final symlink: %v", err)
	}

	_, err := canonicalizeDatabaseConfig(validConfig(source))
	if categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("final symlink category = %v, want %v (error=%v)", categoryOf(err), policyengine.ErrorFailedPrecondition, err)
	}
	after, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read canary after final-symlink rejection: %v", readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("final-symlink target changed: got %q, want %q", after, before)
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat canary after final-symlink rejection: %v", statErr)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("final-symlink target mode = %#o, want %#o", info.Mode().Perm(), os.FileMode(0o640))
	}
}
