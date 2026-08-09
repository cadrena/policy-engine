package sqlite

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

const lockHelperFlag = "CADRENA_SQLITE_LOCK_HELPER"

func TestLockCoordinatesAcrossProcesses(t *testing.T) {
	// This catches a broken or process-local-only lock implementation: a second
	// process must be able to share a runtime lock but not take maintenance
	// ownership until every runtime holder has released it.
	path := filepath.Join(t.TempDir(), "policy.db")
	firstShared := startLockHelper(t, path, "shared")

	secondShared, err := newAdvisoryLock(path)
	if err != nil {
		t.Fatalf("newAdvisoryLock() error = %v", err)
	}
	defer secondShared.Close()
	if err := secondShared.LockShared(context.Background()); err != nil {
		t.Fatalf("second shared lock error = %v", err)
	}

	info, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatalf("Stat(lock file) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock file permissions = %#o, want %#o", got, os.FileMode(0o600))
	}

	if output, err := runLockHelper(path, "exclusive"); err == nil {
		t.Fatalf("exclusive lock succeeded while shared locks held: %q", output)
	}

	if err := secondShared.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	if output, err := runLockHelper(path, "exclusive"); err == nil {
		t.Fatalf("exclusive lock succeeded while one shared lock held: %q", output)
	}
	stopLockHelper(t, firstShared)

	exclusive := startLockHelper(t, path, "exclusive")
	defer stopLockHelper(t, exclusive)
	if output, err := runLockHelper(path, "exclusive"); err == nil {
		t.Fatalf("second exclusive lock succeeded: %q", output)
	}
}

func TestLockDeadlineStopsPolling(t *testing.T) {
	// This catches an implementation that sleeps or retries past the caller's
	// deadline while another process owns the incompatible maintenance lock.
	path := filepath.Join(t.TempDir(), "policy.db")
	held := startLockHelper(t, path, "exclusive")
	defer stopLockHelper(t, held)

	lock, err := newAdvisoryLock(path)
	if err != nil {
		t.Fatalf("newAdvisoryLock() error = %v", err)
	}
	defer lock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = lock.LockShared(ctx)
	if categoryOf(err) != policyengine.ErrorDeadlineExceeded {
		t.Fatalf("LockShared() category = %v, want %v", categoryOf(err), policyengine.ErrorDeadlineExceeded)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("LockShared() waited %v after a 50ms deadline", elapsed)
	}
}

func TestLockUnsupportedPlatformFailsClosedWithoutTouchingDatabase(t *testing.T) {
	// This catches an unsupported-platform fallback that creates a sidecar or
	// silently leaves locking disabled instead of refusing the durable open.
	path := filepath.Join(t.TempDir(), "policy.db")
	lock, err := unsupportedAdvisoryLock(path)
	if lock != nil {
		t.Fatal("unsupportedAdvisoryLock() lock = non-nil, want nil")
	}
	if categoryOf(err) != policyengine.ErrorFailedPrecondition {
		t.Fatalf("unsupportedAdvisoryLock() category = %v, want %v", categoryOf(err), policyengine.ErrorFailedPrecondition)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("database path was touched: stat error = %v", statErr)
	}
	if _, statErr := os.Stat(path + ".lock"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("lock path was touched: stat error = %v", statErr)
	}
}

func TestLockHelperProcess(t *testing.T) {
	if os.Getenv(lockHelperFlag) != "1" {
		return
	}

	path := os.Getenv("CADRENA_SQLITE_LOCK_PATH")
	mode := os.Getenv("CADRENA_SQLITE_LOCK_MODE")
	lock, err := newAdvisoryLock(path)
	ctx, cancel := helperContext()
	defer cancel()
	if err == nil {
		switch mode {
		case "shared":
			err = lock.LockShared(ctx)
		case "exclusive":
			err = lock.LockExclusive(ctx)
		default:
			err = fmt.Errorf("invalid helper mode")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stdout, "failed")
		os.Exit(1)
	}
	defer lock.Close()
	fmt.Fprintln(os.Stdout, "locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func helperContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 150*time.Millisecond)
}

type lockHelper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func startLockHelper(t *testing.T, path, mode string) *lockHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		lockHelperFlag+"=1",
		"CADRENA_SQLITE_LOCK_PATH="+path,
		"CADRENA_SQLITE_LOCK_MODE="+mode,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("lock helper did not acquire %s lock: line=%q error=%v", mode, line, err)
	}
	return &lockHelper{cmd: cmd, stdin: stdin}
}

func stopLockHelper(t *testing.T, helper *lockHelper) {
	t.Helper()
	if helper == nil {
		return
	}
	if err := helper.stdin.Close(); err != nil {
		t.Errorf("lock helper stdin close error = %v", err)
	}
	if err := helper.cmd.Wait(); err != nil {
		t.Errorf("lock helper exit error = %v", err)
	}
}

func runLockHelper(path, mode string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		lockHelperFlag+"=1",
		"CADRENA_SQLITE_LOCK_PATH="+path,
		"CADRENA_SQLITE_LOCK_MODE="+mode,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
