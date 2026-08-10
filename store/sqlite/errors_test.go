package sqlite

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func TestMapErrorClassifiesWrappedFilesystemCapacityAndReadOnlyFailures(t *testing.T) {
	// This catches wrapped filesystem errors being reported as INTERNAL instead
	// of the public capacity or permission category callers can act on.
	for _, test := range []struct {
		name string
		err  error
		want policyengine.ErrorCategory
	}{
		{name: "no space", err: fmt.Errorf("write database: %w", syscall.ENOSPC), want: policyengine.ErrorResourceExhausted},
		{name: "quota", err: fmt.Errorf("write database: %w", syscall.EDQUOT), want: policyengine.ErrorResourceExhausted},
		{name: "read-only", err: fmt.Errorf("write database: %w", syscall.EROFS), want: policyengine.ErrorPermissionDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := categoryOf(mapError(context.Background(), test.err)); got != test.want {
				t.Fatalf("mapError(%v) category = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
