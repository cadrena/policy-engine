package conformance

import (
	"fmt"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func TestCategoryCheckRequiresDirectSanitizedEngineError(t *testing.T) {
	t.Parallel()

	direct, err := policyengine.NewEngineError(policyengine.ErrorConflict)
	if err != nil {
		t.Fatalf("NewEngineError returned %T", err)
	}
	if !hasCategory(direct, policyengine.ErrorConflict) {
		t.Fatal("direct sanitized EngineError was rejected")
	}
	if hasCategory(hostileWrappedError{}, policyengine.ErrorConflict) {
		t.Fatal("hostile wrapped error was accepted")
	}
}

type hostileWrappedError struct{}

func (hostileWrappedError) Error() string { return "secret backend diagnostic" }

func (hostileWrappedError) As(any) bool { panic("As must not be called") }

func (hostileWrappedError) Unwrap() error { panic("Unwrap must not be called") }

func (hostileWrappedError) Format(fmt.State, rune) { panic("Format must not be called") }
