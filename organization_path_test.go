package policyengine_test

import (
	"testing"

	cadrenadsl "github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

func TestCanonicalModulePathsUseCadrena(t *testing.T) {
	var artifact cadrenadsl.Artifact
	if source := artifact.CanonicalSource(); len(source) != 0 {
		t.Fatalf("zero artifact canonical source length = %d, want 0", len(source))
	}

	if got := policyengine.DecisionAllow.String(); got != "ALLOW" {
		t.Fatalf("DecisionAllow.String() = %q, want ALLOW", got)
	}
}
