package app

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

func TestExplainRejectsForgedTraceMetadataWithoutLeakingIt(t *testing.T) {
	artifact, err := dsl.CompileArtifact("explain.cdr", []byte(allowCheckSourceInternal))
	if err != nil {
		t.Fatal(err)
	}
	for _, trace := range [][]dsl.TraceStep{
		{{Resource: dsl.EntityRef{Type: "secret-resource", ID: "approval-token"}, Declaration: "viewer", Kind: "relation", Matched: true}},
		{{Resource: dsl.EntityRef{Type: "document", ID: "delegation-token"}, Declaration: "4111111111111111", Kind: "relation", Matched: true}},
		{{Resource: dsl.EntityRef{Type: "document", ID: "approval-token"}, Declaration: "viewer", Kind: "secret-resource", Matched: true}},
	} {
		steps, err := redactedExplainSteps(context.Background(), artifact, trace)
		if err == nil {
			t.Fatal("forged trace was accepted")
		}
		encoded := fmt.Sprintf("%+v %+v", steps, err)
		for _, forbidden := range []string{"secret-resource", "4111111111111111", "approval-token", "delegation-token"} {
			if strings.Contains(encoded, forbidden) {
				t.Fatalf("forged trace failure leaked %q", forbidden)
			}
		}
	}
}

func TestExplainTraceConversionEnforcesStepBudgetAndCancellation(t *testing.T) {
	artifact, err := dsl.CompileArtifact("explain.cdr", []byte(allowCheckSourceInternal))
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]dsl.TraceStep, policyengine.MaxExplainSteps+1)
	_, err = redactedExplainSteps(context.Background(), artifact, tooMany)
	requireInternalCategory(t, err, policyengine.ErrorResourceExhausted)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = redactedExplainSteps(canceled, artifact, []dsl.TraceStep{{
		Resource: dsl.EntityRef{Type: "document"}, Declaration: "viewer", Kind: "relation",
	}})
	requireInternalCategory(t, err, policyengine.ErrorCanceled)
}

func requireInternalCategory(t *testing.T, err error, want policyengine.ErrorCategory) {
	t.Helper()
	engineErr, ok := err.(*policyengine.EngineError)
	if !ok || engineErr.Category() != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

const allowCheckSourceInternal = `
entity user {}
entity document {
    relation viewer @user
    action view = viewer
}
guard document.view { allow otherwise }
`
