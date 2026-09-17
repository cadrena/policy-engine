package app

import (
	"context"
	"errors"
	"testing"

	"github.com/cadrena/dsl"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/domain"
)

func TestResourceAttributeWorkBudgetPrecedesReads(t *testing.T) {
	artifact, err := dsl.CompileArtifact("work.cdr", []byte(`entity user {} entity document { relation viewer @user action view = viewer } guard document.view { allow when resource.metadata.classification == "public" }`))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := domain.NewDataSchema(artifact)
	if err != nil {
		t.Fatal(err)
	}
	session := evaluationSession{schema: schema, attributeBudget: &batchWorkBudget{maxItems: 3, maxBytes: pe.MaxAggregateInputBytes}}
	// A nil reader proves that admission fails before any store call.
	_, err = resolveResourceAttributes(context.Background(), session, dsl.EntityRef{Type: "document", ID: "doc"}, "view")
	var engineError *pe.EngineError
	if !errors.As(err, &engineError) || engineError.Category() != pe.ErrorResourceExhausted {
		t.Fatalf("work bound=%v", err)
	}
	paths := schema.ResourcePaths("document", "view")
	paths[0][0] = "changed"
	if schema.ResourcePaths("document", "view")[0][0] != "metadata" {
		t.Fatal("caller changed retained resource paths")
	}
}
