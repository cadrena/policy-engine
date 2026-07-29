package policyengine_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

func TestAttributePathConstructorsAreImmutable(t *testing.T) {
	t.Parallel()

	entity := dsl.EntityRef{Type: "document", ID: "roadmap"}
	path := []string{"region", "country"}
	attribute, err := policyengine.NewAttributePath(entity, path, policyengine.NewBooleanValue(true))
	if err != nil {
		t.Fatalf("NewAttributePath() error = %v", err)
	}
	key, err := policyengine.NewAttributeKeyPath(entity, path)
	if err != nil {
		t.Fatalf("NewAttributeKeyPath() error = %v", err)
	}
	path[0] = "mutated"
	if got := attribute.Path(); !reflect.DeepEqual(got, []string{"region", "country"}) {
		t.Fatalf("Attribute.Path() = %v", got)
	}
	returned := key.Path()
	returned[1] = "mutated"
	if got := key.Path(); !reflect.DeepEqual(got, []string{"region", "country"}) {
		t.Fatalf("AttributeKey.Path() = %v", got)
	}
}

func TestAttributePathCollectionsRejectPrefixesAndDeduplicateExactValues(t *testing.T) {
	t.Parallel()

	entity := dsl.EntityRef{Type: "document", ID: "roadmap"}
	parent, err := policyengine.NewAttributePath(entity, []string{"region"}, policyengine.NewBooleanValue(true))
	if err != nil {
		t.Fatal(err)
	}
	child, err := policyengine.NewAttributePath(entity, []string{"region", "country"}, policyengine.NewBooleanValue(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyengine.NewContextualData(nil, []policyengine.Attribute{child, parent}); err == nil {
		t.Fatal("contextual prefix conflict error = nil")
	}
	contextual, err := policyengine.NewContextualData(nil, []policyengine.Attribute{child, child})
	if err != nil {
		t.Fatalf("exact contextual duplicate error = %v", err)
	}
	if got := contextual.Attributes(); len(got) != 1 {
		t.Fatalf("deduplicated contextual attributes = %d, want 1", len(got))
	}

	parentKey, err := policyengine.NewAttributeKeyPath(entity, []string{"region"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
		Namespace:            "tenant",
		ValidationRevisionID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		IdempotencyKey:       "prefix",
		AttributeWrites:      []policyengine.Attribute{child},
		AttributeDeletes:     []policyengine.AttributeKey{parentKey},
	})
	if err == nil {
		t.Fatal("write/delete prefix conflict error = nil")
	}
}

func TestAttributePathSegmentsUseDSLIdentifiers(t *testing.T) {
	t.Parallel()

	entity := dsl.EntityRef{Type: "document", ID: "roadmap"}
	for _, path := range [][]string{nil, {}, {"region.country"}, {"9region"}, {"region", ""}} {
		if _, err := policyengine.NewAttributePath(entity, path, policyengine.NewNullValue()); err == nil {
			t.Fatalf("NewAttributePath(%v) error = nil", path)
		}
	}
}

func TestAttributePathRejectsConservativelyOverBudgetMetadata(t *testing.T) {
	t.Parallel()

	segment := strings.Repeat("a", 1019)
	path := make([]string, 4090)
	for index := range path {
		path[index] = segment
	}
	_, err := policyengine.NewAttributeKeyPath(dsl.EntityRef{Type: "document", ID: "roadmap"}, path)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
}

func TestWriteDataFingerprintUsesStructuredAttributePathSegments(t *testing.T) {
	t.Parallel()

	request := func(key string, path []string) policyengine.WriteDataRequest {
		attribute, err := policyengine.NewAttributePath(dsl.EntityRef{Type: "document", ID: "roadmap"}, path, policyengine.NewNullValue())
		if err != nil {
			t.Fatal(err)
		}
		result, err := policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{
			Namespace:            "tenant",
			ValidationRevisionID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			IdempotencyKey:       key,
			AttributeWrites:      []policyengine.Attribute{attribute},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	_, first, err := store.FingerprintWriteData(request("first", []string{"a", "bc"}))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := store.FingerprintWriteData(request("second", []string{"ab", "c"}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("distinct structured paths produced identical fingerprint")
	}
}

func TestPathBearingValuesRedactSupportedFormatsAndNestedCarrier(t *testing.T) {
	t.Parallel()

	entityCanary := "entity-canary-72ab"
	pathCanaries := []string{"path_canary_81cd", "leaf_canary_93ef"}
	entity := dsl.EntityRef{Type: "document", ID: entityCanary}
	attribute, err := policyengine.NewAttributePath(entity, pathCanaries, policyengine.NewBooleanValue(true))
	if err != nil {
		t.Fatal(err)
	}
	key, err := policyengine.NewAttributeKeyPath(entity, pathCanaries)
	if err != nil {
		t.Fatal(err)
	}
	contextual, err := policyengine.NewContextualData(nil, []policyengine.Attribute{attribute})
	if err != nil {
		t.Fatal(err)
	}
	input := policyengine.WriteDataRequestInput{
		Namespace:            "format-namespace",
		ValidationRevisionID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		IdempotencyKey:       "format-key",
		AttributeWrites:      []policyengine.Attribute{attribute},
	}
	request, err := policyengine.NewWriteDataRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{attribute, key, contextual, input, request} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
			assertNoPathCanary(t, fmt.Sprintf(format, value), entityCanary, pathCanaries)
			assertNoPathCanary(t, fmt.Sprintf(format, struct{ Value any }{Value: value}), entityCanary, pathCanaries)
		}
		carrier := struct{ Value any }{Value: value}
		assertNoPathCanary(t, fmt.Sprintf("%p", &value), entityCanary, pathCanaries)
		assertNoPathCanary(t, fmt.Sprintf("%p", &carrier), entityCanary, pathCanaries)
		var direct, nested bytes.Buffer
		slog.New(slog.NewTextHandler(&direct, nil)).Info("value", "value", value)
		slog.New(slog.NewTextHandler(&nested, nil)).Info("value", "value", struct{ Value any }{Value: value})
		assertNoPathCanary(t, direct.String(), entityCanary, pathCanaries)
		assertNoPathCanary(t, nested.String(), entityCanary, pathCanaries)
	}
}

func assertNoPathCanary(t *testing.T, output, entityCanary string, pathCanaries []string) {
	t.Helper()
	canaries := append([]string{entityCanary}, pathCanaries...)
	for _, canary := range canaries {
		if strings.Contains(output, canary) {
			t.Fatalf("format output leaked %q in %q", canary, output)
		}
	}
}
