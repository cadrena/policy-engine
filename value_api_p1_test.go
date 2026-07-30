package policyengine_test

import (
	"strings"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

func mustStringValue(t testing.TB, input string) policyengine.Value {
	t.Helper()

	value, err := policyengine.NewStringValue(input)
	if err != nil {
		t.Fatalf("NewStringValue(%q) error = %v", input, err)
	}
	return value
}

func TestNewStringValueValidatesAndExposesTypedString(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"empty":   "",
		"ASCII":   "production",
		"Unicode": "héllø 世界",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			value, err := policyengine.NewStringValue(input)
			if err != nil {
				t.Fatalf("NewStringValue(%q) error = %v", input, err)
			}
			got, ok := value.StringValue()
			if !ok || got != input {
				t.Fatalf("StringValue() = %q, %t, want %q, true", got, ok, input)
			}
			if value.Kind() != policyengine.ValueKindString {
				t.Fatalf("Kind() = %v, want ValueKindString", value.Kind())
			}
		})
	}
}

func TestNewStringValueRejectsInvalidText(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"NUL":           "bad\x00value",
		"control":       "bad\nvalue",
		"format rune":   "bad\u200bvalue",
		"invalid UTF-8": string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := policyengine.NewStringValue(input); !isCategory(err, policyengine.ErrorInvalidArgument) {
				t.Fatalf("NewStringValue() error = %#v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func TestNewStringValueRejectsOversizedText(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("v", policyengine.MaxStringValueBytes+1)
	if _, err := policyengine.NewStringValue(input); !isCategory(err, policyengine.ErrorResourceExhausted) {
		t.Fatalf("NewStringValue() error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestNonStringValuesDoNotExposeStringValue(t *testing.T) {
	t.Parallel()

	for _, value := range []policyengine.Value{
		policyengine.NewIntegerValue(1),
		policyengine.NewBooleanValue(true),
		policyengine.NewNullValue(),
	} {
		if got, ok := value.StringValue(); ok || got != "" {
			t.Fatalf("StringValue() = %q, %t, want empty, false", got, ok)
		}
	}
}
