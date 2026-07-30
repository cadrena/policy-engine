package policyengine

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cadrena/dsl"
)

func validateText(value string, maximum int, allowEmpty bool) error {
	if value == "" && !allowEmpty {
		return invalidArgument("required text is empty")
	}
	if len(value) > maximum {
		return resourceExhausted()
	}
	if !utf8.ValidString(value) {
		return invalidArgument("text is not valid UTF-8")
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return invalidArgument("text contains an unsafe character")
		}
	}
	return nil
}

func validateIdentifier(value string) error {
	return validateText(value, MaxIdentifierBytes, false)
}

func validateOptionalIdentifier(value string) error {
	return validateText(value, MaxIdentifierBytes, true)
}

func validateNamespace(value string) error {
	if err := validateText(value, MaxNamespaceBytes, false); err != nil {
		return err
	}
	if strings.Contains(value, "*") {
		return invalidArgument("namespace contains a wildcard")
	}
	return nil
}

func validateNamespacePattern(pattern string) error {
	if err := validateText(pattern, MaxNamespacePatternBytes, false); err != nil {
		return err
	}
	if strings.Count(pattern, "*") > 1 || (strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
		return invalidArgument("namespace pattern is not exact or trailing-wildcard")
	}
	return nil
}

func validIdentifier(value string) bool { return validateIdentifier(value) == nil }
func validNamespace(value string) bool  { return validateNamespace(value) == nil }

func validateAttributePath(path []string) error {
	if len(path) == 0 {
		return invalidArgument("attribute path is empty")
	}
	if len(path) > MaxAggregateWorkItems {
		return resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addAttributePathCost(&budget, path); err != nil {
		return err
	}
	for _, segment := range path {
		if err := validateIdentifier(segment); err != nil {
			return err
		}
		if !validDSLIdentifier(segment) {
			return invalidArgument("attribute path segment is not a DSL identifier")
		}
	}
	return nil
}

func validDSLIdentifier(value string) bool {
	if value == "" || !isDSLIdentifierStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isDSLIdentifierStart(value[index]) && (value[index] < '0' || value[index] > '9') {
			return false
		}
	}
	return true
}

func isDSLIdentifierStart(value byte) bool {
	return value == '_' || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

func validRevisionIDString(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := range value {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func canonicalIdentifiers(values []string, maximumItems, maximumBytes int) ([]string, error) {
	if len(values) > maximumItems {
		return nil, resourceExhausted()
	}
	budget := budgetCounter{max: maximumBytes}
	for _, value := range values {
		if err := budget.add(len(value)); err != nil {
			return nil, err
		}
		if err := validateIdentifier(value); err != nil {
			return nil, err
		}
	}
	cloned := cloneSlice(values)
	sort.Strings(cloned)
	write := 0
	for _, value := range cloned {
		if write > 0 && cloned[write-1] == value {
			continue
		}
		cloned[write] = value
		write++
	}
	return cloned[:write], nil
}

func validCanonicalIdentifiers(values []string, maximumItems, maximumBytes int) bool {
	if len(values) > maximumItems {
		return false
	}
	budget := budgetCounter{max: maximumBytes}
	for index, value := range values {
		if budget.add(len(value)) != nil || validateIdentifier(value) != nil {
			return false
		}
		if index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validateEntityRef(entity dsl.EntityRef) error {
	if err := validateIdentifier(entity.Type); err != nil {
		return err
	}
	return validateIdentifier(entity.ID)
}

func validateSubjectRef(subject dsl.SubjectRef) error {
	if err := validateIdentifier(subject.Type); err != nil {
		return err
	}
	if err := validateIdentifier(subject.ID); err != nil {
		return err
	}
	return validateOptionalIdentifier(subject.Relation)
}

func validateDSLRelationship(tuple dsl.Tuple) error {
	if err := validateEntityRef(tuple.Resource); err != nil {
		return err
	}
	if err := validateIdentifier(tuple.Relation); err != nil {
		return err
	}
	return validateSubjectRef(tuple.Subject)
}

func validateValue(value Value) error {
	if !value.valid() {
		return invalidArgument("typed value is invalid")
	}
	if value.kind == ValueKindString {
		return validateText(value.text, MaxStringValueBytes, true)
	}
	return nil
}

func validateArguments(arguments map[string]Value) error {
	if len(arguments) > MaxArgumentItems {
		return resourceExhausted()
	}
	for key, value := range arguments {
		if err := validateIdentifier(key); err != nil {
			return err
		}
		if err := validateValue(value); err != nil {
			return err
		}
	}
	return nil
}
