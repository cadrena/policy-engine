package policyengine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func assertCostIncludesAtLeast(t *testing.T, minimum int, add func(*budgetCounter) error) {
	t.Helper()

	budget := budgetCounter{max: 1 << 30}
	if err := add(&budget); err != nil {
		t.Fatalf("cost accounting error = %v", err)
	}
	if budget.used < minimum {
		t.Fatalf("accounted bytes = %d, want at least all %d dynamic bytes", budget.used, minimum)
	}
}

func TestCompleteInputCostModelsCountAllDynamicBytes(t *testing.T) {
	long := strings.Repeat("x", MaxIdentifierBytes)
	revisionID := strings.Repeat("a", 64)
	binding := EvidenceBinding{
		caller:         CallerBinding{valid: true},
		namespace:      long,
		selector:       Selector{slot: long},
		revisionID:     revisionID,
		slotGeneration: 1,
		evaluatedAt:    time.Unix(1, 0),
		fingerprint:    EvidenceFingerprint{valid: true},
		validBinding:   true,
	}

	assertCostIncludesAtLeast(t, len(binding.namespace)+len(binding.selector.slot)+len(binding.revisionID), func(budget *budgetCounter) error {
		return addEvidenceBindingCost(budget, binding)
	})

	requirements := []string{long, long}
	evidence := []byte(long)
	assertCostIncludesAtLeast(t, len(binding.namespace)+len(binding.selector.slot)+len(binding.revisionID)+2*len(long)+len(evidence), func(budget *budgetCounter) error {
		return addApprovalVerificationRequestCost(budget, binding, requirements, evidence)
	})
	assertCostIncludesAtLeast(t, len(binding.namespace)+len(binding.selector.slot)+len(binding.revisionID)+len(evidence), func(budget *budgetCounter) error {
		return addDelegationVerificationRequestCost(budget, binding, evidence)
	})
	assertCostIncludesAtLeast(t, 3*len(long), func(budget *budgetCounter) error {
		return addPublishRequestCost(budget, long, long, []byte(long))
	})

	attributes := map[string]string{long: long}
	assertCostIncludesAtLeast(t, 3*len(long), func(budget *budgetCounter) error {
		return addCallerCost(budget, long, attributes)
	})
}

func TestCompleteOutputCostModelsCountAllDynamicBytes(t *testing.T) {
	long := strings.Repeat("x", MaxIdentifierBytes)
	revisionID := strings.Repeat("a", 64)
	now := time.Unix(1, 0)

	grant := Grant{namespacePattern: long, capabilities: []Capability{CapabilityAuthorizationCheck}}
	assertCostIncludesAtLeast(t, len(long)+len(CapabilityAuthorizationCheck), func(budget *budgetCounter) error {
		return addCallerAuthorizationCost(budget, []Grant{grant})
	})

	revision := RevisionMetadata{namespace: long, id: RevisionID{valid: true}, publishedAt: now}
	assertCostIncludesAtLeast(t, 2*len(long), func(budget *budgetCounter) error {
		return addRevisionPageCost(budget, []RevisionMetadata{revision}, long)
	})

	activation := Activation{namespace: long, slot: long, revisionID: revisionID, generation: 1, activatedAt: now}
	assertCostIncludesAtLeast(t, 3*len(long)+len(revisionID), func(budget *budgetCounter) error {
		return addActivationHistoryPageCost(budget, []Activation{activation}, long)
	})

	event := StateEvent{
		namespace:      long,
		cursor:         long,
		kind:           StateEventSlotActivated,
		revisionID:     revisionID,
		slot:           long,
		slotGeneration: 1,
		occurredAt:     now,
	}
	assertCostIncludesAtLeast(t, 4*len(long)+len(revisionID), func(budget *budgetCounter) error {
		return addEventPageCost(budget, []StateEvent{event}, long)
	})

	component := ComponentStatus{name: long, state: ComponentReady, reasonCode: long}
	assertCostIncludesAtLeast(t, 2*len(long), func(budget *budgetCounter) error {
		return addStatusResponseCost(budget, true, []ComponentStatus{component})
	})
}

func TestIdentifierCollectionsExceedAggregateCostWithoutOversizedItems(t *testing.T) {
	values := make([]string, MaxVerifierOutputItems)
	for index := range values {
		values[index] = strings.Repeat("x", MaxIdentifierBytes)
	}

	full := budgetCounter{max: 1 << 30}
	if err := addIdentifiersCost(&full, values); err != nil {
		t.Fatal(err)
	}
	limited := budgetCounter{max: full.used - 1}
	err := addIdentifiersCost(&limited, values)
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Category() != ErrorResourceExhausted {
		t.Fatalf("identifier aggregate error = %#v, want RESOURCE_EXHAUSTED", err)
	}
}
