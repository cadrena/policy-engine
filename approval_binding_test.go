package policyengine_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func TestApprovalBindingDigestExistsOnlyForRequireApproval(t *testing.T) {
	approval := requireApprovalDecisionResult(t, [32]byte{1})
	got, ok := approval.ApprovalBindingDigest()
	if !ok || got != ([32]byte{1}) {
		t.Fatalf("approval digest = %x, %t", got, ok)
	}
	for _, decision := range []policyengine.Decision{policyengine.DecisionAllow, policyengine.DecisionDeny} {
		result := ordinaryDecisionResult(t, decision)
		if _, ok := result.ApprovalBindingDigest(); ok {
			t.Fatalf("%v exposed an approval digest", decision)
		}
	}
}

func TestDecisionResultRejectsApprovalDigestOnWrongDecision(t *testing.T) {
	for _, decision := range []policyengine.Decision{policyengine.DecisionAllow, policyengine.DecisionDeny} {
		input := validDecisionResultInput(t, decision)
		input.ApprovalBindingDigest = [32]byte{1}
		if _, err := policyengine.NewDecisionResult(input); category(err) != policyengine.ErrorInvalidArgument {
			t.Fatalf("%v category = %v", decision, category(err))
		}
	}
}

func TestDecisionResultRequiresNonZeroApprovalBindingDigest(t *testing.T) {
	for _, name := range []string{"missing", "zero"} {
		t.Run(name, func(t *testing.T) {
			input := validDecisionResultInput(t, policyengine.DecisionRequireApproval)
			input.ApprovalBindingDigest = [32]byte{}
			if _, err := policyengine.NewDecisionResult(input); category(err) != policyengine.ErrorInvalidArgument {
				t.Fatalf("%s digest category = %v", name, category(err))
			}
		})
	}
}

func TestDecisionResultApprovalBindingDigestIsRedacted(t *testing.T) {
	digest := sha256.Sum256([]byte("approval-digest-format-canary"))
	result := requireApprovalDecisionResult(t, digest)
	canaries := []string{fmt.Sprintf("%x", digest), fmt.Sprintf("%v", digest)}
	for _, formatted := range []string{
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
	} {
		for _, canary := range canaries {
			if strings.Contains(formatted, canary) {
				t.Fatalf("decision result formatting exposed approval digest: %q", formatted)
			}
		}
	}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("decision", "result", result)
	for _, canary := range canaries {
		if strings.Contains(logs.String(), canary) {
			t.Fatalf("decision result slog output exposed approval digest: %q", logs.String())
		}
	}
}

func TestAuthorizationDigestBindsEveryAuthorityFieldButNotEvaluationTime(t *testing.T) {
	base := approvalEvidenceBinding(t, bindingMutation{})
	want, ok := base.AuthorizationDigest()
	if !ok || want == ([32]byte{}) {
		t.Fatal("base binding has no digest")
	}
	retry := approvalEvidenceBinding(t, bindingMutation{EvaluatedAtDelta: time.Minute})
	if got, _ := retry.AuthorizationDigest(); got != want {
		t.Fatal("evaluation time changed authorization digest")
	}
	for _, mutation := range authorityMutations() {
		changed := approvalEvidenceBinding(t, mutation)
		if got, _ := changed.AuthorizationDigest(); got == want {
			t.Fatalf("mutation %s preserved digest", mutation.Name)
		}
	}
}

type bindingMutation struct {
	Name string

	CallerID           string
	Namespace          string
	SelectorKind       string
	SelectorValue      string
	RevisionID         string
	SlotGeneration     uint64
	DataGeneration     uint64
	SubjectID          string
	ResourceID         string
	Action             string
	Argument           string
	DirectTupleSubject string
	DirectAttribute    string
	DelegatedTupleUser string
	DelegatedAttribute string
	DelegatedAuthority *bool
	EvaluatedAtDelta   time.Duration
}

func authorityMutations() []bindingMutation {
	delegatedAuthority := false
	return []bindingMutation{
		{Name: "caller", CallerID: "caller-2"},
		{Name: "namespace", Namespace: "tenant-b"},
		{Name: "selector kind", SelectorKind: "revision"},
		{Name: "selector value", SelectorValue: "next"},
		{Name: "revision ID", RevisionID: strings.Repeat("b", sha256.Size*2)},
		{Name: "slot generation", SlotGeneration: 12},
		{Name: "data generation", DataGeneration: 14},
		{Name: "subject", SubjectID: "bob"},
		{Name: "resource", ResourceID: "document-2"},
		{Name: "action", Action: "edit"},
		{Name: "canonical argument", Argument: "staging"},
		{Name: "direct contextual tuple", DirectTupleSubject: "carol"},
		{Name: "direct contextual attribute", DirectAttribute: "internal"},
		{Name: "verified delegated tuple", DelegatedTupleUser: "dave"},
		{Name: "verified delegated attribute", DelegatedAttribute: "restricted"},
		{Name: "delegated-authority participation", DelegatedAuthority: &delegatedAuthority},
	}
}

func approvalEvidenceBinding(t *testing.T, mutation bindingMutation) policyengine.EvidenceBinding {
	t.Helper()
	callerID := chooseText(mutation.CallerID, "caller-1")
	namespace := chooseText(mutation.Namespace, "tenant-a")
	revisionID := chooseText(mutation.RevisionID, strings.Repeat("a", sha256.Size*2))
	slotGeneration := chooseUint64(mutation.SlotGeneration, 11)
	selectorSlot := chooseText(mutation.SelectorValue, "stable")
	exactRevision := ""
	if mutation.SelectorKind == "revision" {
		selectorSlot = ""
		exactRevision = revisionID
		slotGeneration = 0
	}
	selector, err := policyengine.NewSelector(selectorSlot, exactRevision)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := policyengine.NewCaller(callerID, map[string]string{"issuer": "adapter"})
	if err != nil {
		t.Fatal(err)
	}
	delegatedAuthority := true
	if mutation.DelegatedAuthority != nil {
		delegatedAuthority = *mutation.DelegatedAuthority
	}
	fingerprint := authorizationFixtureFingerprint(
		chooseText(mutation.SubjectID, "alice"),
		chooseText(mutation.ResourceID, "document-1"),
		chooseText(mutation.Action, "view"),
		chooseText(mutation.Argument, "production"),
		chooseText(mutation.DirectTupleSubject, "alice"),
		chooseText(mutation.DirectAttribute, "public"),
		chooseText(mutation.DelegatedTupleUser, "bob"),
		chooseText(mutation.DelegatedAttribute, "confidential"),
		delegatedAuthority,
	)
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: namespace, Selector: selector,
		RevisionID: revisionID, SlotGeneration: slotGeneration,
		DataGeneration: chooseUint64(mutation.DataGeneration, 13),
		EvaluatedAt:    time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC).Add(mutation.EvaluatedAtDelta),
		Fingerprint:    policyengine.NewEvidenceFingerprint(fingerprint),
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func authorizationFixtureFingerprint(subjectID, resourceID, action, argument, directTupleSubject, directAttribute, delegatedTupleUser, delegatedAttribute string, delegatedAuthority bool) [sha256.Size]byte {
	hash := sha256.New()
	writeApprovalFixtureField(hash, "subject")
	writeApprovalFixtureField(hash, "user")
	writeApprovalFixtureField(hash, subjectID)
	writeApprovalFixtureField(hash, "resource")
	writeApprovalFixtureField(hash, "document")
	writeApprovalFixtureField(hash, resourceID)
	writeApprovalFixtureField(hash, "action")
	writeApprovalFixtureField(hash, action)
	writeApprovalFixtureField(hash, "argument")
	writeApprovalFixtureField(hash, "environment")
	writeApprovalFixtureField(hash, argument)
	writeApprovalFixtureField(hash, "direct-tuple")
	writeApprovalFixtureField(hash, directTupleSubject)
	writeApprovalFixtureField(hash, "direct-attribute")
	writeApprovalFixtureField(hash, directAttribute)
	writeApprovalFixtureField(hash, "delegated-tuple")
	writeApprovalFixtureField(hash, delegatedTupleUser)
	writeApprovalFixtureField(hash, "delegated-attribute")
	writeApprovalFixtureField(hash, delegatedAttribute)
	if delegatedAuthority {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeApprovalFixtureField(hash interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(value))
}

func chooseText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func chooseUint64(value, fallback uint64) uint64 {
	if value == 0 {
		return fallback
	}
	return value
}

func validDecisionResultInput(t *testing.T, decision policyengine.Decision) policyengine.DecisionResultInput {
	t.Helper()
	input := policyengine.DecisionResultInput{
		Decision: decision, DecisionID: "decision-1", ReasonCode: "APPROVAL_REQUIRED",
		RevisionID: testRevisionID(t), SlotGeneration: 1,
		EvaluatedAt: time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC),
	}
	if decision == policyengine.DecisionRequireApproval {
		input.Requirements = []string{"finance"}
		input.ApprovalBindingDigest = [sha256.Size]byte{1}
	}
	return input
}

func requireApprovalDecisionResult(t *testing.T, digest [sha256.Size]byte) policyengine.DecisionResult {
	t.Helper()
	input := validDecisionResultInput(t, policyengine.DecisionRequireApproval)
	input.ApprovalBindingDigest = digest
	result, err := policyengine.NewDecisionResult(input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func ordinaryDecisionResult(t *testing.T, decision policyengine.Decision) policyengine.DecisionResult {
	t.Helper()
	result, err := policyengine.NewDecisionResult(validDecisionResultInput(t, decision))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func category(err error) policyengine.ErrorCategory {
	var engineErr *policyengine.EngineError
	if !errors.As(err, &engineErr) || engineErr == nil {
		return policyengine.ErrorCategory("")
	}
	return engineErr.Category()
}
