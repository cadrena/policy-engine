package policyengine_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

func requireCategory(t *testing.T, err error, want policyengine.ErrorCategory) {
	t.Helper()
	var engineErr *policyengine.EngineError
	if !errors.As(err, &engineErr) || engineErr.Category() != want {
		t.Fatalf("error = %v, want category %s", err, want)
	}
}

func task5Binding(t *testing.T) policyengine.EvidenceBinding {
	t.Helper()
	caller, err := policyengine.NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := policyengine.NewSelector("stable", "")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: "acme", Selector: selector,
		RevisionID: testRevisionID(t), SlotGeneration: 1, EvaluatedAt: time.Now(),
		Fingerprint: policyengine.NewEvidenceFingerprint([32]byte{1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestTask5StableHardLimitsRejectBeforeAllocation(t *testing.T) {
	if policyengine.MaxPolicySourceBytes != dsl.DefaultLimits().MaxSourceBytes || policyengine.MaxPolicyArtifactBytes != dsl.DefaultArtifactMaxBytes {
		t.Fatal("policy limits do not reuse tagged DSL v1 limits")
	}

	_, err := policyengine.NewListRevisionsRequest("acme", "", math.MaxInt)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	_, err = policyengine.NewDelegationVerificationRequest(task5Binding(t), make([]byte, policyengine.MaxEvidenceBytes+1))
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	grant, err := policyengine.NewGrant("acme", []policyengine.Capability{policyengine.CapabilityPolicyRead})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policyengine.NewCallerAuthorization(make([]policyengine.Grant, policyengine.MaxCallerGrants+1))
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	component, err := policyengine.NewComponentStatus("store", policyengine.ComponentReady, "READY")
	if err != nil {
		t.Fatal(err)
	}
	components := make([]policyengine.ComponentStatus, policyengine.MaxStatusComponents+1)
	for i := range components {
		components[i] = component
	}
	_, err = policyengine.NewStatusResponse(true, components)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	item, err := policyengine.NewBatchCheckItem(dsl.EntityRef{Type: "user", ID: "alice"}, dsl.EntityRef{Type: "doc", ID: "one"}, "read", nil)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]policyengine.BatchCheckItem, policyengine.MaxBatchItems+1)
	for i := range items {
		items[i] = item
	}
	selector, _ := policyengine.NewSelector("stable", "")
	_, err = policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{Namespace: "acme", Selector: selector, Items: items})
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "doc", ID: "one"}, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mutations := make([]policyengine.RelationshipTuple, policyengine.MaxMutationItems+1)
	for i := range mutations {
		mutations[i] = tuple
	}
	_, err = policyengine.NewWriteDataRequest(policyengine.WriteDataRequestInput{Namespace: "acme", ValidationRevisionID: testRevisionID(t), IdempotencyKey: "write", TupleWrites: mutations})
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	_, err = policyengine.NewPublishRequest("acme", "policy.cdr", make([]byte, policyengine.MaxPolicySourceBytes+1))
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	arguments := make(map[string]policyengine.Value, policyengine.MaxArgumentItems+1)
	for i := 0; i <= policyengine.MaxArgumentItems; i++ {
		arguments[strings.Repeat("a", i+1)] = policyengine.NewNullValue()
	}
	_, err = policyengine.NewBatchCheckItem(dsl.EntityRef{Type: "user", ID: "alice"}, dsl.EntityRef{Type: "doc", ID: "one"}, "read", arguments)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	_, err = policyengine.NewCaller(strings.Repeat("x", policyengine.MaxIdentifierBytes+1), nil)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)

	_, err = policyengine.NewCaller("", nil)
	requireCategory(t, err, policyengine.ErrorInvalidArgument)

	_ = grant
}

func TestTask5SharedIdentifierValidationAndOpaqueNamespaces(t *testing.T) {
	bad := []string{"nul\x00value", string([]byte{0xff}), "control\u0001", "format\u202e"}
	for _, value := range bad {
		if _, err := policyengine.NewCaller(value, nil); err == nil {
			t.Fatalf("NewCaller(%q) accepted unsafe identifier", value)
		}
		if _, err := policyengine.NewCaller("caller", map[string]string{"key": value}); err == nil {
			t.Fatalf("caller attribute value %q accepted", value)
		}
		if _, err := policyengine.NewSelector(value, ""); err == nil {
			t.Fatalf("selector slot %q accepted", value)
		}
		if _, err := policyengine.NewPublishRequest(value, "policy.cdr", []byte("entity user {}")); err == nil {
			t.Fatalf("namespace %q accepted", value)
		}
		if _, err := policyengine.NewComponentStatus(value, policyengine.ComponentReady, "READY"); err == nil {
			t.Fatalf("component name %q accepted", value)
		}
	}

	if _, err := policyengine.NewGrant("ac*me", []policyengine.Capability{policyengine.CapabilityPolicyRead}); err == nil {
		t.Fatal("non-trailing wildcard namespace pattern accepted")
	}
	grant, err := policyengine.NewGrant("acme*", []policyengine.Capability{policyengine.CapabilityPolicyRead})
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range bad {
		if grant.MatchesNamespace(namespace) {
			t.Fatalf("grant matched invalid namespace %q", namespace)
		}
	}

	composed := "caf\u00e9"
	decomposed := "cafe\u0301"
	exact, err := policyengine.NewGrant(composed, []policyengine.Capability{policyengine.CapabilityPolicyRead})
	if err != nil {
		t.Fatal(err)
	}
	if !exact.MatchesNamespace(composed) || exact.MatchesNamespace(decomposed) {
		t.Fatal("opaque namespace matching normalized byte-distinct values")
	}

	if _, err := policyengine.ParseRevisionID(strings.Repeat("A", 64)); err == nil {
		t.Fatal("uppercase revision ID accepted")
	}

	unsafe := "bad\u202e"
	if _, err := policyengine.NewBatchCheckItem(dsl.EntityRef{Type: unsafe, ID: "alice"}, dsl.EntityRef{Type: "doc", ID: "one"}, "read", nil); err == nil {
		t.Fatal("unsafe DSL entity type accepted")
	}
	if _, err := policyengine.NewBatchCheckItem(dsl.EntityRef{Type: "user", ID: "alice"}, dsl.EntityRef{Type: "doc", ID: "one"}, unsafe, nil); err == nil {
		t.Fatal("unsafe action accepted")
	}
	if _, err := policyengine.NewAttribute(dsl.EntityRef{Type: "user", ID: "alice"}, unsafe, policyengine.NewNullValue()); err == nil {
		t.Fatal("unsafe attribute name accepted")
	}
	if _, err := policyengine.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "doc", ID: "one"}, Relation: unsafe, Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}, nil); err == nil {
		t.Fatal("unsafe tuple relation accepted")
	}
	if _, err := policyengine.NewListEventsRequest("acme", unsafe, 1); err == nil {
		t.Fatal("unsafe cursor accepted")
	}
	if _, err := policyengine.NewDecisionDelivery(policyengine.DecisionDeliveryAccepted, unsafe); err == nil {
		t.Fatal("unsafe reason code accepted")
	}
}

func TestTask5CanonicalCollectionsRejectConflictsAndDedupeExactFacts(t *testing.T) {
	entity := dsl.EntityRef{Type: "user", ID: "alice"}
	one, _ := policyengine.NewAttribute(entity, "level", mustStringValue(t, "one"))
	two, _ := policyengine.NewAttribute(entity, "level", mustStringValue(t, "two"))
	if _, err := policyengine.NewContextualData(nil, []policyengine.Attribute{two, one}); err == nil {
		t.Fatal("reversed conflicting contextual attributes accepted")
	}
	contextual, err := policyengine.NewContextualData(nil, []policyengine.Attribute{one, one})
	if err != nil || len(contextual.Attributes()) != 1 {
		t.Fatalf("exact contextual attribute duplicates not deduped: %#v, %v", contextual.Attributes(), err)
	}

	tupleValue := dsl.Tuple{Resource: dsl.EntityRef{Type: "doc", ID: "one"}, Relation: "viewer", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}
	expiryA := time.Now().UTC().Truncate(time.Second)
	expiryB := expiryA.Add(time.Second)
	tupleA, _ := policyengine.NewRelationshipTuple(tupleValue, &expiryA)
	tupleB, _ := policyengine.NewRelationshipTuple(tupleValue, &expiryB)
	if _, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tupleB, tupleA}, nil); err == nil {
		t.Fatal("same tuple with differing expiry accepted")
	}
	contextual, err = policyengine.NewContextualData([]policyengine.RelationshipTuple{tupleA, tupleA}, nil)
	if err != nil || len(contextual.Tuples()) != 1 {
		t.Fatalf("exact contextual tuple duplicates not deduped: %#v, %v", contextual.Tuples(), err)
	}

	tupleKey, _ := policyengine.NewTupleKey(tupleValue)
	base := policyengine.WriteDataRequestInput{Namespace: "acme", ValidationRevisionID: testRevisionID(t), IdempotencyKey: "write"}
	base.TupleWrites = []policyengine.RelationshipTuple{tupleA, tupleA}
	request, err := policyengine.NewWriteDataRequest(base)
	if err != nil || len(request.TupleWrites()) != 1 {
		t.Fatalf("duplicate tuple writes not deduped: %#v, %v", request.TupleWrites(), err)
	}
	base.TupleDeletes = []policyengine.TupleKey{tupleKey}
	if _, err := policyengine.NewWriteDataRequest(base); err == nil {
		t.Fatal("tuple write/delete intersection accepted")
	}

	base = policyengine.WriteDataRequestInput{Namespace: "acme", ValidationRevisionID: testRevisionID(t), IdempotencyKey: "write", AttributeWrites: []policyengine.Attribute{one, two}}
	if _, err := policyengine.NewWriteDataRequest(base); err == nil {
		t.Fatal("conflicting duplicate attribute writes accepted")
	}
	attributeKey, _ := policyengine.NewAttributeKey(entity, "level")
	base.AttributeWrites = []policyengine.Attribute{one, one}
	base.AttributeDeletes = []policyengine.AttributeKey{attributeKey, attributeKey}
	if _, err := policyengine.NewWriteDataRequest(base); err == nil {
		t.Fatal("attribute write/delete intersection accepted")
	}

	grant, _ := policyengine.NewGrant("acme*", []policyengine.Capability{policyengine.CapabilityPolicyRead})
	if _, err := policyengine.NewCallerAuthorization([]policyengine.Grant{grant, grant}); err == nil {
		t.Fatal("duplicate namespace grant pattern accepted")
	}
	componentA, _ := policyengine.NewComponentStatus("store", policyengine.ComponentReady, "READY")
	componentB, _ := policyengine.NewComponentStatus("store", policyengine.ComponentUnavailable, "DOWN")
	if _, err := policyengine.NewStatusResponse(false, []policyengine.ComponentStatus{componentB, componentA}); err == nil {
		t.Fatal("duplicate component names accepted")
	}

	if _, err := policyengine.NewAttribute(dsl.EntityRef{Type: "a", ID: "b\x00c"}, "d", policyengine.NewNullValue()); err == nil {
		t.Fatal("NUL key-collision component accepted")
	}
}
