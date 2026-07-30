package conformance_test

import (
	"bytes"
	"testing"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestWriteDataFingerprintIsCanonicalScopedAndPrivacySafe(t *testing.T) {
	t.Parallel()

	first := mustWriteRequest(t, "tenant-a", "idem-a", "value-a")
	identical := mustWriteRequest(t, "tenant-a", "idem-a", "value-a")
	changed := mustWriteRequest(t, "tenant-a", "idem-a", "value-b")
	firstScope, firstFingerprint, err := store.FingerprintWriteData(first)
	if err != nil {
		t.Fatalf("FingerprintWriteData(first) error = %v", err)
	}
	identicalScope, identicalFingerprint, err := store.FingerprintWriteData(identical)
	if err != nil {
		t.Fatalf("FingerprintWriteData(identical) error = %v", err)
	}
	_, changedFingerprint, err := store.FingerprintWriteData(changed)
	if err != nil {
		t.Fatalf("FingerprintWriteData(changed) error = %v", err)
	}
	if firstScope != identicalScope || !bytes.Equal(firstFingerprint.Bytes(), identicalFingerprint.Bytes()) {
		t.Fatal("identical canonical writes produced different scope or fingerprint")
	}
	if bytes.Equal(firstFingerprint.Bytes(), changedFingerprint.Bytes()) {
		t.Fatal("changed typed payload produced identical fingerprint")
	}
	if firstScope.Namespace() != "tenant-a" || firstScope.Operation() != store.IdempotencyWriteData || firstScope.Key() != "idem-a" {
		t.Fatalf("scope = %v", firstScope)
	}
	returned := firstFingerprint.Bytes()
	returned[0] ^= 0xff
	if bytes.Equal(returned, firstFingerprint.Bytes()) {
		t.Fatal("Fingerprint.Bytes returned aliased storage")
	}
	assertRedacted(t, firstScope, "tenant-a")
	assertRedacted(t, firstFingerprint, string(firstFingerprint.Bytes()))
}

func TestIdempotencyRecordRejectsZeroAndCopiesOriginalResponse(t *testing.T) {
	t.Parallel()

	request := mustWriteRequest(t, "tenant-a", "idem-a", "value-a")
	scope, fingerprint, err := store.FingerprintWriteData(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := policyengine.NewWriteDataResponse(7, false)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.NewIdempotencyRecord(scope, fingerprint, response)
	if err != nil {
		t.Fatalf("NewIdempotencyRecord() error = %v", err)
	}
	if record.Response().Generation() != 7 || record.Scope() != scope || !bytes.Equal(record.Fingerprint().Bytes(), fingerprint.Bytes()) {
		t.Fatalf("record = %v", record)
	}
	if _, err := store.NewIdempotencyRecord(store.IdempotencyScope{}, fingerprint, response); err == nil {
		t.Fatal("zero scope error = nil")
	}
	if _, err := store.NewIdempotencyRecord(scope, store.IdempotencyFingerprint{}, response); err == nil {
		t.Fatal("zero fingerprint error = nil")
	}
}

func mustWriteRequest(t *testing.T, namespace, key, valueText string) policyengine.WriteDataRequest {
	t.Helper()
	value, err := policyengine.NewStringValue(valueText)
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := policyengine.NewAttribute(dsl.EntityRef{Type: "document", ID: "doc"}, "classification", value)
	if err != nil {
		t.Fatal(err)
	}
	input := policyengine.WriteDataRequestInput{
		Namespace:            namespace,
		ValidationRevisionID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ExpectedGeneration:   0,
		IdempotencyKey:       key,
		AttributeWrites:      []policyengine.Attribute{attribute},
	}
	request, err := policyengine.NewWriteDataRequest(input)
	if err != nil {
		t.Fatalf("NewWriteDataRequest() error = %v", err)
	}
	return request
}
