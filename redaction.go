package policyengine

import (
	"fmt"
	"log/slog"
)

const redactedValue = "{redacted}"

func redactedString(typeName string) string { return typeName + redactedValue }

func redactedLogValue(typeName string) slog.Value {
	return slog.GroupValue(
		slog.String("type", typeName),
		slog.Bool("redacted", true),
	)
}

func writeRedactedFormat(state fmt.State, typeName string) {
	_, _ = state.Write([]byte(redactedString(typeName)))
}

// String returns a privacy-safe caller-binding representation.
func (CallerBinding) String() string { return redactedString("CallerBinding") }

// GoString returns a privacy-safe Go-syntax representation.
func (CallerBinding) GoString() string { return redactedString("CallerBinding") }

// Format redacts the caller-binding digest for every fmt verb.
func (CallerBinding) Format(state fmt.State, _ rune) { writeRedactedFormat(state, "CallerBinding") }

// LogValue returns privacy-safe caller-binding metadata.
func (CallerBinding) LogValue() slog.Value { return redactedLogValue("CallerBinding") }

// String returns a privacy-safe evidence-fingerprint representation.
func (EvidenceFingerprint) String() string { return redactedString("EvidenceFingerprint") }

// GoString returns a privacy-safe Go-syntax representation.
func (EvidenceFingerprint) GoString() string { return redactedString("EvidenceFingerprint") }

// Format redacts the evidence fingerprint for every fmt verb.
func (EvidenceFingerprint) Format(state fmt.State, _ rune) {
	writeRedactedFormat(state, "EvidenceFingerprint")
}

// LogValue returns privacy-safe evidence-fingerprint metadata.
func (EvidenceFingerprint) LogValue() slog.Value {
	return redactedLogValue("EvidenceFingerprint")
}

// String returns a privacy-safe representation with all caller values redacted.
func (Caller) String() string { return redactedString("Caller") }

// GoString returns a privacy-safe Go-syntax representation.
func (Caller) GoString() string { return redactedString("Caller") }

// LogValue returns privacy-safe structured caller metadata.
func (Caller) LogValue() slog.Value { return redactedLogValue("Caller") }

// String returns a privacy-safe representation with policy source redacted.
func (PublishRequest) String() string { return redactedString("PublishRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (PublishRequest) GoString() string { return redactedString("PublishRequest") }

// LogValue returns privacy-safe structured publication metadata.
func (PublishRequest) LogValue() slog.Value { return redactedLogValue("PublishRequest") }

// String returns a privacy-safe representation with dynamic input values redacted.
func (CheckRequestInput) String() string { return redactedString("CheckRequestInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (CheckRequestInput) GoString() string { return redactedString("CheckRequestInput") }

// LogValue returns privacy-safe structured check-input metadata.
func (CheckRequestInput) LogValue() slog.Value { return redactedLogValue("CheckRequestInput") }

// String returns a privacy-safe representation with dynamic request values redacted.
func (CheckRequest) String() string { return redactedString("CheckRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (CheckRequest) GoString() string { return redactedString("CheckRequest") }

// LogValue returns privacy-safe structured check metadata.
func (CheckRequest) LogValue() slog.Value { return redactedLogValue("CheckRequest") }

// String returns a privacy-safe representation with item values redacted.
func (BatchCheckItem) String() string { return redactedString("BatchCheckItem") }

// GoString returns a privacy-safe Go-syntax representation.
func (BatchCheckItem) GoString() string { return redactedString("BatchCheckItem") }

// LogValue returns privacy-safe structured batch-item metadata.
func (BatchCheckItem) LogValue() slog.Value { return redactedLogValue("BatchCheckItem") }

// String returns a privacy-safe representation with batch input values redacted.
func (BatchCheckRequestInput) String() string { return redactedString("BatchCheckRequestInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (BatchCheckRequestInput) GoString() string { return redactedString("BatchCheckRequestInput") }

// LogValue returns privacy-safe structured batch-input metadata.
func (BatchCheckRequestInput) LogValue() slog.Value {
	return redactedLogValue("BatchCheckRequestInput")
}

// String returns a privacy-safe representation with batch request values redacted.
func (BatchCheckRequest) String() string { return redactedString("BatchCheckRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (BatchCheckRequest) GoString() string { return redactedString("BatchCheckRequest") }

// LogValue returns privacy-safe structured batch metadata.
func (BatchCheckRequest) LogValue() slog.Value { return redactedLogValue("BatchCheckRequest") }

// String returns a privacy-safe representation with binding values redacted.
func (EvidenceBindingInput) String() string { return redactedString("EvidenceBindingInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (EvidenceBindingInput) GoString() string { return redactedString("EvidenceBindingInput") }

// LogValue returns privacy-safe structured binding-input metadata.
func (EvidenceBindingInput) LogValue() slog.Value { return redactedLogValue("EvidenceBindingInput") }

// String returns a privacy-safe representation with binding values redacted.
func (EvidenceBinding) String() string { return redactedString("EvidenceBinding") }

// GoString returns a privacy-safe Go-syntax representation.
func (EvidenceBinding) GoString() string { return redactedString("EvidenceBinding") }

// LogValue returns privacy-safe structured evidence-binding metadata.
func (EvidenceBinding) LogValue() slog.Value { return redactedLogValue("EvidenceBinding") }

// String returns a privacy-safe representation with approval evidence redacted.
func (ApprovalVerificationRequest) String() string {
	return redactedString("ApprovalVerificationRequest")
}

// GoString returns a privacy-safe Go-syntax representation.
func (ApprovalVerificationRequest) GoString() string {
	return redactedString("ApprovalVerificationRequest")
}

// LogValue returns privacy-safe structured approval-verification metadata.
func (ApprovalVerificationRequest) LogValue() slog.Value {
	return redactedLogValue("ApprovalVerificationRequest")
}

// String returns a privacy-safe representation with delegation evidence redacted.
func (DelegationVerificationRequest) String() string {
	return redactedString("DelegationVerificationRequest")
}

// GoString returns a privacy-safe Go-syntax representation.
func (DelegationVerificationRequest) GoString() string {
	return redactedString("DelegationVerificationRequest")
}

// LogValue returns privacy-safe structured delegation-verification metadata.
func (DelegationVerificationRequest) LogValue() slog.Value {
	return redactedLogValue("DelegationVerificationRequest")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (Value) String() string { return redactedString("Value") }

// GoString returns a privacy-safe Go-syntax representation.
func (Value) GoString() string { return redactedString("Value") }

// LogValue returns privacy-safe structured metadata.
func (Value) LogValue() slog.Value { return redactedLogValue("Value") }

// String returns a privacy-safe representation with dynamic values redacted.
func (RelationshipTuple) String() string { return redactedString("RelationshipTuple") }

// GoString returns a privacy-safe Go-syntax representation.
func (RelationshipTuple) GoString() string { return redactedString("RelationshipTuple") }

// LogValue returns privacy-safe structured metadata.
func (RelationshipTuple) LogValue() slog.Value { return redactedLogValue("RelationshipTuple") }

// String returns a privacy-safe representation with dynamic values redacted.
func (TupleKey) String() string { return redactedString("TupleKey") }

// GoString returns a privacy-safe Go-syntax representation.
func (TupleKey) GoString() string { return redactedString("TupleKey") }

// LogValue returns privacy-safe structured metadata.
func (TupleKey) LogValue() slog.Value { return redactedLogValue("TupleKey") }

// String returns a privacy-safe representation with dynamic values redacted.
func (Attribute) String() string { return redactedString("Attribute") }

// GoString returns a privacy-safe Go-syntax representation.
func (Attribute) GoString() string { return redactedString("Attribute") }

// LogValue returns privacy-safe structured metadata.
func (Attribute) LogValue() slog.Value { return redactedLogValue("Attribute") }

// String returns a privacy-safe representation with dynamic values redacted.
func (AttributeKey) String() string { return redactedString("AttributeKey") }

// GoString returns a privacy-safe Go-syntax representation.
func (AttributeKey) GoString() string { return redactedString("AttributeKey") }

// LogValue returns privacy-safe structured metadata.
func (AttributeKey) LogValue() slog.Value { return redactedLogValue("AttributeKey") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ContextualData) String() string { return redactedString("ContextualData") }

// GoString returns a privacy-safe Go-syntax representation.
func (ContextualData) GoString() string { return redactedString("ContextualData") }

// LogValue returns privacy-safe structured metadata.
func (ContextualData) LogValue() slog.Value { return redactedLogValue("ContextualData") }

// String returns a privacy-safe representation with dynamic values redacted.
func (Selector) String() string { return redactedString("Selector") }

// GoString returns a privacy-safe Go-syntax representation.
func (Selector) GoString() string { return redactedString("Selector") }

// LogValue returns privacy-safe structured metadata.
func (Selector) LogValue() slog.Value { return redactedLogValue("Selector") }

// String returns a privacy-safe representation with dynamic values redacted.
func (RevisionMetadata) String() string { return redactedString("RevisionMetadata") }

// GoString returns a privacy-safe Go-syntax representation.
func (RevisionMetadata) GoString() string { return redactedString("RevisionMetadata") }

// LogValue returns privacy-safe structured metadata.
func (RevisionMetadata) LogValue() slog.Value { return redactedLogValue("RevisionMetadata") }

// String returns a privacy-safe representation with dynamic values redacted.
func (PublishResponse) String() string { return redactedString("PublishResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (PublishResponse) GoString() string { return redactedString("PublishResponse") }

// LogValue returns privacy-safe structured metadata.
func (PublishResponse) LogValue() slog.Value { return redactedLogValue("PublishResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (GetRevisionRequest) String() string { return redactedString("GetRevisionRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (GetRevisionRequest) GoString() string { return redactedString("GetRevisionRequest") }

// LogValue returns privacy-safe structured metadata.
func (GetRevisionRequest) LogValue() slog.Value { return redactedLogValue("GetRevisionRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (GetRevisionResponse) String() string { return redactedString("GetRevisionResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (GetRevisionResponse) GoString() string { return redactedString("GetRevisionResponse") }

// LogValue returns privacy-safe structured metadata.
func (GetRevisionResponse) LogValue() slog.Value { return redactedLogValue("GetRevisionResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ListRevisionsRequest) String() string { return redactedString("ListRevisionsRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (ListRevisionsRequest) GoString() string { return redactedString("ListRevisionsRequest") }

// LogValue returns privacy-safe structured metadata.
func (ListRevisionsRequest) LogValue() slog.Value { return redactedLogValue("ListRevisionsRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ListRevisionsResponse) String() string { return redactedString("ListRevisionsResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (ListRevisionsResponse) GoString() string { return redactedString("ListRevisionsResponse") }

// LogValue returns privacy-safe structured metadata.
func (ListRevisionsResponse) LogValue() slog.Value { return redactedLogValue("ListRevisionsResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ActivateRequest) String() string { return redactedString("ActivateRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (ActivateRequest) GoString() string { return redactedString("ActivateRequest") }

// LogValue returns privacy-safe structured metadata.
func (ActivateRequest) LogValue() slog.Value { return redactedLogValue("ActivateRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (Activation) String() string { return redactedString("Activation") }

// GoString returns a privacy-safe Go-syntax representation.
func (Activation) GoString() string { return redactedString("Activation") }

// LogValue returns privacy-safe structured metadata.
func (Activation) LogValue() slog.Value { return redactedLogValue("Activation") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ActivateResponse) String() string { return redactedString("ActivateResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (ActivateResponse) GoString() string { return redactedString("ActivateResponse") }

// LogValue returns privacy-safe structured metadata.
func (ActivateResponse) LogValue() slog.Value { return redactedLogValue("ActivateResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ResolveRequest) String() string { return redactedString("ResolveRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (ResolveRequest) GoString() string { return redactedString("ResolveRequest") }

// LogValue returns privacy-safe structured metadata.
func (ResolveRequest) LogValue() slog.Value { return redactedLogValue("ResolveRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ResolveResponse) String() string { return redactedString("ResolveResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (ResolveResponse) GoString() string { return redactedString("ResolveResponse") }

// LogValue returns privacy-safe structured metadata.
func (ResolveResponse) LogValue() slog.Value { return redactedLogValue("ResolveResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ListActivationHistoryRequest) String() string {
	return redactedString("ListActivationHistoryRequest")
}

// GoString returns a privacy-safe Go-syntax representation.
func (ListActivationHistoryRequest) GoString() string {
	return redactedString("ListActivationHistoryRequest")
}

// LogValue returns privacy-safe structured metadata.
func (ListActivationHistoryRequest) LogValue() slog.Value {
	return redactedLogValue("ListActivationHistoryRequest")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (ListActivationHistoryResponse) String() string {
	return redactedString("ListActivationHistoryResponse")
}

// GoString returns a privacy-safe Go-syntax representation.
func (ListActivationHistoryResponse) GoString() string {
	return redactedString("ListActivationHistoryResponse")
}

// LogValue returns privacy-safe structured metadata.
func (ListActivationHistoryResponse) LogValue() slog.Value {
	return redactedLogValue("ListActivationHistoryResponse")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (GetDataGenerationRequest) String() string {
	return redactedString("GetDataGenerationRequest")
}

// GoString returns a privacy-safe Go-syntax representation.
func (GetDataGenerationRequest) GoString() string {
	return redactedString("GetDataGenerationRequest")
}

// LogValue returns privacy-safe structured metadata.
func (GetDataGenerationRequest) LogValue() slog.Value {
	return redactedLogValue("GetDataGenerationRequest")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (WriteDataRequestInput) String() string { return redactedString("WriteDataRequestInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (WriteDataRequestInput) GoString() string { return redactedString("WriteDataRequestInput") }

// LogValue returns privacy-safe structured metadata.
func (WriteDataRequestInput) LogValue() slog.Value { return redactedLogValue("WriteDataRequestInput") }

// String returns a privacy-safe representation with dynamic values redacted.
func (WriteDataRequest) String() string { return redactedString("WriteDataRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (WriteDataRequest) GoString() string { return redactedString("WriteDataRequest") }

// LogValue returns privacy-safe structured metadata.
func (WriteDataRequest) LogValue() slog.Value { return redactedLogValue("WriteDataRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (Grant) String() string { return redactedString("Grant") }

// GoString returns a privacy-safe Go-syntax representation.
func (Grant) GoString() string { return redactedString("Grant") }

// LogValue returns privacy-safe structured metadata.
func (Grant) LogValue() slog.Value { return redactedLogValue("Grant") }

// String returns a privacy-safe representation with dynamic values redacted.
func (CallerAuthorization) String() string { return redactedString("CallerAuthorization") }

// GoString returns a privacy-safe Go-syntax representation.
func (CallerAuthorization) GoString() string { return redactedString("CallerAuthorization") }

// LogValue returns privacy-safe structured metadata.
func (CallerAuthorization) LogValue() slog.Value {
	return redactedLogValue("CallerAuthorization")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (DecisionResultInput) String() string { return redactedString("DecisionResultInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (DecisionResultInput) GoString() string { return redactedString("DecisionResultInput") }

// LogValue returns privacy-safe structured metadata.
func (DecisionResultInput) LogValue() slog.Value { return redactedLogValue("DecisionResultInput") }

// String returns a privacy-safe representation with dynamic values redacted.
func (DecisionResult) String() string { return redactedString("DecisionResult") }

// GoString returns a privacy-safe Go-syntax representation.
func (DecisionResult) GoString() string { return redactedString("DecisionResult") }

// LogValue returns privacy-safe structured metadata.
func (DecisionResult) LogValue() slog.Value { return redactedLogValue("DecisionResult") }

// String returns a privacy-safe representation with dynamic values redacted.
func (CheckResponse) String() string { return redactedString("CheckResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (CheckResponse) GoString() string { return redactedString("CheckResponse") }

// LogValue returns privacy-safe structured metadata.
func (CheckResponse) LogValue() slog.Value { return redactedLogValue("CheckResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (BatchCheckResponse) String() string { return redactedString("BatchCheckResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (BatchCheckResponse) GoString() string { return redactedString("BatchCheckResponse") }

// LogValue returns privacy-safe structured metadata.
func (BatchCheckResponse) LogValue() slog.Value { return redactedLogValue("BatchCheckResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ExplainRequest) String() string { return redactedString("ExplainRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (ExplainRequest) GoString() string { return redactedString("ExplainRequest") }

// LogValue returns privacy-safe structured metadata.
func (ExplainRequest) LogValue() slog.Value { return redactedLogValue("ExplainRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ExplainResponse) String() string { return redactedString("ExplainResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (ExplainResponse) GoString() string { return redactedString("ExplainResponse") }

// LogValue returns privacy-safe structured metadata.
func (ExplainResponse) LogValue() slog.Value { return redactedLogValue("ExplainResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ApprovalVerificationResult) String() string {
	return redactedString("ApprovalVerificationResult")
}

// GoString returns a privacy-safe Go-syntax representation.
func (ApprovalVerificationResult) GoString() string {
	return redactedString("ApprovalVerificationResult")
}

// LogValue returns privacy-safe structured metadata.
func (ApprovalVerificationResult) LogValue() slog.Value {
	return redactedLogValue("ApprovalVerificationResult")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (DelegationVerificationResult) String() string {
	return redactedString("DelegationVerificationResult")
}

// GoString returns a privacy-safe Go-syntax representation.
func (DelegationVerificationResult) GoString() string {
	return redactedString("DelegationVerificationResult")
}

// LogValue returns privacy-safe structured metadata.
func (DelegationVerificationResult) LogValue() slog.Value {
	return redactedLogValue("DelegationVerificationResult")
}

// String returns a privacy-safe representation with dynamic values redacted.
func (StateEventInput) String() string { return redactedString("StateEventInput") }

// GoString returns a privacy-safe Go-syntax representation.
func (StateEventInput) GoString() string { return redactedString("StateEventInput") }

// LogValue returns privacy-safe structured metadata.
func (StateEventInput) LogValue() slog.Value { return redactedLogValue("StateEventInput") }

// String returns a privacy-safe representation with dynamic values redacted.
func (StateEvent) String() string { return redactedString("StateEvent") }

// GoString returns a privacy-safe Go-syntax representation.
func (StateEvent) GoString() string { return redactedString("StateEvent") }

// LogValue returns privacy-safe structured metadata.
func (StateEvent) LogValue() slog.Value { return redactedLogValue("StateEvent") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ListEventsRequest) String() string { return redactedString("ListEventsRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (ListEventsRequest) GoString() string { return redactedString("ListEventsRequest") }

// LogValue returns privacy-safe structured metadata.
func (ListEventsRequest) LogValue() slog.Value { return redactedLogValue("ListEventsRequest") }

// String returns a privacy-safe representation with dynamic values redacted.
func (ListEventsResponse) String() string { return redactedString("ListEventsResponse") }

// GoString returns a privacy-safe Go-syntax representation.
func (ListEventsResponse) GoString() string { return redactedString("ListEventsResponse") }

// LogValue returns privacy-safe structured metadata.
func (ListEventsResponse) LogValue() slog.Value { return redactedLogValue("ListEventsResponse") }

// String returns a privacy-safe representation with dynamic values redacted.
func (StatusRequest) String() string { return redactedString("StatusRequest") }

// GoString returns a privacy-safe Go-syntax representation.
func (StatusRequest) GoString() string { return redactedString("StatusRequest") }

// LogValue returns privacy-safe structured metadata.
func (StatusRequest) LogValue() slog.Value { return redactedLogValue("StatusRequest") }

// String returns a privacy-safe representation of configured extension ports.
func (Options) String() string { return redactedString("Options") }

// GoString returns a privacy-safe Go-syntax representation.
func (Options) GoString() string { return redactedString("Options") }

// LogValue returns privacy-safe structured metadata.
func (Options) LogValue() slog.Value { return redactedLogValue("Options") }
