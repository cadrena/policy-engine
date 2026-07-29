package policyengine

import (
	"context"
	"time"
)

// ApprovalVerificationRequest contains exact requirements and opaque evidence.
type ApprovalVerificationRequest struct {
	binding        EvidenceBinding
	requirementIDs []string
	evidence       []byte
}

// NewApprovalVerificationRequest validates, sorts, and copies verifier input.
func NewApprovalVerificationRequest(binding EvidenceBinding, requirementIDs []string, evidence []byte) (ApprovalVerificationRequest, error) {
	if len(requirementIDs) > MaxVerifierOutputItems || len(evidence) > MaxEvidenceBytes {
		return ApprovalVerificationRequest{}, resourceExhausted()
	}
	if len(requirementIDs) == 0 || len(evidence) == 0 {
		return ApprovalVerificationRequest{}, invalidArgument("approval verification requires bounded requirements and evidence")
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addApprovalVerificationRequestCost(&byteBudget, binding, requirementIDs, evidence); err != nil {
		return ApprovalVerificationRequest{}, err
	}
	if !binding.valid() {
		return ApprovalVerificationRequest{}, invalidArgument("approval verification requires bounded requirements and evidence")
	}
	requirements, err := canonicalIdentifiers(requirementIDs, MaxVerifierOutputItems, MaxVerifierOutputBytes)
	if err != nil {
		return ApprovalVerificationRequest{}, err
	}
	return ApprovalVerificationRequest{binding: binding, requirementIDs: requirements, evidence: cloneBytes(evidence)}, nil
}

// Binding returns the exact immutable evaluation binding.
func (r ApprovalVerificationRequest) Binding() EvidenceBinding { return r.binding }

// RequirementIDs returns sorted unique exact approval requirements.
func (r ApprovalVerificationRequest) RequirementIDs() []string {
	return cloneSlice(r.requirementIDs)
}

// Evidence returns a defensive copy of opaque approval evidence.
func (r ApprovalVerificationRequest) Evidence() []byte { return cloneBytes(r.evidence) }

func (r ApprovalVerificationRequest) valid() bool {
	if !r.binding.valid() || len(r.requirementIDs) == 0 || !validCanonicalIdentifiers(r.requirementIDs, MaxVerifierOutputItems, MaxVerifierOutputBytes) || len(r.evidence) == 0 || len(r.evidence) > MaxEvidenceBytes {
		return false
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	return addApprovalVerificationRequestCost(&budget, r.binding, r.requirementIDs, r.evidence) == nil
}

// ApprovalVerificationResult identifies only satisfied requirement IDs.
type ApprovalVerificationResult struct {
	validResult             bool
	satisfiedRequirementIDs []string
}

// NewApprovalVerificationResult validates, sorts, and copies bounded verifier output.
func NewApprovalVerificationResult(satisfiedRequirementIDs []string) (ApprovalVerificationResult, error) {
	if len(satisfiedRequirementIDs) > MaxVerifierOutputItems {
		return ApprovalVerificationResult{}, resourceExhausted()
	}
	byteBudget := budgetCounter{max: MaxVerifierOutputBytes}
	if err := addIdentifiersCost(&byteBudget, satisfiedRequirementIDs); err != nil {
		return ApprovalVerificationResult{}, err
	}
	satisfied, err := canonicalIdentifiers(satisfiedRequirementIDs, MaxVerifierOutputItems, MaxVerifierOutputBytes)
	if err != nil {
		return ApprovalVerificationResult{}, err
	}
	return ApprovalVerificationResult{validResult: true, satisfiedRequirementIDs: satisfied}, nil
}

// SatisfiedRequirementIDs returns sorted unique satisfied requirement IDs.
func (r ApprovalVerificationResult) SatisfiedRequirementIDs() []string {
	return cloneSlice(r.satisfiedRequirementIDs)
}

func (r ApprovalVerificationResult) valid() bool {
	if !r.validResult || !validCanonicalIdentifiers(r.satisfiedRequirementIDs, MaxVerifierOutputItems, MaxVerifierOutputBytes) {
		return false
	}
	budget := budgetCounter{max: MaxVerifierOutputBytes}
	return addIdentifiersCost(&budget, r.satisfiedRequirementIDs) == nil
}

// ApprovalVerifier verifies supplied evidence against exact requirements.
type ApprovalVerifier interface {
	VerifyApproval(context.Context, ApprovalVerificationRequest) (ApprovalVerificationResult, error)
}

// DefaultApprovalVerifier returns the public reject-supplied-evidence verifier.
func DefaultApprovalVerifier() ApprovalVerifier { return rejectApprovalVerifier{} }

type rejectApprovalVerifier struct{}

func (rejectApprovalVerifier) VerifyApproval(context.Context, ApprovalVerificationRequest) (ApprovalVerificationResult, error) {
	return ApprovalVerificationResult{}, engineError(ErrorPermissionDenied)
}

// DelegationVerificationRequest contains opaque delegation evidence.
type DelegationVerificationRequest struct {
	binding  EvidenceBinding
	evidence []byte
}

// NewDelegationVerificationRequest validates and copies opaque evidence.
func NewDelegationVerificationRequest(binding EvidenceBinding, evidence []byte) (DelegationVerificationRequest, error) {
	if len(evidence) > MaxEvidenceBytes {
		return DelegationVerificationRequest{}, resourceExhausted()
	}
	if len(evidence) == 0 {
		return DelegationVerificationRequest{}, invalidArgument("delegation verification requires evidence")
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addDelegationVerificationRequestCost(&byteBudget, binding, evidence); err != nil {
		return DelegationVerificationRequest{}, err
	}
	if !binding.valid() {
		return DelegationVerificationRequest{}, invalidArgument("delegation verification requires evidence")
	}
	return DelegationVerificationRequest{binding: binding, evidence: cloneBytes(evidence)}, nil
}

// Binding returns the exact immutable evaluation binding.
func (r DelegationVerificationRequest) Binding() EvidenceBinding { return r.binding }

// Evidence returns a defensive copy of opaque delegation evidence.
func (r DelegationVerificationRequest) Evidence() []byte { return cloneBytes(r.evidence) }

func (r DelegationVerificationRequest) valid() bool {
	if !r.binding.valid() || len(r.evidence) == 0 || len(r.evidence) > MaxEvidenceBytes {
		return false
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	return addDelegationVerificationRequestCost(&budget, r.binding, r.evidence) == nil
}

// DelegationVerificationResult contains only additive typed contextual facts.
type DelegationVerificationResult struct {
	validResult    bool
	contextualData ContextualData
}

// NewDelegationVerificationResult validates and copies bounded additive facts.
func NewDelegationVerificationResult(contextualData ContextualData) (DelegationVerificationResult, error) {
	itemBudget := budgetCounter{max: MaxVerifierOutputItems}
	if err := itemBudget.add(len(contextualData.tuples)); err != nil {
		return DelegationVerificationResult{}, err
	}
	if err := itemBudget.add(len(contextualData.attributes)); err != nil {
		return DelegationVerificationResult{}, err
	}
	byteBudget := budgetCounter{max: MaxVerifierOutputBytes}
	if err := addContextualDataCost(&byteBudget, contextualData); err != nil {
		return DelegationVerificationResult{}, err
	}
	if !contextualData.valid() {
		return DelegationVerificationResult{}, invalidArgument("delegation verification result is invalid or too large")
	}
	return DelegationVerificationResult{validResult: true, contextualData: cloneContextualData(contextualData)}, nil
}

// ContextualData returns a defensive copy of additive typed facts.
func (r DelegationVerificationResult) ContextualData() ContextualData {
	return cloneContextualData(r.contextualData)
}

func (r DelegationVerificationResult) valid() bool {
	if !r.validResult || !r.contextualData.valid() {
		return false
	}
	itemBudget := budgetCounter{max: MaxVerifierOutputItems}
	if itemBudget.add(len(r.contextualData.tuples)) != nil || itemBudget.add(len(r.contextualData.attributes)) != nil {
		return false
	}
	byteBudget := budgetCounter{max: MaxVerifierOutputBytes}
	return addContextualDataCost(&byteBudget, r.contextualData) == nil
}

// DelegationVerifier verifies evidence and may return only additive contextual facts.
type DelegationVerifier interface {
	VerifyDelegation(context.Context, DelegationVerificationRequest) (DelegationVerificationResult, error)
}

// DefaultDelegationVerifier returns the public reject-supplied-evidence verifier.
func DefaultDelegationVerifier() DelegationVerifier { return rejectDelegationVerifier{} }

type rejectDelegationVerifier struct{}

func (rejectDelegationVerifier) VerifyDelegation(context.Context, DelegationVerificationRequest) (DelegationVerificationResult, error) {
	return DelegationVerificationResult{}, engineError(ErrorPermissionDenied)
}

// CompletedDecisionEventInput contains privacy-safe completed-decision metadata.
type CompletedDecisionEventInput struct {
	Decision           Decision
	ReasonCode         string
	RevisionID         string
	SlotGeneration     uint64
	DataGeneration     uint64
	CompletedAt        time.Time
	UsedContextualData bool
	UsedApproval       bool
	UsedDelegation     bool
}

// CompletedDecisionEvent is privacy-safe best-effort sink metadata.
// It intentionally omits caller, namespace, action, resource, arguments, facts,
// attributes, tuples, evidence, tokens, and explanation values.
type CompletedDecisionEvent struct {
	validEvent         bool
	decision           Decision
	reasonCode         string
	revisionID         string
	slotGeneration     uint64
	dataGeneration     uint64
	completedAt        time.Time
	usedContextualData bool
	usedApproval       bool
	usedDelegation     bool
}

// NewCompletedDecisionEvent validates privacy-safe completed-decision metadata.
func NewCompletedDecisionEvent(input CompletedDecisionEventInput) (CompletedDecisionEvent, error) {
	if !input.Decision.valid() || !validRevisionIDString(input.RevisionID) || input.CompletedAt.IsZero() {
		return CompletedDecisionEvent{}, invalidArgument("completed decision event is incomplete")
	}
	if err := validateIdentifier(input.ReasonCode); err != nil {
		return CompletedDecisionEvent{}, err
	}
	return CompletedDecisionEvent{
		validEvent:         true,
		decision:           input.Decision,
		reasonCode:         input.ReasonCode,
		revisionID:         input.RevisionID,
		slotGeneration:     input.SlotGeneration,
		dataGeneration:     input.DataGeneration,
		completedAt:        input.CompletedAt,
		usedContextualData: input.UsedContextualData,
		usedApproval:       input.UsedApproval,
		usedDelegation:     input.UsedDelegation,
	}, nil
}

// Decision returns the completed public policy outcome.
func (e CompletedDecisionEvent) Decision() Decision { return e.decision }

// ReasonCode returns the stable compact reason code.
func (e CompletedDecisionEvent) ReasonCode() string { return e.reasonCode }

// RevisionID returns the exact evaluated revision.
func (e CompletedDecisionEvent) RevisionID() string { return e.revisionID }

// SlotGeneration returns the pinned slot generation, or zero for exact selection.
func (e CompletedDecisionEvent) SlotGeneration() uint64 { return e.slotGeneration }

// DataGeneration returns the exact evaluated data generation.
func (e CompletedDecisionEvent) DataGeneration() uint64 { return e.dataGeneration }

// CompletedAt returns the decision completion time.
func (e CompletedDecisionEvent) CompletedAt() time.Time { return e.completedAt }

// UsedContextualData reports whether contextual facts were evaluated.
func (e CompletedDecisionEvent) UsedContextualData() bool { return e.usedContextualData }

// UsedApproval reports whether approval evidence was evaluated.
func (e CompletedDecisionEvent) UsedApproval() bool { return e.usedApproval }

// UsedDelegation reports whether delegation evidence was evaluated.
func (e CompletedDecisionEvent) UsedDelegation() bool { return e.usedDelegation }

func (e CompletedDecisionEvent) valid() bool {
	return e.validEvent && e.decision.valid() && validIdentifier(e.reasonCode) && validRevisionIDString(e.revisionID) && !e.completedAt.IsZero()
}

// DecisionDeliveryStatus is a bounded best-effort sink outcome.
type DecisionDeliveryStatus uint8

const (
	// DecisionDeliveryAccepted means the sink accepted the metadata.
	DecisionDeliveryAccepted DecisionDeliveryStatus = iota + 1
	// DecisionDeliveryDropped means the sink safely dropped the metadata.
	DecisionDeliveryDropped
	// DecisionDeliveryFailed means delivery failed without changing the decision.
	DecisionDeliveryFailed
)

// DecisionDelivery safely reports best-effort sink delivery without dynamic values.
type DecisionDelivery struct {
	status     DecisionDeliveryStatus
	reasonCode string
}

// NewDecisionDelivery validates a bounded privacy-safe sink outcome.
func NewDecisionDelivery(status DecisionDeliveryStatus, reasonCode string) (DecisionDelivery, error) {
	if status < DecisionDeliveryAccepted || status > DecisionDeliveryFailed {
		return DecisionDelivery{}, invalidArgument("decision delivery requires valid status")
	}
	if err := validateIdentifier(reasonCode); err != nil {
		return DecisionDelivery{}, err
	}
	return DecisionDelivery{status: status, reasonCode: reasonCode}, nil
}

// Status returns the bounded best-effort delivery outcome.
func (d DecisionDelivery) Status() DecisionDeliveryStatus { return d.status }

// ReasonCode returns a stable privacy-safe delivery reason.
func (d DecisionDelivery) ReasonCode() string { return d.reasonCode }

func (d DecisionDelivery) valid() bool {
	return d.status >= DecisionDeliveryAccepted && d.status <= DecisionDeliveryFailed && validIdentifier(d.reasonCode)
}

// DecisionEventSink receives privacy-safe completed-decision metadata only.
// Delivery is best effort and never changes an already completed decision.
type DecisionEventSink interface {
	RecordDecision(context.Context, CompletedDecisionEvent) DecisionDelivery
}

// DefaultDecisionEventSink returns the best-effort no-op sink.
// It reports a safe drop and is not a durable audit implementation.
func DefaultDecisionEventSink() DecisionEventSink { return noopDecisionEventSink{} }

type noopDecisionEventSink struct{}

func (noopDecisionEventSink) RecordDecision(context.Context, CompletedDecisionEvent) DecisionDelivery {
	return DecisionDelivery{status: DecisionDeliveryDropped, reasonCode: "NO_SINK"}
}

var (
	_ ApprovalVerifier   = rejectApprovalVerifier{}
	_ DelegationVerifier = rejectDelegationVerifier{}
	_ DecisionEventSink  = noopDecisionEventSink{}
)
