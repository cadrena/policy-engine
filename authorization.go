package policyengine

import (
	"crypto/sha256"
	"time"

	"github.com/cadrena/dsl"
)

// Decision is a successful public policy outcome, never an engine error.
type Decision uint8

const (
	// DecisionAllow permits the requested action.
	DecisionAllow Decision = iota + 1
	// DecisionDeny rejects the requested action.
	DecisionDeny
	// DecisionRequireApproval requires external approval before execution.
	DecisionRequireApproval
)

// String returns the stable uppercase public decision name.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionDeny:
		return "DENY"
	case DecisionRequireApproval:
		return "REQUIRE_APPROVAL"
	default:
		return "INVALID"
	}
}

func (d Decision) valid() bool {
	return d >= DecisionAllow && d <= DecisionRequireApproval
}

// CheckRequestInput contains sensitive construction-only values copied by
// NewCheckRequest. Its default formatting and structured logging are redacted.
type CheckRequestInput struct {
	Namespace          string
	Selector           Selector
	Subject            dsl.EntityRef
	Resource           dsl.EntityRef
	Action             string
	Arguments          map[string]Value
	ContextualData     ContextualData
	ApprovalEvidence   []byte
	DelegationEvidence []byte
	MinimumGeneration  uint64
}

// CheckRequest is one immutable transport-neutral authorization check.
type CheckRequest struct {
	namespace          string
	selector           Selector
	subject            dsl.EntityRef
	resource           dsl.EntityRef
	action             string
	arguments          map[string]Value
	contextualData     ContextualData
	approvalEvidence   []byte
	delegationEvidence []byte
	minimumGeneration  uint64
}

// NewCheckRequest validates and defensively copies one authorization check.
func NewCheckRequest(input CheckRequestInput) (CheckRequest, error) {
	if len(input.Arguments) > MaxArgumentItems || len(input.ApprovalEvidence) > MaxEvidenceBytes || len(input.DelegationEvidence) > MaxEvidenceBytes {
		return CheckRequest{}, resourceExhausted()
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addCheckRequestCost(&byteBudget, input); err != nil {
		return CheckRequest{}, err
	}
	if !input.Selector.valid() || !input.ContextualData.valid() {
		return CheckRequest{}, invalidArgument("check request is incomplete")
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return CheckRequest{}, err
	}
	if err := validateEntityRef(input.Subject); err != nil {
		return CheckRequest{}, err
	}
	if err := validateEntityRef(input.Resource); err != nil {
		return CheckRequest{}, err
	}
	if err := validateIdentifier(input.Action); err != nil {
		return CheckRequest{}, err
	}
	if err := validateArguments(input.Arguments); err != nil {
		return CheckRequest{}, err
	}
	return CheckRequest{
		namespace:          input.Namespace,
		selector:           input.Selector,
		subject:            input.Subject,
		resource:           input.Resource,
		action:             input.Action,
		arguments:          cloneMap(input.Arguments),
		contextualData:     cloneContextualData(input.ContextualData),
		approvalEvidence:   cloneBytes(input.ApprovalEvidence),
		delegationEvidence: cloneBytes(input.DelegationEvidence),
		minimumGeneration:  input.MinimumGeneration,
	}, nil
}

// Namespace returns the opaque evaluation namespace.
func (r CheckRequest) Namespace() string { return r.namespace }

// Selector returns the exactly-one policy selector.
func (r CheckRequest) Selector() Selector { return r.selector }

// Subject returns the checked subject.
func (r CheckRequest) Subject() dsl.EntityRef { return r.subject }

// Resource returns the checked resource.
func (r CheckRequest) Resource() dsl.EntityRef { return r.resource }

// Action returns the artifact-declared action name.
func (r CheckRequest) Action() string { return r.action }

// Arguments returns a defensive copy of typed action arguments.
func (r CheckRequest) Arguments() map[string]Value { return cloneMap(r.arguments) }

// ContextualData returns a defensive copy of trusted additive contextual facts.
func (r CheckRequest) ContextualData() ContextualData { return cloneContextualData(r.contextualData) }

// ApprovalEvidence returns a defensive copy of opaque approval evidence.
func (r CheckRequest) ApprovalEvidence() []byte { return cloneBytes(r.approvalEvidence) }

// DelegationEvidence returns a defensive copy of opaque delegation evidence.
func (r CheckRequest) DelegationEvidence() []byte { return cloneBytes(r.delegationEvidence) }

// MinimumGeneration returns the requested authorization-data lower bound.
func (r CheckRequest) MinimumGeneration() uint64 { return r.minimumGeneration }

func (r CheckRequest) valid() bool {
	if !validNamespace(r.namespace) || !r.selector.valid() || validateEntityRef(r.subject) != nil || validateEntityRef(r.resource) != nil || !validIdentifier(r.action) || validateArguments(r.arguments) != nil || !r.contextualData.valid() || len(r.approvalEvidence) > MaxEvidenceBytes || len(r.delegationEvidence) > MaxEvidenceBytes {
		return false
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	return addCheckRequestCost(&byteBudget, CheckRequestInput{
		Namespace:          r.namespace,
		Selector:           r.selector,
		Subject:            r.subject,
		Resource:           r.resource,
		Action:             r.action,
		Arguments:          r.arguments,
		ContextualData:     r.contextualData,
		ApprovalEvidence:   r.approvalEvidence,
		DelegationEvidence: r.delegationEvidence,
		MinimumGeneration:  r.minimumGeneration,
	}) == nil
}

// DecisionResultInput contains compact metadata copied by NewDecisionResult.
type DecisionResultInput struct {
	Decision              Decision
	DecisionID            string
	ReasonCode            string
	RevisionID            string
	SlotGeneration        uint64
	DataGeneration        uint64
	EvaluatedAt           time.Time
	Requirements          []string
	ApprovalBindingDigest [sha256.Size]byte
	UsedContextualData    bool
	UsedApproval          bool
	UsedDelegation        bool
}

// DecisionResult is one immutable successful policy result with compact metadata.
type DecisionResult struct {
	validResult           bool
	decision              Decision
	decisionID            string
	reasonCode            string
	revisionID            string
	slotGeneration        uint64
	dataGeneration        uint64
	evaluatedAt           time.Time
	requirements          []string
	approvalBindingDigest [sha256.Size]byte
	hasApprovalBinding    bool
	usedContextualData    bool
	usedApproval          bool
	usedDelegation        bool
}

// NewDecisionResult validates and constructs one compact policy result.
func NewDecisionResult(input DecisionResultInput) (DecisionResult, error) {
	if len(input.Requirements) > MaxVerifierOutputItems {
		return DecisionResult{}, resourceExhausted()
	}
	byteBudget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addDecisionResultCost(&byteBudget, input); err != nil {
		return DecisionResult{}, err
	}
	if !input.Decision.valid() || !validRevisionIDString(input.RevisionID) || input.EvaluatedAt.IsZero() {
		return DecisionResult{}, invalidArgument("decision result is incomplete")
	}
	if err := validateIdentifier(input.DecisionID); err != nil {
		return DecisionResult{}, err
	}
	if err := validateIdentifier(input.ReasonCode); err != nil {
		return DecisionResult{}, err
	}
	requirements, err := canonicalIdentifiers(input.Requirements, MaxVerifierOutputItems, MaxAggregateOutputBytes)
	if err != nil {
		return DecisionResult{}, err
	}
	if input.Decision != DecisionRequireApproval && len(requirements) != 0 {
		return DecisionResult{}, invalidArgument("only require-approval decisions may contain requirements")
	}
	if input.Decision == DecisionRequireApproval && len(requirements) == 0 {
		return DecisionResult{}, invalidArgument("require-approval decision requires requirements")
	}
	hasApprovalBinding := input.ApprovalBindingDigest != ([sha256.Size]byte{})
	if (input.Decision == DecisionRequireApproval) != hasApprovalBinding {
		return DecisionResult{}, invalidArgument("approval binding digest does not match decision")
	}
	return DecisionResult{
		validResult:           true,
		decision:              input.Decision,
		decisionID:            input.DecisionID,
		reasonCode:            input.ReasonCode,
		revisionID:            input.RevisionID,
		slotGeneration:        input.SlotGeneration,
		dataGeneration:        input.DataGeneration,
		evaluatedAt:           input.EvaluatedAt,
		requirements:          requirements,
		approvalBindingDigest: input.ApprovalBindingDigest,
		hasApprovalBinding:    hasApprovalBinding,
		usedContextualData:    input.UsedContextualData,
		usedApproval:          input.UsedApproval,
		usedDelegation:        input.UsedDelegation,
	}, nil
}

// Decision returns ALLOW, DENY, or REQUIRE_APPROVAL.
func (r DecisionResult) Decision() Decision { return r.decision }

// DecisionID returns the privacy-safe decision identifier.
func (r DecisionResult) DecisionID() string { return r.decisionID }

// ReasonCode returns the stable compact reason code.
func (r DecisionResult) ReasonCode() string { return r.reasonCode }

// RevisionID returns the exact pinned policy revision.
func (r DecisionResult) RevisionID() string { return r.revisionID }

// SlotGeneration returns the pinned slot generation, or zero for exact selection.
func (r DecisionResult) SlotGeneration() uint64 { return r.slotGeneration }

// DataGeneration returns the exact pinned authorization-data generation.
func (r DecisionResult) DataGeneration() uint64 { return r.dataGeneration }

// EvaluatedAt returns the single time captured for evaluation.
func (r DecisionResult) EvaluatedAt() time.Time { return r.evaluatedAt }

// Requirements returns sorted unique unsatisfied approval requirement IDs.
func (r DecisionResult) Requirements() []string { return cloneSlice(r.requirements) }

// ApprovalBindingDigest returns the continuation binding for require-approval
// decisions only.
func (r DecisionResult) ApprovalBindingDigest() ([sha256.Size]byte, bool) {
	if r.decision != DecisionRequireApproval || !r.hasApprovalBinding {
		return [sha256.Size]byte{}, false
	}
	return r.approvalBindingDigest, true
}

// UsedContextualData reports whether contextual facts were evaluated.
func (r DecisionResult) UsedContextualData() bool { return r.usedContextualData }

// UsedApproval reports whether approval evidence was evaluated.
func (r DecisionResult) UsedApproval() bool { return r.usedApproval }

// UsedDelegation reports whether delegation evidence was evaluated.
func (r DecisionResult) UsedDelegation() bool { return r.usedDelegation }

func (r DecisionResult) valid() bool {
	if !r.validResult || !r.decision.valid() || !validIdentifier(r.decisionID) || !validIdentifier(r.reasonCode) || !validRevisionIDString(r.revisionID) || r.evaluatedAt.IsZero() {
		return false
	}
	if !validCanonicalIdentifiers(r.requirements, MaxVerifierOutputItems, MaxAggregateOutputBytes) {
		return false
	}
	hasApprovalDigest := r.approvalBindingDigest != ([sha256.Size]byte{})
	if r.hasApprovalBinding != hasApprovalDigest || (r.decision == DecisionRequireApproval) != r.hasApprovalBinding {
		return false
	}
	byteBudget := budgetCounter{max: MaxAggregateOutputBytes}
	if addDecisionResultValueCost(&byteBudget, r) != nil {
		return false
	}
	return (r.decision == DecisionRequireApproval) == (len(r.requirements) > 0)
}

// CheckResponse reports one policy decision and pinned metadata.
type CheckResponse struct {
	selector Selector
	result   DecisionResult
}

// NewCheckResponse validates and constructs a response bound to its originating request.
func NewCheckResponse(request CheckRequest, result DecisionResult) (CheckResponse, error) {
	if !request.valid() || !result.valid() {
		return CheckResponse{}, invalidArgument("check response requires a valid decision result")
	}
	if !selectorMatchesResult(request.selector, result) {
		return CheckResponse{}, invalidArgument("check response snapshot does not match selector")
	}
	return CheckResponse{selector: request.selector, result: result}, nil
}

// Result returns the immutable compact policy result.
func (r CheckResponse) Result() DecisionResult { return r.result }

func (r CheckResponse) valid() bool {
	return r.selector.valid() && r.result.valid() && selectorMatchesResult(r.selector, r.result)
}

// BatchCheckItem is one immutable item in a snapshot-pinned batch.
type BatchCheckItem struct {
	subject   dsl.EntityRef
	resource  dsl.EntityRef
	action    string
	arguments map[string]Value
}

// NewBatchCheckItem validates and copies one batch item.
func NewBatchCheckItem(subject, resource dsl.EntityRef, action string, arguments map[string]Value) (BatchCheckItem, error) {
	if len(arguments) > MaxArgumentItems {
		return BatchCheckItem{}, resourceExhausted()
	}
	raw := BatchCheckItem{subject: subject, resource: resource, action: action, arguments: arguments}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addBatchItemCost(&byteBudget, raw); err != nil {
		return BatchCheckItem{}, err
	}
	if err := validateEntityRef(subject); err != nil {
		return BatchCheckItem{}, err
	}
	if err := validateEntityRef(resource); err != nil {
		return BatchCheckItem{}, err
	}
	if err := validateIdentifier(action); err != nil {
		return BatchCheckItem{}, err
	}
	if err := validateArguments(arguments); err != nil {
		return BatchCheckItem{}, err
	}
	return BatchCheckItem{subject: subject, resource: resource, action: action, arguments: cloneMap(arguments)}, nil
}

// Subject returns the checked subject.
func (i BatchCheckItem) Subject() dsl.EntityRef { return i.subject }

// Resource returns the checked resource.
func (i BatchCheckItem) Resource() dsl.EntityRef { return i.resource }

// Action returns the artifact-declared action name.
func (i BatchCheckItem) Action() string { return i.action }

// Arguments returns a defensive copy of typed action arguments.
func (i BatchCheckItem) Arguments() map[string]Value { return cloneMap(i.arguments) }

func (i BatchCheckItem) valid() bool {
	if validateEntityRef(i.subject) != nil || validateEntityRef(i.resource) != nil || !validIdentifier(i.action) || validateArguments(i.arguments) != nil {
		return false
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	return addBatchItemCost(&byteBudget, i) == nil
}

// BatchCheckRequestInput contains sensitive construction-only shared values
// copied by NewBatchCheckRequest. Default formatting and logging are redacted.
type BatchCheckRequestInput struct {
	Namespace          string
	Selector           Selector
	Items              []BatchCheckItem
	ContextualData     ContextualData
	ApprovalEvidence   []byte
	DelegationEvidence []byte
	MinimumGeneration  uint64
}

// BatchCheckRequest is an immutable snapshot-pinned group of checks.
type BatchCheckRequest struct {
	namespace          string
	selector           Selector
	items              []BatchCheckItem
	contextualData     ContextualData
	approvalEvidence   []byte
	delegationEvidence []byte
	minimumGeneration  uint64
}

// NewBatchCheckRequest validates and defensively copies a batch request.
func NewBatchCheckRequest(input BatchCheckRequestInput) (BatchCheckRequest, error) {
	if len(input.Items) > MaxBatchItems || len(input.ApprovalEvidence) > MaxEvidenceBytes || len(input.DelegationEvidence) > MaxEvidenceBytes {
		return BatchCheckRequest{}, resourceExhausted()
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addBatchRequestCost(&byteBudget, input); err != nil {
		return BatchCheckRequest{}, err
	}
	workBudget := budgetCounter{max: MaxAggregateWorkItems}
	if err := workBudget.add(contextualWorkItems(input.ContextualData)); err != nil {
		return BatchCheckRequest{}, err
	}
	for _, item := range input.Items {
		if err := workBudget.add(1 + len(item.arguments)); err != nil {
			return BatchCheckRequest{}, err
		}
	}
	if !input.Selector.valid() || len(input.Items) == 0 || !input.ContextualData.valid() {
		return BatchCheckRequest{}, invalidArgument("batch check request is incomplete")
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return BatchCheckRequest{}, err
	}
	for _, item := range input.Items {
		if !item.valid() {
			return BatchCheckRequest{}, invalidArgument("batch check request contains an invalid item")
		}
	}
	items := make([]BatchCheckItem, len(input.Items))
	for index, item := range input.Items {
		item.arguments = cloneMap(item.arguments)
		items[index] = item
	}
	return BatchCheckRequest{
		namespace:          input.Namespace,
		selector:           input.Selector,
		items:              items,
		contextualData:     cloneContextualData(input.ContextualData),
		approvalEvidence:   cloneBytes(input.ApprovalEvidence),
		delegationEvidence: cloneBytes(input.DelegationEvidence),
		minimumGeneration:  input.MinimumGeneration,
	}, nil
}

// Namespace returns the single opaque batch namespace.
func (r BatchCheckRequest) Namespace() string { return r.namespace }

// Selector returns the single exactly-one shared selector.
func (r BatchCheckRequest) Selector() Selector { return r.selector }

// Items returns a deep defensive copy preserving caller order.
func (r BatchCheckRequest) Items() []BatchCheckItem {
	items := make([]BatchCheckItem, len(r.items))
	for index, item := range r.items {
		item.arguments = cloneMap(item.arguments)
		items[index] = item
	}
	return items
}

// ContextualData returns a defensive copy of shared additive contextual facts.
func (r BatchCheckRequest) ContextualData() ContextualData {
	return cloneContextualData(r.contextualData)
}

// ApprovalEvidence returns a defensive copy of shared opaque approval evidence.
func (r BatchCheckRequest) ApprovalEvidence() []byte { return cloneBytes(r.approvalEvidence) }

// DelegationEvidence returns a defensive copy of shared opaque delegation evidence.
func (r BatchCheckRequest) DelegationEvidence() []byte { return cloneBytes(r.delegationEvidence) }

// MinimumGeneration returns the shared authorization-data lower bound.
func (r BatchCheckRequest) MinimumGeneration() uint64 { return r.minimumGeneration }

func (r BatchCheckRequest) valid() bool {
	if !validNamespace(r.namespace) || !r.selector.valid() || len(r.items) == 0 || len(r.items) > MaxBatchItems ||
		!r.contextualData.valid() || len(r.approvalEvidence) > MaxEvidenceBytes || len(r.delegationEvidence) > MaxEvidenceBytes {
		return false
	}
	input := BatchCheckRequestInput{
		Namespace:          r.namespace,
		Selector:           r.selector,
		Items:              r.items,
		ContextualData:     r.contextualData,
		ApprovalEvidence:   r.approvalEvidence,
		DelegationEvidence: r.delegationEvidence,
		MinimumGeneration:  r.minimumGeneration,
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if addBatchRequestCost(&byteBudget, input) != nil {
		return false
	}
	workBudget := budgetCounter{max: MaxAggregateWorkItems}
	if workBudget.add(contextualWorkItems(r.contextualData)) != nil {
		return false
	}
	for _, item := range r.items {
		if !item.valid() || workBudget.add(1+len(item.arguments)) != nil {
			return false
		}
	}
	return true
}

// BatchCheckResponse reports an authoritative complete batch of decisions.
type BatchCheckResponse struct {
	selector Selector
	results  []DecisionResult
}

// NewBatchCheckResponse validates one result per originating request item and
// enforces a single pinned revision, slot generation, data generation, and time.
func NewBatchCheckResponse(request BatchCheckRequest, results []DecisionResult) (BatchCheckResponse, error) {
	if len(results) > MaxBatchItems {
		return BatchCheckResponse{}, resourceExhausted()
	}
	if !request.valid() || len(results) != len(request.items) {
		return BatchCheckResponse{}, invalidArgument("batch response cardinality does not match request")
	}
	byteBudget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addBatchResponseCost(&byteBudget, results); err != nil {
		return BatchCheckResponse{}, err
	}
	first := results[0]
	for _, result := range results {
		if !result.valid() {
			return BatchCheckResponse{}, invalidArgument("batch response contains an invalid decision result")
		}
		if result.revisionID != first.revisionID || result.slotGeneration != first.slotGeneration || result.dataGeneration != first.dataGeneration || !result.evaluatedAt.Equal(first.evaluatedAt) {
			return BatchCheckResponse{}, invalidArgument("batch response contains mixed snapshots")
		}
	}
	if !selectorMatchesResult(request.selector, first) {
		return BatchCheckResponse{}, invalidArgument("batch response slot generation does not match selector")
	}
	return BatchCheckResponse{selector: request.selector, results: cloneSlice(results)}, nil
}

// Results returns a defensive copy in request item order.
func (r BatchCheckResponse) Results() []DecisionResult { return cloneSlice(r.results) }

func (r BatchCheckResponse) valid() bool {
	if !r.selector.valid() || len(r.results) == 0 || len(r.results) > MaxBatchItems {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if addBatchResponseCost(&budget, r.results) != nil {
		return false
	}
	first := r.results[0]
	for _, result := range r.results {
		if !result.valid() || result.revisionID != first.revisionID || result.slotGeneration != first.slotGeneration || result.dataGeneration != first.dataGeneration || !result.evaluatedAt.Equal(first.evaluatedAt) {
			return false
		}
	}
	return selectorMatchesResult(r.selector, first)
}

// ExplainRequest requests a privileged redacted explanation of one check.
type ExplainRequest struct {
	check CheckRequest
}

// NewExplainRequest validates and constructs a separate explanation request.
func NewExplainRequest(check CheckRequest) (ExplainRequest, error) {
	if !check.valid() {
		return ExplainRequest{}, invalidArgument("explain request requires a valid check")
	}
	check.arguments = cloneMap(check.arguments)
	check.contextualData = cloneContextualData(check.contextualData)
	check.approvalEvidence = cloneBytes(check.approvalEvidence)
	check.delegationEvidence = cloneBytes(check.delegationEvidence)
	return ExplainRequest{check: check}, nil
}

// Check returns a defensive copy of the underlying immutable check request.
func (r ExplainRequest) Check() CheckRequest {
	check := r.check
	check.arguments = cloneMap(check.arguments)
	check.contextualData = cloneContextualData(check.contextualData)
	check.approvalEvidence = cloneBytes(check.approvalEvidence)
	check.delegationEvidence = cloneBytes(check.delegationEvidence)
	return check
}

func (r ExplainRequest) valid() bool { return r.check.valid() }

// ExplainStep is one redacted deterministic explanation step.
type ExplainStep struct {
	schemaPath string
	operator   string
	outcome    bool
}

// NewExplainStep validates and constructs a privacy-safe explanation step.
func NewExplainStep(schemaPath, operator string, outcome bool) (ExplainStep, error) {
	if err := validateIdentifier(schemaPath); err != nil {
		return ExplainStep{}, err
	}
	if err := validateIdentifier(operator); err != nil {
		return ExplainStep{}, err
	}
	return ExplainStep{schemaPath: schemaPath, operator: operator, outcome: outcome}, nil
}

// SchemaPath returns the stable artifact schema path.
func (s ExplainStep) SchemaPath() string { return s.schemaPath }

// Operator returns the stable artifact operator name.
func (s ExplainStep) Operator() string { return s.operator }

// Outcome returns the boolean result without dynamic input values.
func (s ExplainStep) Outcome() bool { return s.outcome }

func (s ExplainStep) valid() bool {
	return validIdentifier(s.schemaPath) && validIdentifier(s.operator)
}

// ExplainResponse reports a decision and redacted explanation metadata.
type ExplainResponse struct {
	selector Selector
	result   DecisionResult
	steps    []ExplainStep
}

// NewExplainResponse validates and copies an explanation bound to its originating request.
func NewExplainResponse(request ExplainRequest, result DecisionResult, steps []ExplainStep) (ExplainResponse, error) {
	if len(steps) > MaxExplainSteps {
		return ExplainResponse{}, resourceExhausted()
	}
	byteBudget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addExplainResponseCost(&byteBudget, result, steps); err != nil {
		return ExplainResponse{}, err
	}
	if !request.check.valid() || !result.valid() {
		return ExplainResponse{}, invalidArgument("explain response requires a valid decision result")
	}
	if !selectorMatchesResult(request.check.selector, result) {
		return ExplainResponse{}, invalidArgument("explain response snapshot does not match selector")
	}
	for _, step := range steps {
		if !step.valid() {
			return ExplainResponse{}, invalidArgument("explain response contains an invalid step")
		}
	}
	return ExplainResponse{selector: request.check.selector, result: result, steps: cloneSlice(steps)}, nil
}

// Result returns the same immutable compact decision metadata as Check.
func (r ExplainResponse) Result() DecisionResult { return r.result }

// Steps returns a defensive copy of redacted deterministic explanation steps.
func (r ExplainResponse) Steps() []ExplainStep { return cloneSlice(r.steps) }

func (r ExplainResponse) valid() bool {
	if !r.selector.valid() || !r.result.valid() || !selectorMatchesResult(r.selector, r.result) || len(r.steps) > MaxExplainSteps {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if addExplainResponseCost(&budget, r.result, r.steps) != nil {
		return false
	}
	for _, step := range r.steps {
		if !step.valid() {
			return false
		}
	}
	return true
}

func selectorMatchesResult(selector Selector, result DecisionResult) bool {
	exactRevision, exact := selector.ExactRevision()
	if exact {
		return result.slotGeneration == 0 && result.revisionID == exactRevision
	}
	return selector.valid() && result.slotGeneration > 0
}

func cloneMap[K comparable, V any](value map[K]V) map[K]V {
	if len(value) == 0 {
		return map[K]V{}
	}
	cloned := make(map[K]V, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func cloneContextualData(value ContextualData) ContextualData {
	return ContextualData{tuples: cloneSlice(value.tuples), attributes: cloneSlice(value.attributes)}
}
