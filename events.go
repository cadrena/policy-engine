package policyengine

import (
	"sort"
	"time"
)

// StateEventKind identifies a successful local state mutation.
type StateEventKind uint8

const (
	// StateEventRevisionPublished records a newly published immutable revision.
	StateEventRevisionPublished StateEventKind = iota + 1
	// StateEventSlotActivated records a successful atomic slot activation.
	StateEventSlotActivated
	// StateEventDataWritten records a successful atomic data-generation write.
	StateEventDataWritten
)

// StateEventInput contains privacy-safe local mutation metadata.
type StateEventInput struct {
	Namespace      string
	Cursor         string
	Kind           StateEventKind
	RevisionID     string
	Slot           string
	SlotGeneration uint64
	DataGeneration uint64
	OccurredAt     time.Time
}

// StateEvent is an immutable bounded cursor-addressable local mutation record.
type StateEvent struct {
	namespace      string
	cursor         string
	kind           StateEventKind
	revisionID     string
	slot           string
	slotGeneration uint64
	dataGeneration uint64
	occurredAt     time.Time
}

// NewStateEvent validates and constructs privacy-safe local mutation metadata.
func NewStateEvent(input StateEventInput) (StateEvent, error) {
	raw := StateEvent{
		namespace: input.Namespace, cursor: input.Cursor, kind: input.Kind,
		revisionID: input.RevisionID, slot: input.Slot, slotGeneration: input.SlotGeneration,
		dataGeneration: input.DataGeneration, occurredAt: input.OccurredAt,
	}
	budget := budgetCounter{max: MaxEventPageBytes}
	if err := addStateEventCost(&budget, raw); err != nil {
		return StateEvent{}, err
	}
	if input.OccurredAt.IsZero() {
		return StateEvent{}, invalidArgument("state event requires namespace, cursor, and occurrence time")
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return StateEvent{}, err
	}
	if err := validateIdentifier(input.Cursor); err != nil {
		return StateEvent{}, err
	}
	switch input.Kind {
	case StateEventRevisionPublished:
		if !validRevisionIDString(input.RevisionID) || input.Slot != "" || input.SlotGeneration != 0 || input.DataGeneration != 0 {
			return StateEvent{}, invalidArgument("revision-published event requires a revision")
		}
	case StateEventSlotActivated:
		if !validRevisionIDString(input.RevisionID) || validateIdentifier(input.Slot) != nil || input.SlotGeneration == 0 || input.DataGeneration != 0 {
			return StateEvent{}, invalidArgument("slot-activated event requires slot, revision, and generation")
		}
	case StateEventDataWritten:
		if input.RevisionID != "" || input.Slot != "" || input.SlotGeneration != 0 || input.DataGeneration == 0 {
			return StateEvent{}, invalidArgument("data-written event requires a generation")
		}
	default:
		return StateEvent{}, invalidArgument("state event kind is invalid")
	}
	return raw, nil
}

// Namespace returns the opaque event namespace.
func (e StateEvent) Namespace() string { return e.namespace }

// Cursor returns the monotonic namespace-scoped event cursor.
func (e StateEvent) Cursor() string { return e.cursor }

// Kind returns the successful local mutation category.
func (e StateEvent) Kind() StateEventKind { return e.kind }

// RevisionID returns the affected revision when applicable.
func (e StateEvent) RevisionID() string { return e.revisionID }

// Slot returns the affected local slot when applicable.
func (e StateEvent) Slot() string { return e.slot }

// SlotGeneration returns the committed slot generation when applicable.
func (e StateEvent) SlotGeneration() uint64 { return e.slotGeneration }

// DataGeneration returns the committed data generation when applicable.
func (e StateEvent) DataGeneration() uint64 { return e.dataGeneration }

// OccurredAt returns the local mutation commit time.
func (e StateEvent) OccurredAt() time.Time { return e.occurredAt }

func (e StateEvent) valid() bool {
	if !validNamespace(e.namespace) || !validIdentifier(e.cursor) || e.occurredAt.IsZero() {
		return false
	}
	budget := budgetCounter{max: MaxEventPageBytes}
	if addStateEventCost(&budget, e) != nil {
		return false
	}
	switch e.kind {
	case StateEventRevisionPublished:
		return validRevisionIDString(e.revisionID) && e.slot == "" && e.slotGeneration == 0 && e.dataGeneration == 0
	case StateEventSlotActivated:
		return validRevisionIDString(e.revisionID) && validIdentifier(e.slot) && e.slotGeneration > 0 && e.dataGeneration == 0
	case StateEventDataWritten:
		return e.revisionID == "" && e.slot == "" && e.slotGeneration == 0 && e.dataGeneration > 0
	default:
		return false
	}
}

// ListEventsRequest requests a bounded page of local state events.
type ListEventsRequest struct {
	namespace   string
	afterCursor string
	limit       int
}

// NewListEventsRequest validates and constructs a bounded event listing.
func NewListEventsRequest(namespace, afterCursor string, limit int) (ListEventsRequest, error) {
	if limit <= 0 {
		return ListEventsRequest{}, invalidArgument("event list requires positive limit")
	}
	if err := validateNamespace(namespace); err != nil {
		return ListEventsRequest{}, err
	}
	if err := validateOptionalIdentifier(afterCursor); err != nil {
		return ListEventsRequest{}, err
	}
	if limit > MaxPageRequestItems {
		return ListEventsRequest{}, resourceExhausted()
	}
	return ListEventsRequest{namespace: namespace, afterCursor: afterCursor, limit: limit}, nil
}

// Namespace returns the opaque listing namespace.
func (r ListEventsRequest) Namespace() string { return r.namespace }

// AfterCursor returns the optional exclusive event cursor.
func (r ListEventsRequest) AfterCursor() string { return r.afterCursor }

// Limit returns the requested positive page limit.
func (r ListEventsRequest) Limit() int { return r.limit }

func (r ListEventsRequest) valid() bool {
	return validNamespace(r.namespace) && validateOptionalIdentifier(r.afterCursor) == nil &&
		r.limit > 0 && r.limit <= MaxPageRequestItems
}

// ListEventsResponse reports a bounded page of local state events.
type ListEventsResponse struct {
	validResponse bool
	request       ListEventsRequest
	events        []StateEvent
	nextCursor    string
}

// NewListEventsResponse validates and copies a request-bound event page.
// Event cursors are opaque: caller/store order is preserved and adapters are
// responsible for supplying store-monotonic order; this constructor rejects
// duplicates but does not compare cursors lexically.
func NewListEventsResponse(request ListEventsRequest, events []StateEvent, nextCursor string) (ListEventsResponse, error) {
	if !request.valid() {
		return ListEventsResponse{}, invalidArgument("event page requires a valid originating request")
	}
	if len(events) > request.limit || len(events) > MaxEventPageItems || len(events) > MaxPageResponseItems {
		return ListEventsResponse{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxEventPageBytes}
	if err := addEventPageCost(&budget, events, nextCursor); err != nil {
		return ListEventsResponse{}, err
	}
	if err := validateOptionalIdentifier(nextCursor); err != nil {
		return ListEventsResponse{}, err
	}
	if !validEventPage(request, events) {
		return ListEventsResponse{}, invalidArgument("event page is out of scope or contains duplicate cursors")
	}
	return ListEventsResponse{
		validResponse: true,
		request:       request,
		events:        cloneSlice(events),
		nextCursor:    nextCursor,
	}, nil
}

// Events returns a defensive copy preserving cursor order.
func (r ListEventsResponse) Events() []StateEvent { return cloneSlice(r.events) }

// NextCursor returns the optional cursor for the next page.
func (r ListEventsResponse) NextCursor() string { return r.nextCursor }

func (r ListEventsResponse) valid() bool {
	if !r.validResponse || !r.request.valid() || len(r.events) > r.request.limit ||
		len(r.events) > MaxEventPageItems || len(r.events) > MaxPageResponseItems ||
		validateOptionalIdentifier(r.nextCursor) != nil {
		return false
	}
	budget := budgetCounter{max: MaxEventPageBytes}
	return addEventPageCost(&budget, r.events, r.nextCursor) == nil && validEventPage(r.request, r.events)
}

func validEventPage(request ListEventsRequest, events []StateEvent) bool {
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		if !event.valid() || event.namespace != request.namespace {
			return false
		}
		if _, duplicate := seen[event.cursor]; duplicate {
			return false
		}
		seen[event.cursor] = struct{}{}
	}
	return true
}

// StatusRequest requests detailed local component and readiness status.
type StatusRequest struct {
	authorizationNamespace string
}

// NewStatusRequest validates the namespace used only for caller authorization.
func NewStatusRequest(authorizationNamespace string) (StatusRequest, error) {
	if err := validateNamespace(authorizationNamespace); err != nil {
		return StatusRequest{}, err
	}
	return StatusRequest{authorizationNamespace: authorizationNamespace}, nil
}

// AuthorizationNamespace returns the opaque scope used for capability checks.
// Status responses never include this value.
func (r StatusRequest) AuthorizationNamespace() string { return r.authorizationNamespace }

// ComponentState identifies one bounded local component condition.
type ComponentState uint8

const (
	// ComponentReady means a component can perform its required local work.
	ComponentReady ComponentState = iota + 1
	// ComponentDegraded means a component is available with reduced readiness.
	ComponentDegraded
	// ComponentUnavailable means a component cannot perform required local work.
	ComponentUnavailable
)

// ComponentStatus is privacy-safe local component metadata.
type ComponentStatus struct {
	name       string
	state      ComponentState
	reasonCode string
}

// NewComponentStatus validates and constructs privacy-safe component metadata.
func NewComponentStatus(name string, state ComponentState, reasonCode string) (ComponentStatus, error) {
	raw := ComponentStatus{name: name, state: state, reasonCode: reasonCode}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addComponentStatusCost(&budget, raw); err != nil {
		return ComponentStatus{}, err
	}
	if state < ComponentReady || state > ComponentUnavailable {
		return ComponentStatus{}, invalidArgument("component status requires valid state")
	}
	if err := validateIdentifier(name); err != nil {
		return ComponentStatus{}, err
	}
	if err := validateIdentifier(reasonCode); err != nil {
		return ComponentStatus{}, err
	}
	return raw, nil
}

// Name returns the stable component name.
func (s ComponentStatus) Name() string { return s.name }

// State returns the bounded component condition.
func (s ComponentStatus) State() ComponentState { return s.state }

// ReasonCode returns a stable privacy-safe status reason.
func (s ComponentStatus) ReasonCode() string { return s.reasonCode }

func (s ComponentStatus) valid() bool {
	if !validIdentifier(s.name) || !validIdentifier(s.reasonCode) || s.state < ComponentReady || s.state > ComponentUnavailable {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	return addComponentStatusCost(&budget, s) == nil
}

// StatusResponse reports detailed local component and readiness status.
type StatusResponse struct {
	validResponse bool
	ready         bool
	components    []ComponentStatus
}

// NewStatusResponse validates, sorts, and copies detailed local status.
func NewStatusResponse(ready bool, components []ComponentStatus) (StatusResponse, error) {
	if len(components) > MaxStatusComponents {
		return StatusResponse{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addStatusResponseCost(&budget, ready, components); err != nil {
		return StatusResponse{}, err
	}
	for _, component := range components {
		if !component.valid() {
			return StatusResponse{}, invalidArgument("status response contains invalid component metadata")
		}
	}
	names := make(map[string]struct{}, len(components))
	for _, component := range components {
		if _, duplicate := names[component.name]; duplicate {
			return StatusResponse{}, invalidArgument("status response contains a duplicate component name")
		}
		names[component.name] = struct{}{}
	}
	cloned := cloneSlice(components)
	sort.Slice(cloned, func(i, j int) bool { return cloned[i].name < cloned[j].name })
	return StatusResponse{validResponse: true, ready: ready, components: cloned}, nil
}

// Ready reports whether the local runtime is ready for policy operations.
func (r StatusResponse) Ready() bool { return r.ready }

// Components returns a deterministic defensive copy of component status.
func (r StatusResponse) Components() []ComponentStatus { return cloneSlice(r.components) }

func (r StatusResponse) valid() bool {
	if !r.validResponse || len(r.components) > MaxStatusComponents {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if addStatusResponseCost(&budget, r.ready, r.components) != nil {
		return false
	}
	for index, component := range r.components {
		if !component.valid() || (index > 0 && r.components[index-1].name >= component.name) {
			return false
		}
	}
	return true
}
