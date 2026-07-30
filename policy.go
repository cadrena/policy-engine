package policyengine

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/cadrena/dsl"
)

// Selector identifies exactly one policy slot or immutable revision.
type Selector struct {
	slot       string
	revisionID string
}

// NewSelector validates and constructs an exactly-one policy selector.
func NewSelector(slot, exactRevision string) (Selector, error) {
	if (slot == "") == (exactRevision == "") {
		return Selector{}, invalidArgument("selector must contain exactly one of slot or exact revision")
	}
	if slot != "" {
		if err := validateIdentifier(slot); err != nil {
			return Selector{}, err
		}
	}
	if exactRevision != "" && !validRevisionIDString(exactRevision) {
		return Selector{}, invalidArgument("selector revision is not content addressed")
	}
	return Selector{slot: slot, revisionID: exactRevision}, nil
}

// Slot returns the selected slot and whether this is a slot selector.
func (s Selector) Slot() (string, bool) {
	return s.slot, s.slot != "" && s.revisionID == ""
}

// ExactRevision returns the selected revision and whether this is an exact selector.
func (s Selector) ExactRevision() (string, bool) {
	return s.revisionID, s.revisionID != "" && s.slot == ""
}

func (s Selector) valid() bool {
	if (s.slot == "") == (s.revisionID == "") {
		return false
	}
	return (s.slot != "" && validIdentifier(s.slot)) || (s.revisionID != "" && validRevisionIDString(s.revisionID))
}

// RevisionID is a validated lowercase SHA-256 content address derived from a
// tagged DSL artifact digest. Its zero value is invalid.
type RevisionID struct {
	digest [sha256.Size]byte
	valid  bool
}

// RevisionIDFromArtifact derives the sole stable revision identity.
func RevisionIDFromArtifact(artifact *dsl.Artifact) (RevisionID, error) {
	if artifact == nil {
		return RevisionID{}, invalidArgument("revision artifact is nil")
	}
	if _, err := artifact.MarshalBinary(); err != nil {
		return RevisionID{}, invalidArgument("revision artifact is invalid")
	}
	return RevisionID{digest: artifact.Digest(), valid: true}, nil
}

// ParseRevisionID validates fixed-size lowercase hexadecimal encoding.
func ParseRevisionID(value string) (RevisionID, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return RevisionID{}, invalidArgument("revision id is not canonical")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return RevisionID{}, invalidArgument("revision id is not canonical")
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return RevisionID{digest: digest, valid: true}, nil
}

// String returns fixed-size lowercase hexadecimal encoding, or empty if invalid.
func (id RevisionID) String() string {
	if !id.valid {
		return ""
	}
	return hex.EncodeToString(id.digest[:])
}

// RevisionMetadata is immutable policy metadata. It intentionally carries no
// artifact, canonical source, IR, or program content.
type RevisionMetadata struct {
	namespace   string
	id          RevisionID
	publishedAt time.Time
}

// NewRevisionMetadata validates immutable local policy metadata.
func NewRevisionMetadata(namespace string, id RevisionID, publishedAt time.Time) (RevisionMetadata, error) {
	raw := RevisionMetadata{namespace: namespace, id: id, publishedAt: publishedAt}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addRevisionMetadataCost(&budget, raw); err != nil {
		return RevisionMetadata{}, err
	}
	if err := validateNamespace(namespace); err != nil {
		return RevisionMetadata{}, err
	}
	if !id.valid || publishedAt.IsZero() {
		return RevisionMetadata{}, invalidArgument("revision metadata is incomplete")
	}
	return raw, nil
}

// Namespace returns the opaque namespace containing the revision.
func (r RevisionMetadata) Namespace() string { return r.namespace }

// ID returns the immutable content-addressed revision identifier.
func (r RevisionMetadata) ID() string { return r.id.String() }

// PublishedAt returns the revision publication time.
func (r RevisionMetadata) PublishedAt() time.Time { return r.publishedAt }

func (r RevisionMetadata) valid() bool {
	if !validNamespace(r.namespace) || !r.id.valid || r.publishedAt.IsZero() {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	return addRevisionMetadataCost(&budget, r) == nil
}

// PublishRequest requests local publication of DSL source as an immutable revision.
type PublishRequest struct {
	namespace  string
	sourceName string
	source     []byte
}

// NewPublishRequest validates and copies policy source for publication.
func NewPublishRequest(namespace, sourceName string, source []byte) (PublishRequest, error) {
	if len(source) == 0 {
		return PublishRequest{}, invalidArgument("publish request requires source")
	}
	if len(source) > MaxPolicySourceBytes {
		return PublishRequest{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addPublishRequestCost(&budget, namespace, sourceName, source); err != nil {
		return PublishRequest{}, err
	}
	if err := validateNamespace(namespace); err != nil {
		return PublishRequest{}, err
	}
	if err := validateText(sourceName, MaxSourceNameBytes, false); err != nil {
		return PublishRequest{}, err
	}
	return PublishRequest{
		namespace:  namespace,
		sourceName: sourceName,
		source:     cloneBytes(source),
	}, nil
}

// Namespace returns the opaque target namespace.
func (r PublishRequest) Namespace() string { return r.namespace }

// SourceName returns the diagnostic-safe source name supplied to the DSL.
func (r PublishRequest) SourceName() string { return r.sourceName }

// Source returns a defensive copy of the DSL source.
func (r PublishRequest) Source() []byte { return cloneBytes(r.source) }

func (r PublishRequest) valid() bool {
	if !validNamespace(r.namespace) || validateText(r.sourceName, MaxSourceNameBytes, false) != nil || len(r.source) == 0 || len(r.source) > MaxPolicySourceBytes {
		return false
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	return addPublishRequestCost(&budget, r.namespace, r.sourceName, r.source) == nil
}

// PublishResponse reports the published revision and whether it was newly created.
type PublishResponse struct {
	revision RevisionMetadata
	created  bool
}

// NewPublishResponse validates and constructs a publication response.
func NewPublishResponse(revision RevisionMetadata, created bool) (PublishResponse, error) {
	if !revision.valid() {
		return PublishResponse{}, invalidArgument("publish response requires a valid revision")
	}
	return PublishResponse{revision: revision, created: created}, nil
}

// Revision returns the immutable published revision.
func (r PublishResponse) Revision() RevisionMetadata { return r.revision }

// Created reports whether publication committed a new revision.
func (r PublishResponse) Created() bool { return r.created }

// GetRevisionRequest identifies one local immutable revision.
type GetRevisionRequest struct {
	namespace  string
	revisionID string
}

// NewGetRevisionRequest validates and constructs a revision lookup.
func NewGetRevisionRequest(namespace, revisionID string) (GetRevisionRequest, error) {
	if err := validateNamespace(namespace); err != nil {
		return GetRevisionRequest{}, err
	}
	if !validRevisionIDString(revisionID) {
		return GetRevisionRequest{}, invalidArgument("revision lookup requires revision id")
	}
	return GetRevisionRequest{namespace: namespace, revisionID: revisionID}, nil
}

// Namespace returns the opaque lookup namespace.
func (r GetRevisionRequest) Namespace() string { return r.namespace }

// RevisionID returns the exact revision identifier.
func (r GetRevisionRequest) RevisionID() string { return r.revisionID }

// GetRevisionResponse reports one local immutable revision.
type GetRevisionResponse struct {
	revision RevisionMetadata
}

// NewGetRevisionResponse validates and constructs a revision response.
func NewGetRevisionResponse(revision RevisionMetadata) (GetRevisionResponse, error) {
	if !revision.valid() {
		return GetRevisionResponse{}, invalidArgument("revision response requires a valid revision")
	}
	return GetRevisionResponse{revision: revision}, nil
}

// Revision returns the immutable local revision.
func (r GetRevisionResponse) Revision() RevisionMetadata { return r.revision }

// ListRevisionsRequest requests a bounded cursor page of local revisions.
type ListRevisionsRequest struct {
	namespace string
	cursor    string
	limit     int
}

// NewListRevisionsRequest validates and constructs a bounded revision listing.
func NewListRevisionsRequest(namespace, cursor string, limit int) (ListRevisionsRequest, error) {
	if limit <= 0 {
		return ListRevisionsRequest{}, invalidArgument("revision list requires positive limit")
	}
	if err := validateNamespace(namespace); err != nil {
		return ListRevisionsRequest{}, err
	}
	if err := validateOptionalIdentifier(cursor); err != nil {
		return ListRevisionsRequest{}, err
	}
	if limit > MaxPageRequestItems {
		return ListRevisionsRequest{}, resourceExhausted()
	}
	return ListRevisionsRequest{namespace: namespace, cursor: cursor, limit: limit}, nil
}

// Namespace returns the opaque listing namespace.
func (r ListRevisionsRequest) Namespace() string { return r.namespace }

// Cursor returns the optional opaque page cursor.
func (r ListRevisionsRequest) Cursor() string { return r.cursor }

// Limit returns the requested positive page limit.
func (r ListRevisionsRequest) Limit() int { return r.limit }

func (r ListRevisionsRequest) valid() bool {
	return validNamespace(r.namespace) && validateOptionalIdentifier(r.cursor) == nil &&
		r.limit > 0 && r.limit <= MaxPageRequestItems
}

// ListRevisionsResponse reports a bounded page of immutable local revisions.
type ListRevisionsResponse struct {
	validResponse bool
	request       ListRevisionsRequest
	revisions     []RevisionMetadata
	nextCursor    string
}

// NewListRevisionsResponse validates and copies a revision page bound to request.
// Revisions must be ordered by PublishedAt ascending, then RevisionID ascending.
func NewListRevisionsResponse(request ListRevisionsRequest, revisions []RevisionMetadata, nextCursor string) (ListRevisionsResponse, error) {
	if !request.valid() {
		return ListRevisionsResponse{}, invalidArgument("revision page requires a valid originating request")
	}
	if len(revisions) > request.limit || len(revisions) > MaxPageResponseItems {
		return ListRevisionsResponse{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addRevisionPageCost(&budget, revisions, nextCursor); err != nil {
		return ListRevisionsResponse{}, err
	}
	if err := validateOptionalIdentifier(nextCursor); err != nil {
		return ListRevisionsResponse{}, err
	}
	if !validRevisionPage(request, revisions) {
		return ListRevisionsResponse{}, invalidArgument("revision page is out of scope, duplicated, or unordered")
	}
	return ListRevisionsResponse{
		validResponse: true,
		request:       request,
		revisions:     cloneSlice(revisions),
		nextCursor:    nextCursor,
	}, nil
}

// Revisions returns a defensive copy of the revision page.
func (r ListRevisionsResponse) Revisions() []RevisionMetadata { return cloneSlice(r.revisions) }

// NextCursor returns the optional opaque cursor for the next page.
func (r ListRevisionsResponse) NextCursor() string { return r.nextCursor }

func (r ListRevisionsResponse) valid() bool {
	if !r.validResponse || !r.request.valid() || len(r.revisions) > r.request.limit ||
		len(r.revisions) > MaxPageResponseItems || validateOptionalIdentifier(r.nextCursor) != nil {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	return addRevisionPageCost(&budget, r.revisions, r.nextCursor) == nil &&
		validRevisionPage(r.request, r.revisions)
}

func validRevisionPage(request ListRevisionsRequest, revisions []RevisionMetadata) bool {
	seen := make(map[string]struct{}, len(revisions))
	for index, revision := range revisions {
		if !revision.valid() || revision.namespace != request.namespace {
			return false
		}
		id := revision.id.String()
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
		if index == 0 {
			continue
		}
		previous := revisions[index-1]
		if previous.publishedAt.After(revision.publishedAt) ||
			(previous.publishedAt.Equal(revision.publishedAt) && previous.id.String() >= id) {
			return false
		}
	}
	return true
}

// SlotExpectation is an immutable, explicit activation CAS precondition.
// It represents exactly an unset slot or an active revision at a positive
// generation; its zero value is invalid.
type SlotExpectation struct {
	kind       uint8
	revisionID string
	generation uint64
}

const (
	slotExpectationUnset uint8 = iota + 1
	slotExpectationActive
)

// NewUnsetSlotExpectation requires the target slot to be unset.
func NewUnsetSlotExpectation() SlotExpectation {
	return SlotExpectation{kind: slotExpectationUnset}
}

// NewActiveSlotExpectation requires an exact revision and slot generation.
func NewActiveSlotExpectation(revisionID string, generation uint64) (SlotExpectation, error) {
	if !validRevisionIDString(revisionID) || generation == 0 {
		return SlotExpectation{}, invalidArgument("active slot expectation requires revision and generation")
	}
	return SlotExpectation{kind: slotExpectationActive, revisionID: revisionID, generation: generation}, nil
}

// IsUnset reports whether this expectation requires an unset slot.
func (e SlotExpectation) IsUnset() bool {
	return e.kind == slotExpectationUnset && e.revisionID == "" && e.generation == 0
}

// Active returns the exact expected revision and generation, when active.
func (e SlotExpectation) Active() (string, uint64, bool) {
	valid := e.kind == slotExpectationActive && e.revisionID != "" && e.generation > 0
	return e.revisionID, e.generation, valid
}

func (e SlotExpectation) valid() bool {
	if e.IsUnset() {
		return true
	}
	revisionID, _, active := e.Active()
	return active && validRevisionIDString(revisionID)
}

// ActivateRequest requests an atomic compare-and-swap local slot update.
type ActivateRequest struct {
	namespace        string
	slot             string
	targetRevisionID string
	expectation      SlotExpectation
}

// NewActivateRequest validates and constructs a slot activation request.
func NewActivateRequest(namespace, slot, targetRevisionID string, expectation SlotExpectation) (ActivateRequest, error) {
	if err := validateNamespace(namespace); err != nil {
		return ActivateRequest{}, err
	}
	if err := validateIdentifier(slot); err != nil {
		return ActivateRequest{}, err
	}
	if !validRevisionIDString(targetRevisionID) || !expectation.valid() {
		return ActivateRequest{}, invalidArgument("activation requires target revision and expectation")
	}
	return ActivateRequest{
		namespace:        namespace,
		slot:             slot,
		targetRevisionID: targetRevisionID,
		expectation:      expectation,
	}, nil
}

// Namespace returns the opaque target namespace.
func (r ActivateRequest) Namespace() string { return r.namespace }

// Slot returns the local slot name.
func (r ActivateRequest) Slot() string { return r.slot }

// TargetRevisionID returns the revision to activate.
func (r ActivateRequest) TargetRevisionID() string { return r.targetRevisionID }

// Expectation returns the immutable ABA-safe CAS precondition.
func (r ActivateRequest) Expectation() SlotExpectation { return r.expectation }

// Activation records one successful atomic local slot update.
type Activation struct {
	namespace   string
	slot        string
	revisionID  string
	generation  uint64
	activatedAt time.Time
}

// NewActivation validates and constructs immutable activation metadata.
func NewActivation(namespace, slot, revisionID string, generation uint64, activatedAt time.Time) (Activation, error) {
	raw := Activation{namespace: namespace, slot: slot, revisionID: revisionID, generation: generation, activatedAt: activatedAt}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addActivationCost(&budget, raw); err != nil {
		return Activation{}, err
	}
	if err := validateNamespace(namespace); err != nil {
		return Activation{}, err
	}
	if err := validateIdentifier(slot); err != nil {
		return Activation{}, err
	}
	if !validRevisionIDString(revisionID) || generation == 0 || activatedAt.IsZero() {
		return Activation{}, invalidArgument("activation requires revision, generation, and time")
	}
	return raw, nil
}

// Namespace returns the opaque activation namespace.
func (a Activation) Namespace() string { return a.namespace }

// Slot returns the activated local slot.
func (a Activation) Slot() string { return a.slot }

// RevisionID returns the activated exact revision.
func (a Activation) RevisionID() string { return a.revisionID }

// Generation returns the monotonic slot generation.
func (a Activation) Generation() uint64 { return a.generation }

// ActivatedAt returns the activation commit time.
func (a Activation) ActivatedAt() time.Time { return a.activatedAt }

func (a Activation) valid() bool {
	if !validNamespace(a.namespace) || !validIdentifier(a.slot) || !validRevisionIDString(a.revisionID) || a.generation == 0 || a.activatedAt.IsZero() {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	return addActivationCost(&budget, a) == nil
}

// ActivateResponse reports the completed local slot update.
type ActivateResponse struct {
	activation Activation
}

// NewActivateResponse validates and constructs an activation response.
func NewActivateResponse(activation Activation) (ActivateResponse, error) {
	if !activation.valid() {
		return ActivateResponse{}, invalidArgument("activation response requires valid activation metadata")
	}
	return ActivateResponse{activation: activation}, nil
}

// Activation returns immutable activation metadata.
func (r ActivateResponse) Activation() Activation { return r.activation }

// ResolveRequest identifies one local slot to resolve.
type ResolveRequest struct {
	namespace string
	slot      string
}

// NewResolveRequest validates and constructs a slot resolution request.
func NewResolveRequest(namespace, slot string) (ResolveRequest, error) {
	if err := validateNamespace(namespace); err != nil {
		return ResolveRequest{}, err
	}
	if err := validateIdentifier(slot); err != nil {
		return ResolveRequest{}, err
	}
	return ResolveRequest{namespace: namespace, slot: slot}, nil
}

// Namespace returns the opaque resolution namespace.
func (r ResolveRequest) Namespace() string { return r.namespace }

// Slot returns the local slot name.
func (r ResolveRequest) Slot() string { return r.slot }

// ResolveResponse reports the revision pinned by a local slot.
type ResolveResponse struct {
	activation Activation
}

// NewResolveResponse validates and constructs a slot resolution response.
func NewResolveResponse(activation Activation) (ResolveResponse, error) {
	if !activation.valid() {
		return ResolveResponse{}, invalidArgument("resolution response requires valid activation metadata")
	}
	return ResolveResponse{activation: activation}, nil
}

// Activation returns the resolved immutable activation metadata.
func (r ResolveResponse) Activation() Activation { return r.activation }

// ListActivationHistoryRequest requests bounded local slot history.
type ListActivationHistoryRequest struct {
	namespace string
	slot      string
	cursor    string
	limit     int
}

// NewListActivationHistoryRequest validates and constructs an activation-history listing.
func NewListActivationHistoryRequest(namespace, slot, cursor string, limit int) (ListActivationHistoryRequest, error) {
	if limit <= 0 {
		return ListActivationHistoryRequest{}, invalidArgument("activation history requires namespace, slot, and positive limit")
	}
	if err := validateNamespace(namespace); err != nil {
		return ListActivationHistoryRequest{}, err
	}
	if err := validateIdentifier(slot); err != nil {
		return ListActivationHistoryRequest{}, err
	}
	if err := validateOptionalIdentifier(cursor); err != nil {
		return ListActivationHistoryRequest{}, err
	}
	if limit > MaxPageRequestItems {
		return ListActivationHistoryRequest{}, resourceExhausted()
	}
	return ListActivationHistoryRequest{namespace: namespace, slot: slot, cursor: cursor, limit: limit}, nil
}

// Namespace returns the opaque listing namespace.
func (r ListActivationHistoryRequest) Namespace() string { return r.namespace }

// Slot returns the local slot whose history is listed.
func (r ListActivationHistoryRequest) Slot() string { return r.slot }

// Cursor returns the optional opaque page cursor.
func (r ListActivationHistoryRequest) Cursor() string { return r.cursor }

// Limit returns the requested positive page limit.
func (r ListActivationHistoryRequest) Limit() int { return r.limit }

func (r ListActivationHistoryRequest) valid() bool {
	return validNamespace(r.namespace) && validIdentifier(r.slot) &&
		validateOptionalIdentifier(r.cursor) == nil && r.limit > 0 && r.limit <= MaxPageRequestItems
}

// ListActivationHistoryResponse reports bounded local slot history.
type ListActivationHistoryResponse struct {
	validResponse bool
	request       ListActivationHistoryRequest
	activations   []Activation
	nextCursor    string
}

// NewListActivationHistoryResponse validates and copies a request-bound page.
// Activations must have strictly increasing generations.
func NewListActivationHistoryResponse(request ListActivationHistoryRequest, activations []Activation, nextCursor string) (ListActivationHistoryResponse, error) {
	if !request.valid() {
		return ListActivationHistoryResponse{}, invalidArgument("activation page requires a valid originating request")
	}
	if len(activations) > request.limit || len(activations) > MaxPageResponseItems {
		return ListActivationHistoryResponse{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	if err := addActivationHistoryPageCost(&budget, activations, nextCursor); err != nil {
		return ListActivationHistoryResponse{}, err
	}
	if err := validateOptionalIdentifier(nextCursor); err != nil {
		return ListActivationHistoryResponse{}, err
	}
	if !validActivationHistoryPage(request, activations) {
		return ListActivationHistoryResponse{}, invalidArgument("activation page is out of scope, duplicated, or unordered")
	}
	return ListActivationHistoryResponse{
		validResponse: true,
		request:       request,
		activations:   cloneSlice(activations),
		nextCursor:    nextCursor,
	}, nil
}

// Activations returns a defensive copy of the activation-history page.
func (r ListActivationHistoryResponse) Activations() []Activation { return cloneSlice(r.activations) }

// NextCursor returns the optional opaque cursor for the next page.
func (r ListActivationHistoryResponse) NextCursor() string { return r.nextCursor }

func (r ListActivationHistoryResponse) valid() bool {
	if !r.validResponse || !r.request.valid() || len(r.activations) > r.request.limit ||
		len(r.activations) > MaxPageResponseItems || validateOptionalIdentifier(r.nextCursor) != nil {
		return false
	}
	budget := budgetCounter{max: MaxAggregateOutputBytes}
	return addActivationHistoryPageCost(&budget, r.activations, r.nextCursor) == nil &&
		validActivationHistoryPage(r.request, r.activations)
}

func validActivationHistoryPage(request ListActivationHistoryRequest, activations []Activation) bool {
	var previousGeneration uint64
	for index, activation := range activations {
		if !activation.valid() || activation.namespace != request.namespace || activation.slot != request.slot {
			return false
		}
		if index > 0 && activation.generation <= previousGeneration {
			return false
		}
		previousGeneration = activation.generation
	}
	return true
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return []byte{}
	}
	return append([]byte(nil), value...)
}

func cloneSlice[T any](value []T) []T {
	if len(value) == 0 {
		return []T{}
	}
	return append([]T(nil), value...)
}
