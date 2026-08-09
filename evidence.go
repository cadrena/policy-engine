package policyengine

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"
)

// CallerBinding is a fixed-size canonical binding of authenticated caller state.
// It carries no raw caller identifier or attributes.
type CallerBinding struct {
	digest *[sha256.Size]byte
	valid  bool
}

// Bytes returns the fixed-size caller-binding digest by value.
func (b CallerBinding) Bytes() [sha256.Size]byte {
	if b.digest == nil {
		return [sha256.Size]byte{}
	}
	return *b.digest
}

func (b CallerBinding) isValid() bool { return b.valid && b.digest != nil }

// Binding returns a canonical fixed-size binding over the caller ID and sorted
// authenticated attributes. It does not expose those dynamic values.
func (c Caller) Binding() CallerBinding {
	if !c.valid() {
		return CallerBinding{}
	}
	hash := sha256.New()
	writeBoundField(hash, c.id)
	keys := make([]string, 0, len(c.attributes))
	for key := range c.attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeBoundField(hash, key)
		writeBoundField(hash, c.attributes[key])
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return CallerBinding{digest: &digest, valid: true}
}

// EvidenceFingerprint is exactly one SHA-256-sized canonical request or ordered
// batch fingerprint. It cannot represent an arbitrary-length digest.
type EvidenceFingerprint struct {
	digest *[sha256.Size]byte
	valid  bool
}

// NewEvidenceFingerprint copies one fixed-size canonical fingerprint.
func NewEvidenceFingerprint(digest [sha256.Size]byte) EvidenceFingerprint {
	copied := digest
	return EvidenceFingerprint{digest: &copied, valid: true}
}

// Bytes returns the fixed-size fingerprint by value.
func (f EvidenceFingerprint) Bytes() [sha256.Size]byte {
	if f.digest == nil {
		return [sha256.Size]byte{}
	}
	return *f.digest
}

func (f EvidenceFingerprint) isValid() bool { return f.valid && f.digest != nil }

// EvidenceBindingInput contains sensitive construction-only trusted metadata
// and fixed-size bindings. Default formatting and logging are redacted.
type EvidenceBindingInput struct {
	Caller         CallerBinding
	Namespace      string
	Selector       Selector
	RevisionID     string
	SlotGeneration uint64
	DataGeneration uint64
	EvaluatedAt    time.Time
	Fingerprint    EvidenceFingerprint
}

// EvidenceBinding binds opaque evidence to one exact pinned evaluation. Its
// fingerprint scope depends on the verifier: delegation verification uses the
// whole request (the complete ordered batch for BatchCheck), while approval
// verification uses the individual item's effective evaluation scope.
type EvidenceBinding struct {
	caller         CallerBinding
	namespace      string
	selector       Selector
	revisionID     string
	slotGeneration uint64
	dataGeneration uint64
	evaluatedAt    time.Time
	fingerprint    EvidenceFingerprint
	validBinding   bool
}

// NewEvidenceBinding validates exact selector/snapshot semantics.
func NewEvidenceBinding(input EvidenceBindingInput) (EvidenceBinding, error) {
	raw := EvidenceBinding{
		caller:         input.Caller,
		namespace:      input.Namespace,
		selector:       input.Selector,
		revisionID:     input.RevisionID,
		slotGeneration: input.SlotGeneration,
		dataGeneration: input.DataGeneration,
		evaluatedAt:    input.EvaluatedAt,
		fingerprint:    input.Fingerprint,
		validBinding:   true,
	}
	byteBudget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addEvidenceBindingCost(&byteBudget, raw); err != nil {
		return EvidenceBinding{}, err
	}
	if !input.Caller.isValid() || !input.Selector.valid() || !validRevisionIDString(input.RevisionID) || input.EvaluatedAt.IsZero() || !input.Fingerprint.isValid() {
		return EvidenceBinding{}, invalidArgument("evidence binding is incomplete")
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return EvidenceBinding{}, err
	}
	exactRevision, exact := input.Selector.ExactRevision()
	if exact && exactRevision != input.RevisionID {
		return EvidenceBinding{}, invalidArgument("exact selector does not match resolved revision")
	}
	if exact && input.SlotGeneration != 0 {
		return EvidenceBinding{}, invalidArgument("exact selector evidence binding requires zero slot generation")
	}
	if !exact && input.SlotGeneration == 0 {
		return EvidenceBinding{}, invalidArgument("slot selector evidence binding requires positive slot generation")
	}
	return raw, nil
}

// Caller returns the fixed-size authenticated caller binding.
func (b EvidenceBinding) Caller() CallerBinding { return b.caller }

// Namespace returns the byte-exact namespace.
func (b EvidenceBinding) Namespace() string { return b.namespace }

// Selector returns the original selector kind and name.
func (b EvidenceBinding) Selector() Selector { return b.selector }

// RevisionID returns the exact resolved revision.
func (b EvidenceBinding) RevisionID() string { return b.revisionID }

// SlotGeneration returns zero for exact selection or the exact slot generation.
func (b EvidenceBinding) SlotGeneration() uint64 { return b.slotGeneration }

// DataGeneration returns the exact data generation, including initial zero.
func (b EvidenceBinding) DataGeneration() uint64 { return b.dataGeneration }

// EvaluatedAt returns the single captured evaluation time.
func (b EvidenceBinding) EvaluatedAt() time.Time { return b.evaluatedAt }

// Fingerprint returns the fixed-size scope-specific fingerprint: the complete
// request or ordered batch for delegation verification, or the individual
// item's effective evaluation for approval verification.
func (b EvidenceBinding) Fingerprint() EvidenceFingerprint { return b.fingerprint }

// AuthorizationDigest returns a stable approval-continuation binding. It omits
// evaluation time so a retry against the same authority remains resumable.
func (b EvidenceBinding) AuthorizationDigest() ([sha256.Size]byte, bool) {
	if !b.valid() {
		return [sha256.Size]byte{}, false
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("cadrena.approval.authorization.v1"))
	caller := b.caller.Bytes()
	fingerprint := b.fingerprint.Bytes()
	_, _ = hash.Write(caller[:])
	writeBoundField(hash, b.namespace)
	writeSelectorBinding(hash, b.selector)
	writeBoundField(hash, b.revisionID)
	writeBoundUint64(hash, b.slotGeneration)
	writeBoundUint64(hash, b.dataGeneration)
	_, _ = hash.Write(fingerprint[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, true
}

func (b EvidenceBinding) valid() bool {
	if !b.validBinding || !b.caller.isValid() || !validNamespace(b.namespace) || !b.selector.valid() || !validRevisionIDString(b.revisionID) || b.evaluatedAt.IsZero() || !b.fingerprint.isValid() {
		return false
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if addEvidenceBindingCost(&budget, b) != nil {
		return false
	}
	exactRevision, exact := b.selector.ExactRevision()
	if exact {
		return b.slotGeneration == 0 && b.revisionID == exactRevision
	}
	return b.slotGeneration > 0
}

func writeBoundField(hash interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(value))
}

func writeBoundUint64(hash interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = hash.Write(encoded[:])
}

func writeSelectorBinding(hash interface{ Write([]byte) (int, error) }, selector Selector) {
	if slot, ok := selector.Slot(); ok {
		writeBoundField(hash, "slot")
		writeBoundField(hash, slot)
		return
	}
	revision, _ := selector.ExactRevision()
	writeBoundField(hash, "revision")
	writeBoundField(hash, revision)
}
