package sqlite

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestCodecRevisionProvenanceRoundTripIsDeterministicAndDefensive(t *testing.T) {
	// This catches a non-canonical provenance encoding or a decoder that aliases
	// durable source bytes instead of rebuilding the public immutable value.
	request, err := policyengine.NewPublishRequest("codec-ns", "policy.cdr", []byte("entity user {}"))
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	provenance, err := store.NewRevisionProvenance(request)
	if err != nil {
		t.Fatalf("NewRevisionProvenance() error = %v", err)
	}

	first, err := encodeRevisionProvenance(provenance)
	if err != nil {
		t.Fatalf("encodeRevisionProvenance() error = %v", err)
	}
	second, err := encodeRevisionProvenance(provenance)
	if err != nil {
		t.Fatalf("second encodeRevisionProvenance() error = %v", err)
	}
	if !bytes.Equal(first, second) || len(first) == 0 || first[0] != codecVersion {
		t.Fatalf("encoding is not deterministic version-1 bytes: %x / %x", first, second)
	}

	decoded, err := decodeRevisionProvenance("codec-ns", first)
	if err != nil {
		t.Fatalf("decodeRevisionProvenance() error = %v", err)
	}
	if got, want := decoded.SourceName(), provenance.SourceName(); got != want {
		t.Fatalf("SourceName() = %q, want %q", got, want)
	}
	if got, want := decoded.OriginalSource(), provenance.OriginalSource(); !bytes.Equal(got, want) {
		t.Fatalf("OriginalSource() = %q, want %q", got, want)
	}
	mutated := decoded.OriginalSource()
	mutated[0] ^= 0xff
	if got, want := decoded.OriginalSource(), provenance.OriginalSource(); !bytes.Equal(got, want) {
		t.Fatalf("decoded provenance retained mutable source alias: %q, want %q", got, want)
	}
}

func TestCodecPublicMetadataActivationAndEventRoundTripNormalizeUTC(t *testing.T) {
	// This catches a decoder that bypasses public constructors, loses fixed
	// fields, or preserves a caller's non-UTC location in durable values.
	artifact, err := dsl.CompileArtifact("codec.cdr", []byte("entity document {}"))
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	local := time.FixedZone("codec-local", -3*60*60)
	when := time.Date(2040, 2, 3, 4, 5, 6, 700, local)
	metadata, err := policyengine.NewRevisionMetadata("codec-ns", id, when)
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	encodedMetadata, err := encodeRevisionMetadata(metadata)
	if err != nil {
		t.Fatalf("encodeRevisionMetadata() error = %v", err)
	}
	decodedMetadata, err := decodeRevisionMetadata(encodedMetadata)
	if err != nil {
		t.Fatalf("decodeRevisionMetadata() error = %v", err)
	}
	if got, want := decodedMetadata.Namespace(), "codec-ns"; got != want {
		t.Fatalf("metadata Namespace() = %q, want %q", got, want)
	}
	if got, want := decodedMetadata.ID(), id.String(); got != want {
		t.Fatalf("metadata ID() = %q, want %q", got, want)
	}
	if got, want := decodedMetadata.PublishedAt(), when.UTC(); !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("metadata PublishedAt() = %v (%v), want UTC %v", got, got.Location(), want)
	}

	activation, err := policyengine.NewActivation("codec-ns", "primary", id.String(), 7, when)
	if err != nil {
		t.Fatalf("NewActivation() error = %v", err)
	}
	encodedActivation, err := encodeActivation(activation)
	if err != nil {
		t.Fatalf("encodeActivation() error = %v", err)
	}
	decodedActivation, err := decodeActivation(encodedActivation)
	if err != nil {
		t.Fatalf("decodeActivation() error = %v", err)
	}
	if got := decodedActivation; got.Namespace() != "codec-ns" || got.Slot() != "primary" || got.RevisionID() != id.String() || got.Generation() != 7 || !got.ActivatedAt().Equal(when.UTC()) || got.ActivatedAt().Location() != time.UTC {
		t.Fatalf("activation round trip = %#v", got)
	}

	event, err := policyengine.NewStateEvent(policyengine.StateEventInput{
		Namespace: "codec-ns", Cursor: "opaque-cursor", Kind: policyengine.StateEventSlotActivated,
		RevisionID: id.String(), Slot: "primary", SlotGeneration: 7, OccurredAt: when,
	})
	if err != nil {
		t.Fatalf("NewStateEvent() error = %v", err)
	}
	encodedEvent, err := encodeStateEvent(event)
	if err != nil {
		t.Fatalf("encodeStateEvent() error = %v", err)
	}
	decodedEvent, err := decodeStateEvent(encodedEvent)
	if err != nil {
		t.Fatalf("decodeStateEvent() error = %v", err)
	}
	if got := decodedEvent; got.Namespace() != "codec-ns" || got.Cursor() != "opaque-cursor" || got.Kind() != policyengine.StateEventSlotActivated || got.RevisionID() != id.String() || got.Slot() != "primary" || got.SlotGeneration() != 7 || got.DataGeneration() != 0 || !got.OccurredAt().Equal(when.UTC()) || got.OccurredAt().Location() != time.UTC {
		t.Fatalf("event round trip = %#v", got)
	}
}

func TestCodecRejectsUnknownEnumsOversizedLengthsAndTrailingBytes(t *testing.T) {
	// This catches parser changes that accept a future format, allocate from an
	// attacker-controlled length, or silently accept an ambiguous suffix.
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{
			name: "unknown provenance enum",
			call: func() error {
				_, err := decodeRevisionProvenance("codec-ns", []byte{codecVersion, 9})
				return err
			},
		},
		{
			name: "oversized provenance source",
			call: func() error {
				encoded := []byte{codecVersion, provenancePresent, 0, 1, 'x'}
				var declared [4]byte
				binary.BigEndian.PutUint32(declared[:], uint32(policyengine.MaxPolicySourceBytes+1))
				encoded = append(encoded, declared[:]...)
				_, err := decodeRevisionProvenance("codec-ns", encoded)
				return err
			},
		},
		{
			name: "trailing provenance bytes",
			call: func() error {
				_, err := decodeRevisionProvenance("codec-ns", []byte{codecVersion, provenanceAbsent, 0})
				return err
			},
		},
		{
			name: "unknown event enum",
			call: func() error {
				_, err := decodeStateEvent([]byte{codecVersion, 99})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := categoryOf(tc.call()); got != policyengine.ErrorIntegrity {
				t.Fatalf("decode category = %v, want %v", got, policyengine.ErrorIntegrity)
			}
		})
	}
}

func TestCursorCodecBindsScopeSequenceAndExpiryBoundary(t *testing.T) {
	// This catches cursors that omit their expiry boundary, use process-random
	// state, accept cross-namespace replay, or compare a MAC non-constantly.
	adapter := &Store{}
	for index := range adapter.cursorKey {
		adapter.cursorKey[index] = byte(index + 1)
	}
	input := cursorState{domain: cursorDomainEvent, namespace: "cursor-ns", position: 9, boundary: 4}
	first, err := adapter.newCursor(input)
	if err != nil {
		t.Fatalf("newCursor() error = %v", err)
	}
	second, err := adapter.newCursor(input)
	if err != nil {
		t.Fatalf("second newCursor() error = %v", err)
	}
	if first != second || first == "" || len(first) > policyengine.MaxIdentifierBytes {
		t.Fatalf("cursor is not deterministic bounded canonical output: %q / %q", first, second)
	}
	decoded, err := adapter.decodeCursor(first, cursorDomainEvent, "cursor-ns", "")
	if err != nil {
		t.Fatalf("decodeCursor() error = %v", err)
	}
	if decoded.domain != cursorDomainEvent || decoded.namespace != "cursor-ns" || decoded.position != 9 || decoded.boundary != 4 {
		t.Fatalf("decoded cursor = %#v", decoded)
	}
	if _, err := adapter.decodeCursor(first, cursorDomainEvent, "other-ns", ""); categoryOf(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("cross-namespace cursor category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
	}
	tampered := tamperSQLiteCursorForTest(first)
	if _, err := adapter.decodeCursor(tampered, cursorDomainEvent, "cursor-ns", ""); categoryOf(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("tampered cursor category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
	}
}

func TestCursorCodecRejectsNonCanonicalTrailingBitAlias(t *testing.T) {
	// This catches an opaque cursor parser that lets Raw Base64 spellings with
	// nonzero unused tail bits authenticate as the same durable token.
	adapter := &Store{}
	for index := range adapter.cursorKey {
		adapter.cursorKey[index] = byte(index + 1)
	}
	canonical, err := adapter.newCursor(cursorState{domain: cursorDomainEvent, namespace: "cursor-alias", position: 9, boundary: 4})
	if err != nil {
		t.Fatalf("newCursor() error = %v", err)
	}
	decodedCanonical, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatalf("DecodeString(canonical) error = %v", err)
	}
	alias := ""
	for _, digit := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		candidate := canonical[:len(canonical)-1] + string(digit)
		decodedCandidate, decodeErr := base64.RawURLEncoding.DecodeString(candidate)
		if candidate != canonical && decodeErr == nil && bytes.Equal(decodedCandidate, decodedCanonical) {
			alias = candidate
			break
		}
	}
	if alias == "" {
		t.Fatal("test did not construct a non-canonical Raw Base64 alias")
	}
	if _, err := adapter.decodeCursor(alias, cursorDomainEvent, "cursor-alias", ""); categoryOf(err) != policyengine.ErrorInvalidArgument {
		t.Fatalf("non-canonical cursor alias category = %v, want %v", categoryOf(err), policyengine.ErrorInvalidArgument)
	}
}
