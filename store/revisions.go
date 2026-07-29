package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
)

// RevisionStore persists immutable content-addressed local DSL artifacts.
type RevisionStore interface {
	PutRevision(context.Context, RevisionWrite) (PutRevisionResult, error)
	GetRevision(context.Context, policyengine.GetRevisionRequest) (RevisionRecord, error)
	ListRevisions(context.Context, policyengine.ListRevisionsRequest) (policyengine.ListRevisionsResponse, error)
}

// RevisionWrite is an immutable bounded candidate revision. The declared
// metadata and artifact are intentionally allowed to disagree so an adapter can
// detect and report a digest collision as INTEGRITY_ERROR without storing data.
type RevisionWrite struct {
	metadata policyengine.RevisionMetadata
	artifact []byte
}

// NewRevisionWrite validates shape and bounds before copying artifact bytes.
func NewRevisionWrite(metadata policyengine.RevisionMetadata, artifact []byte) (RevisionWrite, error) {
	if err := validateRevisionMetadata(metadata); err != nil {
		return RevisionWrite{}, err
	}
	if len(artifact) == 0 {
		return RevisionWrite{}, newError(policyengine.ErrorInvalidArgument)
	}
	if len(artifact) > policyengine.MaxPolicyArtifactBytes {
		return RevisionWrite{}, newError(policyengine.ErrorResourceExhausted)
	}
	return RevisionWrite{metadata: metadata, artifact: cloneBytes(artifact)}, nil
}

// Metadata returns the candidate's immutable public metadata.
func (w RevisionWrite) Metadata() policyengine.RevisionMetadata { return w.metadata }

// Artifact returns a defensive copy of the encoded DSL artifact.
func (w RevisionWrite) Artifact() []byte { return cloneBytes(w.artifact) }

// Valid reports whether the candidate has valid bounded shape. It does not
// assert that the declared content address matches the bytes.
func (w RevisionWrite) Valid() bool {
	return validateRevisionMetadata(w.metadata) == nil && len(w.artifact) > 0 &&
		len(w.artifact) <= policyengine.MaxPolicyArtifactBytes
}

// RevisionRecord is an immutable verified content-addressed local revision.
type RevisionRecord struct {
	metadata policyengine.RevisionMetadata
	artifact []byte
}

// NewRevisionRecord validates the DSL artifact and its declared content address
// before copying bytes. A mismatch is authoritative-integrity failure.
func NewRevisionRecord(metadata policyengine.RevisionMetadata, artifact []byte) (RevisionRecord, error) {
	write, err := NewRevisionWrite(metadata, artifact)
	if err != nil {
		return RevisionRecord{}, err
	}
	if err := verifyRevisionContent(write); err != nil {
		return RevisionRecord{}, err
	}
	return RevisionRecord{metadata: metadata, artifact: cloneBytes(artifact)}, nil
}

// Metadata returns immutable public revision metadata.
func (r RevisionRecord) Metadata() policyengine.RevisionMetadata { return r.metadata }

// Artifact returns a defensive copy of the encoded DSL artifact.
func (r RevisionRecord) Artifact() []byte { return cloneBytes(r.artifact) }

// Valid reports whether metadata, artifact, and content address are valid.
func (r RevisionRecord) Valid() bool {
	write := RevisionWrite(r)
	return write.Valid() && verifyRevisionContent(write) == nil
}

// PutRevisionResult reports the verified stored revision and whether this call
// atomically created it. An idempotent duplicate has Created false.
type PutRevisionResult struct {
	record  RevisionRecord
	created bool
}

// NewPutRevisionResult constructs a verified immutable write result.
func NewPutRevisionResult(record RevisionRecord, created bool) (PutRevisionResult, error) {
	if !record.Valid() {
		return PutRevisionResult{}, newError(policyengine.ErrorInvalidArgument)
	}
	return PutRevisionResult{record: record, created: created}, nil
}

// Record returns the verified immutable stored revision.
func (r PutRevisionResult) Record() RevisionRecord { return r.record }

// Created reports whether a new revision and state event committed.
func (r PutRevisionResult) Created() bool { return r.created }

// Valid reports whether this is a constructor-produced valid result.
func (r PutRevisionResult) Valid() bool { return r.record.Valid() }

func validateRevisionMetadata(metadata policyengine.RevisionMetadata) error {
	if metadata.Namespace() == "" || metadata.ID() == "" || metadata.PublishedAt().IsZero() {
		return newError(policyengine.ErrorInvalidArgument)
	}
	if _, err := policyengine.NewGetRevisionRequest(metadata.Namespace(), metadata.ID()); err != nil {
		return err
	}
	id, err := policyengine.ParseRevisionID(metadata.ID())
	if err != nil {
		return err
	}
	_, err = policyengine.NewRevisionMetadata(metadata.Namespace(), id, metadata.PublishedAt())
	return err
}

func verifyRevisionContent(write RevisionWrite) error {
	artifact, err := dsl.DecodeArtifact(write.artifact)
	if err != nil {
		return newError(policyengine.ErrorIntegrity)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil || id.String() != write.metadata.ID() {
		return newError(policyengine.ErrorIntegrity)
	}
	canonical, err := artifact.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, write.artifact) {
		return newError(policyengine.ErrorIntegrity)
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return []byte{}
	}
	return append([]byte(nil), value...)
}

func redactedString(typeName string) string { return typeName + "{redacted}" }

func writeRedacted(state fmt.State, typeName string) {
	_, _ = state.Write([]byte(redactedString(typeName)))
}

func redactedLogValue(typeName string) slog.Value {
	return slog.GroupValue(slog.String("type", typeName), slog.Bool("redacted", true))
}

func (RevisionWrite) String() string { return redactedString("RevisionWrite") }

// GoString returns a redacted Go-syntax representation.
func (RevisionWrite) GoString() string { return redactedString("RevisionWrite") }

// Format writes a redacted representation for every formatting verb.
func (RevisionWrite) Format(s fmt.State, _ rune) { writeRedacted(s, "RevisionWrite") }

// LogValue returns privacy-safe structured logging metadata.
func (RevisionWrite) LogValue() slog.Value { return redactedLogValue("RevisionWrite") }
func (RevisionRecord) String() string      { return redactedString("RevisionRecord") }

// GoString returns a redacted Go-syntax representation.
func (RevisionRecord) GoString() string { return redactedString("RevisionRecord") }

// Format writes a redacted representation for every formatting verb.
func (RevisionRecord) Format(s fmt.State, _ rune) { writeRedacted(s, "RevisionRecord") }

// LogValue returns privacy-safe structured logging metadata.
func (RevisionRecord) LogValue() slog.Value { return redactedLogValue("RevisionRecord") }
func (PutRevisionResult) String() string    { return redactedString("PutRevisionResult") }

// GoString returns a redacted Go-syntax representation.
func (PutRevisionResult) GoString() string { return redactedString("PutRevisionResult") }

// Format writes a redacted representation for every formatting verb.
func (PutRevisionResult) Format(s fmt.State, _ rune) { writeRedacted(s, "PutRevisionResult") }

// LogValue returns privacy-safe structured logging metadata.
func (PutRevisionResult) LogValue() slog.Value { return redactedLogValue("PutRevisionResult") }
