// Package domain contains private lifecycle values assembled from the stable
// public API and store contracts.
package domain

import (
	"bytes"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

// Revision is a verified candidate containing canonical artifact bytes and
// separate original-source provenance.
type Revision struct {
	write store.RevisionWrite
}

// NewRevision derives the content-addressed metadata and immutable store write
// from one canonical tagged-DSL artifact.
func NewRevision(
	request policyengine.PublishRequest,
	artifact *dsl.Artifact,
	publishedAt time.Time,
) (Revision, error) {
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		return Revision{}, err
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		return Revision{}, err
	}
	metadata, err := policyengine.NewRevisionMetadata(request.Namespace(), id, publishedAt)
	if err != nil {
		return Revision{}, err
	}
	provenance, err := store.NewRevisionProvenance(request)
	if err != nil {
		return Revision{}, err
	}
	write, err := store.NewRevisionWriteWithProvenance(metadata, encoded, provenance)
	if err != nil {
		return Revision{}, err
	}
	return Revision{write: write}, nil
}

// Write returns the immutable candidate for the authoritative revision store.
func (r Revision) Write() store.RevisionWrite { return r.write }

// Matches reports whether an authoritative record contains the exact canonical
// artifact bytes and namespace-scoped content address requested by this candidate.
func (r Revision) Matches(record store.RevisionRecord) bool {
	if !r.write.Valid() || !record.Valid() {
		return false
	}
	candidateMetadata := r.write.Metadata()
	storedMetadata := record.Metadata()
	return candidateMetadata.Namespace() == storedMetadata.Namespace() &&
		candidateMetadata.ID() == storedMetadata.ID() &&
		bytes.Equal(r.write.Artifact(), record.Artifact())
}
