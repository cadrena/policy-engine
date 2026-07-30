package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/store"
)

func TestRevisionWriteAndRecordPreserveImmutableSourceProvenance(t *testing.T) {
	t.Parallel()

	original := []byte("entity user {\n}\n")
	request, err := policyengine.NewPublishRequest("tenant-a", "policy.cdr", original)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	provenance, err := store.NewRevisionProvenance(request)
	if err != nil {
		t.Fatalf("NewRevisionProvenance() error = %v", err)
	}
	artifact := mustArtifactBytes(t, string(original))
	metadata := mustRevisionMetadata(t, "tenant-a", artifact, time.Unix(1, 0).UTC())
	write, err := store.NewRevisionWriteWithProvenance(metadata, artifact, provenance)
	if err != nil {
		t.Fatalf("NewRevisionWriteWithProvenance() error = %v", err)
	}

	original[0] = 'X'
	gotProvenance := write.Provenance()
	if got, want := gotProvenance.SourceName(), "policy.cdr"; got != want {
		t.Fatalf("SourceName() = %q, want %q", got, want)
	}
	if got, want := gotProvenance.OriginalSource(), []byte("entity user {\n}\n"); !bytes.Equal(got, want) {
		t.Fatalf("OriginalSource() = %q, want %q", got, want)
	}
	if got, want := gotProvenance.OriginalSourceDigest(), sha256.Sum256([]byte("entity user {\n}\n")); got != want {
		t.Fatalf("OriginalSourceDigest() = %x, want %x", got, want)
	}

	record, err := store.NewRevisionRecordFromWrite(write)
	if err != nil {
		t.Fatalf("NewRevisionRecordFromWrite() error = %v", err)
	}
	returned := record.Provenance().OriginalSource()
	returned[0] = 'X'
	if got, want := record.Provenance().OriginalSource(), []byte("entity user {\n}\n"); !bytes.Equal(got, want) {
		t.Fatalf("record OriginalSource() after caller mutation = %q, want %q", got, want)
	}
	if got := record.Artifact(); !bytes.Equal(got, artifact) {
		t.Fatal("record canonical artifact changed while preserving provenance")
	}
	assertRedacted(t, provenance, "policy.cdr")
}

func TestRevisionWriteAndRecordAreImmutableAndPrivacySafe(t *testing.T) {
	t.Parallel()

	artifact := mustArtifactBytes(t, "entity user {}")
	metadata := mustRevisionMetadata(t, "tenant-a", artifact, time.Unix(1, 0).UTC())
	write, err := store.NewRevisionWrite(metadata, artifact)
	if err != nil {
		t.Fatalf("NewRevisionWrite() error = %v", err)
	}
	artifact[0] ^= 0xff
	if bytes.Equal(write.Artifact(), artifact) {
		t.Fatal("RevisionWrite retained caller artifact bytes")
	}
	returned := write.Artifact()
	returned[0] ^= 0xff
	if bytes.Equal(write.Artifact(), returned) {
		t.Fatal("RevisionWrite.Artifact returned aliased bytes")
	}

	record, err := store.NewRevisionRecord(write.Metadata(), write.Artifact())
	if err != nil {
		t.Fatalf("NewRevisionRecord() error = %v", err)
	}
	if got := record.Metadata().ID(); got != metadata.ID() {
		t.Fatalf("record revision = %q, want %q", got, metadata.ID())
	}
	assertRedacted(t, write, "tenant-a")
	assertRedacted(t, record, "tenant-a")
}

func TestRevisionConstructorsRejectZeroForgedAndOversizedValues(t *testing.T) {
	t.Parallel()

	artifact := mustArtifactBytes(t, "entity user {}")
	metadata := mustRevisionMetadata(t, "tenant-a", artifact, time.Unix(1, 0).UTC())
	for name, call := range map[string]func() error{
		"zero metadata":  func() error { _, err := store.NewRevisionWrite(policyengine.RevisionMetadata{}, artifact); return err },
		"empty artifact": func() error { _, err := store.NewRevisionWrite(metadata, nil); return err },
		"oversized artifact": func() error {
			_, err := store.NewRevisionWrite(metadata, make([]byte, policyengine.MaxPolicyArtifactBytes+1))
			return err
		},
		"record digest mismatch": func() error {
			other := mustArtifactBytes(t, "entity document {}")
			_, err := store.NewRevisionRecord(metadata, other)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("error = nil")
			}
		})
	}
}

func mustArtifactBytes(t *testing.T, source string) []byte {
	t.Helper()
	artifact, err := dsl.CompileArtifact("conformance.dsl", []byte(source))
	if err != nil {
		t.Fatalf("CompileArtifact() error = %v", err)
	}
	encoded, err := artifact.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return encoded
}

func mustRevisionMetadata(t *testing.T, namespace string, encoded []byte, publishedAt time.Time) policyengine.RevisionMetadata {
	t.Helper()
	artifact, err := dsl.DecodeArtifact(encoded)
	if err != nil {
		t.Fatalf("DecodeArtifact() error = %v", err)
	}
	id, err := policyengine.RevisionIDFromArtifact(artifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	metadata, err := policyengine.NewRevisionMetadata(namespace, id, publishedAt)
	if err != nil {
		t.Fatalf("NewRevisionMetadata() error = %v", err)
	}
	return metadata
}

func assertRedacted(t *testing.T, value any, secret string) {
	t.Helper()
	for _, output := range []string{
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		fmt.Sprintf("%s", value),
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("%T formatting leaked secret in %q", value, output)
		}
	}
	var buffer bytes.Buffer
	slog.New(slog.NewTextHandler(&buffer, nil)).Info("value", "value", value)
	if strings.Contains(buffer.String(), secret) {
		t.Fatalf("%T slog leaked secret in %q", value, buffer.String())
	}
}
