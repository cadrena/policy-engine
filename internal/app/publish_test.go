package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	artifactloader "github.com/cadrena/policy-engine/internal/artifact"
	storecontract "github.com/cadrena/policy-engine/store"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestPublishClockPanicFailsClosedWithoutStorage(t *testing.T) {
	t.Parallel()

	adapter, err := memory.NewWithClock(fixedClock{now: time.Unix(100, 0).UTC()})
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, panicClock{})
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	request, err := policyengine.NewPublishRequest(
		"tenant-a",
		"policy.cdr",
		[]byte("entity user {}"),
	)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}

	_, err = service.Publish(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorInternal)
	listRequest, err := policyengine.NewListRevisionsRequest("tenant-a", "", 10)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	page, err := adapter.ListRevisions(context.Background(), listRequest)
	if err != nil {
		t.Fatalf("ListRevisions() error = %v", err)
	}
	if got := len(page.Revisions()); got != 0 {
		t.Fatalf("stored revisions = %d, want 0", got)
	}
}

func TestNewPolicyServiceRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	var nilStore *memory.Store
	var nilAuthorizer *allowAuthorizer
	var nilClock *fixedClock
	for name, dependencies := range map[string]struct {
		store      storecontract.Store
		authorizer policyengine.CallerAuthorizer
		clock      app.Clock
	}{
		"store":      {store: nilStore, authorizer: allowAuthorizer{}, clock: clock},
		"authorizer": {store: adapter, authorizer: nilAuthorizer, clock: clock},
		"clock":      {store: adapter, authorizer: allowAuthorizer{}, clock: nilClock},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.NewPolicyService(
				dependencies.store,
				dependencies.authorizer,
				dependencies.clock,
			)
			requireCategory(t, err, policyengine.ErrorInvalidArgument)
		})
	}
}

func TestRevisionAndActivationLookupsDoNotRevealCrossNamespaceExistence(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	ctx := context.Background()
	caller := mustCaller(t)
	published := publishSource(ctx, t, service, caller, "private.cdr", "entity private {}")
	missingArtifact, err := dsl.CompileArtifact("missing.cdr", []byte("entity missing {}"))
	if err != nil {
		t.Fatalf("CompileArtifact(missing) error = %v", err)
	}
	missingID, err := policyengine.RevisionIDFromArtifact(missingArtifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact(missing) error = %v", err)
	}

	crossRequest, err := policyengine.NewGetRevisionRequest(
		"tenant-b",
		published.Revision().ID(),
	)
	if err != nil {
		t.Fatalf("NewGetRevisionRequest(cross) error = %v", err)
	}
	_, crossErr := service.GetRevision(ctx, caller, crossRequest)
	requireCategory(t, crossErr, policyengine.ErrorNotFound)
	missingRequest, err := policyengine.NewGetRevisionRequest("tenant-b", missingID.String())
	if err != nil {
		t.Fatalf("NewGetRevisionRequest(missing) error = %v", err)
	}
	_, missingErr := service.GetRevision(ctx, caller, missingRequest)
	requireCategory(t, missingErr, policyengine.ErrorNotFound)
	if crossErr.Error() != missingErr.Error() {
		t.Fatalf("cross-namespace error = %q, absent error = %q", crossErr, missingErr)
	}

	crossActivation, err := policyengine.NewActivateRequest(
		"tenant-b",
		"stable",
		published.Revision().ID(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(cross) error = %v", err)
	}
	_, crossActivationErr := service.Activate(ctx, caller, crossActivation)
	requireCategory(t, crossActivationErr, policyengine.ErrorNotFound)
	missingActivation, err := policyengine.NewActivateRequest(
		"tenant-b",
		"stable",
		missingID.String(),
		policyengine.NewUnsetSlotExpectation(),
	)
	if err != nil {
		t.Fatalf("NewActivateRequest(missing) error = %v", err)
	}
	_, missingActivationErr := service.Activate(ctx, caller, missingActivation)
	requireCategory(t, missingActivationErr, policyengine.ErrorNotFound)
	if crossActivationErr.Error() != missingActivationErr.Error() {
		t.Fatalf(
			"cross-namespace activation error = %q, absent error = %q",
			crossActivationErr,
			missingActivationErr,
		)
	}

	listRequest, err := policyengine.NewListRevisionsRequest("tenant-b", "", 10)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	page, err := service.ListRevisions(ctx, caller, listRequest)
	if err != nil {
		t.Fatalf("ListRevisions() error = %v", err)
	}
	if got := len(page.Revisions()); got != 0 {
		t.Fatalf("tenant-b revisions = %d, want 0", got)
	}
}

func TestPublishRejectsCanonicalArtifactMismatchWithoutActivating(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	replacementArtifact, err := dsl.CompileArtifact("replacement.cdr", []byte("entity replacement {}"))
	if err != nil {
		t.Fatalf("CompileArtifact(replacement) error = %v", err)
	}
	replacementBytes, err := replacementArtifact.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(replacement) error = %v", err)
	}
	replacementID, err := policyengine.RevisionIDFromArtifact(replacementArtifact)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact(replacement) error = %v", err)
	}
	replacementMetadata, err := policyengine.NewRevisionMetadata("tenant-a", replacementID, clock.Now())
	if err != nil {
		t.Fatalf("NewRevisionMetadata(replacement) error = %v", err)
	}
	replacementRecord, err := storecontract.NewRevisionRecord(replacementMetadata, replacementBytes)
	if err != nil {
		t.Fatalf("NewRevisionRecord(replacement) error = %v", err)
	}
	replacementResult, err := storecontract.NewPutRevisionResult(replacementRecord, true)
	if err != nil {
		t.Fatalf("NewPutRevisionResult(replacement) error = %v", err)
	}
	hostile := &mismatchingStore{Store: adapter, replacement: replacementResult}
	service, err := app.NewPolicyService(hostile, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	request, err := policyengine.NewPublishRequest(
		"tenant-a",
		"policy.cdr",
		[]byte("entity user {}"),
	)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}

	_, err = service.Publish(context.Background(), mustCaller(t), request)
	requireCategory(t, err, policyengine.ErrorIntegrity)
	if got := hostile.activateCalls; got != 0 {
		t.Fatalf("Activate() calls = %d, want 0", got)
	}
	resolve, err := policyengine.NewResolveRequest("tenant-a", "stable")
	if err != nil {
		t.Fatalf("NewResolveRequest() error = %v", err)
	}
	_, err = adapter.Resolve(context.Background(), resolve)
	requireCategory(t, err, policyengine.ErrorNotFound)
}

func TestPublishRejectsAuthoritativeResultsWithInvalidCreationProvenance(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	request, err := policyengine.NewPublishRequest(
		"tenant-a",
		"policy.cdr",
		[]byte("entity user {}"),
	)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	tests := map[string]func(testing.TB, storecontract.RevisionWrite) storecontract.PutRevisionResult{
		"created result strips provenance": func(t testing.TB, write storecontract.RevisionWrite) storecontract.PutRevisionResult {
			t.Helper()
			record, err := storecontract.NewRevisionRecord(write.Metadata(), write.Artifact())
			if err != nil {
				t.Fatalf("NewRevisionRecord() error = %v", err)
			}
			result, err := storecontract.NewPutRevisionResult(record, true)
			if err != nil {
				t.Fatalf("NewPutRevisionResult() error = %v", err)
			}
			return result
		},
		"created result alters provenance": func(t testing.TB, write storecontract.RevisionWrite) storecontract.PutRevisionResult {
			t.Helper()
			alteredRequest, err := policyengine.NewPublishRequest(
				write.Metadata().Namespace(),
				"altered.cdr",
				[]byte("entity altered {}"),
			)
			if err != nil {
				t.Fatalf("NewPublishRequest(altered) error = %v", err)
			}
			provenance, err := storecontract.NewRevisionProvenance(alteredRequest)
			if err != nil {
				t.Fatalf("NewRevisionProvenance(altered) error = %v", err)
			}
			alteredWrite, err := storecontract.NewRevisionWriteWithProvenance(
				write.Metadata(),
				write.Artifact(),
				provenance,
			)
			if err != nil {
				t.Fatalf("NewRevisionWriteWithProvenance(altered) error = %v", err)
			}
			record, err := storecontract.NewRevisionRecordFromWrite(alteredWrite)
			if err != nil {
				t.Fatalf("NewRevisionRecordFromWrite(altered) error = %v", err)
			}
			result, err := storecontract.NewPutRevisionResult(record, true)
			if err != nil {
				t.Fatalf("NewPutRevisionResult() error = %v", err)
			}
			return result
		},
		"created result alters publication time": func(t testing.TB, write storecontract.RevisionWrite) storecontract.PutRevisionResult {
			t.Helper()
			id, err := policyengine.ParseRevisionID(write.Metadata().ID())
			if err != nil {
				t.Fatalf("ParseRevisionID() error = %v", err)
			}
			metadata, err := policyengine.NewRevisionMetadata(
				write.Metadata().Namespace(),
				id,
				write.Metadata().PublishedAt().Add(time.Second),
			)
			if err != nil {
				t.Fatalf("NewRevisionMetadata(altered) error = %v", err)
			}
			alteredWrite, err := storecontract.NewRevisionWriteWithProvenance(
				metadata,
				write.Artifact(),
				write.Provenance(),
			)
			if err != nil {
				t.Fatalf("NewRevisionWriteWithProvenance(altered) error = %v", err)
			}
			record, err := storecontract.NewRevisionRecordFromWrite(alteredWrite)
			if err != nil {
				t.Fatalf("NewRevisionRecordFromWrite(altered) error = %v", err)
			}
			result, err := storecontract.NewPutRevisionResult(record, true)
			if err != nil {
				t.Fatalf("NewPutRevisionResult() error = %v", err)
			}
			return result
		},
		"reused result strips first-writer provenance": func(t testing.TB, write storecontract.RevisionWrite) storecontract.PutRevisionResult {
			t.Helper()
			record, err := storecontract.NewRevisionRecord(write.Metadata(), write.Artifact())
			if err != nil {
				t.Fatalf("NewRevisionRecord() error = %v", err)
			}
			result, err := storecontract.NewPutRevisionResult(record, false)
			if err != nil {
				t.Fatalf("NewPutRevisionResult() error = %v", err)
			}
			return result
		},
	}
	for name, transform := range tests {
		transform := transform
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adapter, err := memory.NewWithClock(clock)
			if err != nil {
				t.Fatalf("memory.NewWithClock() error = %v", err)
			}
			hostile := &transformingRevisionStore{
				Store: adapter,
				transform: func(write storecontract.RevisionWrite) storecontract.PutRevisionResult {
					return transform(t, write)
				},
			}
			service, err := app.NewPolicyService(hostile, allowAuthorizer{}, clock)
			if err != nil {
				t.Fatalf("NewPolicyService() error = %v", err)
			}

			_, err = service.Publish(context.Background(), mustCaller(t), request)
			requireCategory(t, err, policyengine.ErrorIntegrity)
		})
	}
}

func TestPublishStoresCanonicalArtifactAndReusesEquivalentRevision(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	caller := mustCaller(t)
	original := []byte("entity user {}")
	request, err := policyengine.NewPublishRequest("tenant-a", "first.cdr", original)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}

	published, err := service.Publish(context.Background(), caller, request)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if !published.Created() {
		t.Fatal("first Publish() Created() = false")
	}
	getRequest, err := policyengine.NewGetRevisionRequest(
		"tenant-a",
		published.Revision().ID(),
	)
	if err != nil {
		t.Fatalf("NewGetRevisionRequest() error = %v", err)
	}
	stored, err := adapter.GetRevision(context.Background(), getRequest)
	if err != nil {
		t.Fatalf("GetRevision() error = %v", err)
	}
	decoded, err := dsl.DecodeArtifact(stored.Artifact())
	if err != nil {
		t.Fatalf("DecodeArtifact() error = %v", err)
	}
	if got := decoded.CanonicalSource(); bytes.Equal(got, original) {
		t.Fatalf("CanonicalSource() = %q, want canonical form distinct from original formatting", got)
	}
	if got := decoded.CanonicalIR(); len(got) == 0 {
		t.Fatal("CanonicalIR() is empty")
	}
	manifest := decoded.Manifest()
	if manifest.FormatVersion != dsl.ArtifactFormatV1 ||
		manifest.LanguageVersion != dsl.LanguageVersionV1 ||
		manifest.EvaluatorABI != dsl.EvaluatorABIV1 {
		t.Fatalf("Manifest() = %#v, want supported v1 metadata", manifest)
	}
	id, err := policyengine.RevisionIDFromArtifact(decoded)
	if err != nil {
		t.Fatalf("RevisionIDFromArtifact() error = %v", err)
	}
	if got, want := published.Revision().ID(), id.String(); got != want {
		t.Fatalf("published revision ID = %q, want artifact digest %q", got, want)
	}
	if got, want := stored.Provenance().SourceName(), "first.cdr"; got != want {
		t.Fatalf("stored SourceName() = %q, want %q", got, want)
	}
	if got, want := stored.Provenance().OriginalSourceDigest(), sha256.Sum256(original); got != want {
		t.Fatalf("stored source digest = %x, want %x", got, want)
	}

	equivalentRequest, err := policyengine.NewPublishRequest(
		"tenant-a",
		"equivalent.cdr",
		[]byte("entity user {\n}\n"),
	)
	if err != nil {
		t.Fatalf("NewPublishRequest(equivalent) error = %v", err)
	}
	reused, err := service.Publish(context.Background(), caller, equivalentRequest)
	if err != nil {
		t.Fatalf("Publish(equivalent) error = %v", err)
	}
	if reused.Created() {
		t.Fatal("Publish(equivalent) Created() = true")
	}
	if got, want := reused.Revision().ID(), published.Revision().ID(); got != want {
		t.Fatalf("equivalent revision ID = %q, want %q", got, want)
	}
	storedAgain, err := adapter.GetRevision(context.Background(), getRequest)
	if err != nil {
		t.Fatalf("GetRevision(after equivalent) error = %v", err)
	}
	if got, want := storedAgain.Provenance().SourceName(), "first.cdr"; got != want {
		t.Fatalf("provenance after equivalent publish = %q, want first-writer %q", got, want)
	}
}

func TestPublishInvalidDSLReturnsStructuredDiagnosticsAndStoresNothing(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Unix(100, 0).UTC()}
	adapter, err := memory.NewWithClock(clock)
	if err != nil {
		t.Fatalf("memory.NewWithClock() error = %v", err)
	}
	service, err := app.NewPolicyService(adapter, allowAuthorizer{}, clock)
	if err != nil {
		t.Fatalf("NewPolicyService() error = %v", err)
	}
	request, err := policyengine.NewPublishRequest(
		"tenant-a",
		"broken.cdr",
		[]byte("entity document { relation viewer"),
	)
	if err != nil {
		t.Fatalf("NewPublishRequest() error = %v", err)
	}
	caller := mustCaller(t)

	if _, err = service.Publish(context.Background(), caller, request); err == nil {
		t.Fatal("Publish() error = nil")
	}
	var artifactError *dsl.ArtifactError
	if !errors.As(err, &artifactError) {
		t.Fatalf("Publish() error type = %T, want *dsl.ArtifactError", err)
	}
	if got, want := artifactError.Code, dsl.ArtifactErrorCodeSourceInvalid; got != want {
		t.Fatalf("artifact error code = %q, want %q", got, want)
	}
	diagnostics := artifactError.Diagnostics()
	if len(diagnostics) == 0 || diagnostics[0].Source != "broken.cdr" || diagnostics[0].Code == "" {
		t.Fatalf("artifact diagnostics = %#v, want located stable diagnostic", diagnostics)
	}
	listRequest, err := policyengine.NewListRevisionsRequest("tenant-a", "", 10)
	if err != nil {
		t.Fatalf("NewListRevisionsRequest() error = %v", err)
	}
	page, err := adapter.ListRevisions(context.Background(), listRequest)
	if err != nil {
		t.Fatalf("ListRevisions() error = %v", err)
	}
	if got := len(page.Revisions()); got != 0 {
		t.Fatalf("stored revisions = %d, want 0", got)
	}
}

func TestLoaderInvalidArtifactReturnsStructuredArtifactError(t *testing.T) {
	t.Parallel()

	_, err := artifactloader.NewLoader().Decode([]byte("not-an-artifact"))
	if err == nil {
		t.Fatal("Decode() error = nil")
	}
	var artifactError *dsl.ArtifactError
	if !errors.As(err, &artifactError) {
		t.Fatalf("Decode() error type = %T, want *dsl.ArtifactError", err)
	}
	if artifactError.Code == "" || artifactError.Message == "" {
		t.Fatalf("artifact error = %#v, want structured code and message", artifactError)
	}
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time { return c.now }

type panicClock struct{}

func (panicClock) Now() time.Time { panic("clock secret") }

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(
	_ context.Context,
	_ policyengine.Caller,
	namespace string,
	required []policyengine.Capability,
) (policyengine.CallerAuthorization, error) {
	grant, err := policyengine.NewGrant(namespace, required)
	if err != nil {
		return policyengine.CallerAuthorization{}, err
	}
	return policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
}

func mustCaller(t testing.TB) policyengine.Caller {
	t.Helper()
	caller, err := policyengine.NewCaller("embedded-test", nil)
	if err != nil {
		t.Fatalf("NewCaller() error = %v", err)
	}
	return caller
}

type mismatchingStore struct {
	*memory.Store
	replacement   storecontract.PutRevisionResult
	activateCalls int
}

type transformingRevisionStore struct {
	*memory.Store
	transform func(storecontract.RevisionWrite) storecontract.PutRevisionResult
}

func (s *transformingRevisionStore) PutRevision(
	_ context.Context,
	write storecontract.RevisionWrite,
) (storecontract.PutRevisionResult, error) {
	return s.transform(write), nil
}

func (s *mismatchingStore) PutRevision(
	context.Context,
	storecontract.RevisionWrite,
) (storecontract.PutRevisionResult, error) {
	return s.replacement, nil
}

func (s *mismatchingStore) Activate(
	ctx context.Context,
	request policyengine.ActivateRequest,
) (policyengine.ActivateResponse, error) {
	s.activateCalls++
	return s.Store.Activate(ctx, request)
}

func requireCategory(t testing.TB, err error, want policyengine.ErrorCategory) {
	t.Helper()
	var engineError *policyengine.EngineError
	if !errors.As(err, &engineError) || engineError.Category() != want {
		t.Fatalf("error = %#v, want %s", err, want)
	}
}
