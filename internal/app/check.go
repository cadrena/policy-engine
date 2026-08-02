package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	artifactloader "github.com/cadrena/policy-engine/internal/artifact"
	"github.com/cadrena/policy-engine/internal/cache"
	"github.com/cadrena/policy-engine/internal/domain"
	"github.com/cadrena/policy-engine/internal/evaluator"
	"github.com/cadrena/policy-engine/store"
)

// AuthorizationDependencies contains the required local decision-core ports.
type AuthorizationDependencies struct {
	Revisions          store.RevisionStore
	Slots              store.SlotStore
	Data               store.DataReader
	RevisionCache      *cache.RevisionCache
	PointerCache       *cache.PointerCache
	CallerAuthorizer   policyengine.CallerAuthorizer
	ApprovalVerifier   policyengine.ApprovalVerifier
	DelegationVerifier policyengine.DelegationVerifier
	DecisionSink       policyengine.DecisionEventSink
	Clock              func() time.Time
}

// AuthorizationService implements revision- and data-pinned authorization.
type AuthorizationService struct {
	dependencies AuthorizationDependencies
	loader       artifactloader.Loader
}

// NewAuthorizationService constructs a fail-closed authorization service.
func NewAuthorizationService(dependencies AuthorizationDependencies) (*AuthorizationService, error) {
	if nilDependency(dependencies.Revisions) || nilDependency(dependencies.Slots) ||
		nilDependency(dependencies.Data) || nilDependency(dependencies.RevisionCache) ||
		nilDependency(dependencies.PointerCache) || nilDependency(dependencies.CallerAuthorizer) ||
		nilDependency(dependencies.Clock) {
		return nil, appError(policyengine.ErrorInvalidArgument)
	}
	if nilDependency(dependencies.ApprovalVerifier) {
		dependencies.ApprovalVerifier = policyengine.DefaultApprovalVerifier()
	}
	if nilDependency(dependencies.DelegationVerifier) {
		dependencies.DelegationVerifier = policyengine.DefaultDelegationVerifier()
	}
	if nilDependency(dependencies.DecisionSink) {
		dependencies.DecisionSink = policyengine.DefaultDecisionEventSink()
	}
	return &AuthorizationService{dependencies: dependencies, loader: artifactloader.NewLoader()}, nil
}

// Check evaluates one request against one exact revision and data generation.
func (s *AuthorizationService) Check(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.CheckRequest,
) (policyengine.CheckResponse, error) {
	validated, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: request.Namespace(), Selector: request.Selector(), Subject: request.Subject(),
		Resource: request.Resource(), Action: request.Action(), Arguments: request.Arguments(),
		ContextualData: request.ContextualData(), ApprovalEvidence: request.ApprovalEvidence(),
		DelegationEvidence: request.DelegationEvidence(), MinimumGeneration: request.MinimumGeneration(),
	})
	if err != nil {
		return policyengine.CheckResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(ctx, s.dependencies.CallerAuthorizer, caller,
		validated.Namespace(), validated.RequiredCapabilities()); err != nil {
		return policyengine.CheckResponse{}, err
	}
	pin, err := s.resolveRevision(ctx, validated)
	if err != nil {
		return policyengine.CheckResponse{}, err
	}
	hydrated, err := s.loadRevision(ctx, pin)
	if err != nil {
		return policyengine.CheckResponse{}, err
	}
	evaluatedAt, err := s.evaluationTime()
	if err != nil {
		return policyengine.CheckResponse{}, err
	}

	snapshot, err := s.openExactSnapshot(ctx, validated, evaluatedAt)
	if err != nil {
		return policyengine.CheckResponse{}, err
	}
	result, resultErr := s.evaluatePinned(ctx, caller, validated, pin, hydrated, snapshot, evaluatedAt)
	closeErr := snapshot.Close()
	if resultErr != nil {
		return policyengine.CheckResponse{}, resultErr
	}
	if closeErr != nil {
		return policyengine.CheckResponse{}, sanitizeRuntimeError(closeErr, policyengine.ErrorInternal)
	}
	response, err := policyengine.NewCheckResponse(validated, result)
	if err != nil {
		return policyengine.CheckResponse{}, appError(policyengine.ErrorInternal)
	}
	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision: result.Decision(), ReasonCode: result.ReasonCode(), RevisionID: result.RevisionID(),
		SlotGeneration: result.SlotGeneration(), DataGeneration: result.DataGeneration(),
		CompletedAt: result.EvaluatedAt(), UsedContextualData: result.UsedContextualData(),
		UsedApproval: result.UsedApproval(), UsedDelegation: result.UsedDelegation(),
	})
	if err == nil {
		_ = policyengine.DeliverDecisionEvent(ctx, s.dependencies.DecisionSink, event)
	}
	return response, nil
}

func (s *AuthorizationService) loadRevision(ctx context.Context, pin resolvedRevision) (cache.HydratedRevision, error) {
	key, err := cache.NewRevisionKey(pin.namespace, pin.revisionID, dsl.EvaluatorABIV1)
	if err != nil {
		return cache.HydratedRevision{}, appError(policyengine.ErrorInternal)
	}
	value, err := s.dependencies.RevisionCache.GetOrLoad(ctx, key, func(loadCtx context.Context) (*dsl.Artifact, error) {
		request, requestErr := policyengine.NewGetRevisionRequest(pin.namespace, pin.revisionID)
		if requestErr != nil {
			return nil, requestErr
		}
		record, getErr := s.dependencies.Revisions.GetRevision(loadCtx, request)
		if getErr != nil {
			return nil, getErr
		}
		metadata := record.Metadata()
		if !record.Valid() || metadata.Namespace() != pin.namespace || metadata.ID() != pin.revisionID {
			return nil, appError(policyengine.ErrorIntegrity)
		}
		artifact, decodeErr := s.loader.Decode(record.Artifact())
		if decodeErr != nil {
			return nil, appError(policyengine.ErrorIntegrity)
		}
		return artifact, nil
	})
	if err != nil {
		return cache.HydratedRevision{}, sanitizeRuntimeError(err, policyengine.ErrorInternal)
	}
	if value.Program() == nil || value.Artifact() == nil {
		return cache.HydratedRevision{}, appError(policyengine.ErrorIntegrity)
	}
	return value, nil
}

func (s *AuthorizationService) openExactSnapshot(ctx context.Context, request policyengine.CheckRequest, readAt time.Time) (store.Snapshot, error) {
	headRequest, err := policyengine.NewGetDataGenerationRequest(request.Namespace())
	if err != nil {
		return nil, err
	}
	head, err := s.dependencies.Data.GetDataGeneration(ctx, headRequest)
	if err != nil {
		return nil, sanitizeRuntimeError(err, policyengine.ErrorUnavailable)
	}
	if !head.Valid() {
		return nil, appError(policyengine.ErrorIntegrity)
	}
	minimum := request.MinimumGeneration()
	if head.Generation() > minimum {
		minimum = head.Generation()
	}
	snapshotRequest, err := store.NewSnapshotRequest(request.Namespace(), minimum, readAt)
	if err != nil {
		return nil, err
	}
	snapshot, err := s.dependencies.Data.OpenSnapshot(ctx, snapshotRequest)
	if err != nil {
		return nil, sanitizeRuntimeError(err, policyengine.ErrorUnavailable)
	}
	if nilDependency(snapshot) || snapshot.Namespace() != request.Namespace() ||
		snapshot.ReadAt() != readAt || snapshot.Generation() != head.Generation() ||
		snapshot.Generation() < request.MinimumGeneration() {
		if !nilDependency(snapshot) {
			_ = snapshot.Close()
		}
		return nil, appError(policyengine.ErrorFailedPrecondition)
	}
	return snapshot, nil
}

func (s *AuthorizationService) evaluatePinned(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.CheckRequest,
	pin resolvedRevision,
	hydrated cache.HydratedRevision,
	snapshot store.Snapshot,
	evaluatedAt time.Time,
) (policyengine.DecisionResult, error) {
	fingerprint := checkFingerprint(request)
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: request.Namespace(), Selector: request.Selector(),
		RevisionID: pin.revisionID, SlotGeneration: pin.slotGeneration,
		DataGeneration: snapshot.Generation(), EvaluatedAt: evaluatedAt,
		Fingerprint: policyengine.NewEvidenceFingerprint(fingerprint),
	})
	if err != nil {
		return policyengine.DecisionResult{}, appError(policyengine.ErrorInternal)
	}
	contextual := request.ContextualData()
	usedDelegation := false
	if evidence := request.DelegationEvidence(); len(evidence) != 0 {
		verification, requestErr := policyengine.NewDelegationVerificationRequest(binding, evidence)
		if requestErr != nil {
			return policyengine.DecisionResult{}, requestErr
		}
		verified, verifyErr := policyengine.InvokeDelegationVerifier(ctx, s.dependencies.DelegationVerifier, verification)
		if verifyErr != nil {
			return policyengine.DecisionResult{}, verifyErr
		}
		delegated := verified.ContextualData()
		contextual, err = policyengine.NewContextualData(
			append(contextual.Tuples(), delegated.Tuples()...),
			append(contextual.Attributes(), delegated.Attributes()...),
		)
		if err != nil {
			return policyengine.DecisionResult{}, err
		}
		usedDelegation = true
	}
	usedContextualData := !contextual.Empty()
	schema, err := domain.NewDataSchema(hydrated.Artifact())
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	contextual, err = schema.NormalizeContextualData(ctx, snapshot, contextual)
	if err != nil {
		return policyengine.DecisionResult{}, sanitizeRuntimeError(err, policyengine.ErrorInternal)
	}
	reader, err := evaluator.NewSnapshotReader(snapshot, contextual)
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	arguments, err := evaluator.ResolveArguments(request.Arguments())
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	dslResult, err := hydrated.Program().Check(ctx, dsl.Request{
		Subject: request.Subject(), Resource: request.Resource(), Action: request.Action(), Arguments: arguments,
	}, reader)
	if err != nil {
		return policyengine.DecisionResult{}, sanitizeRuntimeError(err, policyengine.ErrorFailedPrecondition)
	}
	decision, requirements, usedApproval, err := s.finalizeApproval(ctx, binding, request.ApprovalEvidence(), dslResult)
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	decisionDigest := sha256.Sum256(append(fingerprint[:], byte(decision)))
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision: decision, DecisionID: hex.EncodeToString(decisionDigest[:]), ReasonCode: dslResult.Reason,
		RevisionID: pin.revisionID, SlotGeneration: pin.slotGeneration, DataGeneration: snapshot.Generation(),
		EvaluatedAt: evaluatedAt, Requirements: requirements, UsedContextualData: usedContextualData,
		UsedApproval: usedApproval, UsedDelegation: usedDelegation,
	})
	if err != nil {
		return policyengine.DecisionResult{}, appError(policyengine.ErrorInternal)
	}
	return result, nil
}

func (s *AuthorizationService) finalizeApproval(ctx context.Context, binding policyengine.EvidenceBinding, evidence []byte, result dsl.Result) (policyengine.Decision, []string, bool, error) {
	if len(result.RequiredApprovals) == 0 && len(evidence) != 0 {
		return 0, nil, false, appError(policyengine.ErrorFailedPrecondition)
	}
	if result.Decision == dsl.DecisionDeny {
		return policyengine.DecisionDeny, nil, false, nil
	}
	if result.Decision == dsl.DecisionAllow {
		return policyengine.DecisionAllow, nil, false, nil
	}
	if result.Decision != dsl.DecisionRequireApproval || len(result.RequiredApprovals) == 0 {
		return 0, nil, false, appError(policyengine.ErrorInternal)
	}
	requirements := append([]string(nil), result.RequiredApprovals...)
	sort.Strings(requirements)
	if len(evidence) == 0 {
		return policyengine.DecisionRequireApproval, requirements, false, nil
	}
	verification, err := policyengine.NewApprovalVerificationRequest(binding, requirements, evidence)
	if err != nil {
		return 0, nil, false, err
	}
	verified, err := policyengine.InvokeApprovalVerifier(ctx, s.dependencies.ApprovalVerifier, verification)
	if err != nil {
		return 0, nil, false, err
	}
	satisfied := verified.SatisfiedRequirementIDs()
	unsatisfied := make([]string, 0, len(requirements))
	index := 0
	for _, requirement := range requirements {
		for index < len(satisfied) && satisfied[index] < requirement {
			index++
		}
		if index == len(satisfied) || satisfied[index] != requirement {
			unsatisfied = append(unsatisfied, requirement)
		}
	}
	if len(unsatisfied) == 0 {
		return policyengine.DecisionAllow, nil, true, nil
	}
	return policyengine.DecisionRequireApproval, unsatisfied, true, nil
}

func (s *AuthorizationService) evaluationTime() (value time.Time, err error) {
	defer func() {
		if recover() != nil {
			value, err = time.Time{}, appError(policyengine.ErrorInternal)
		}
	}()
	value = s.dependencies.Clock()
	if value.IsZero() {
		return time.Time{}, appError(policyengine.ErrorInternal)
	}
	return value, nil
}

func sanitizeRuntimeError(err error, fallback policyengine.ErrorCategory) error {
	if err == nil {
		return nil
	}
	var engineErr *policyengine.EngineError
	if errors.As(err, &engineErr) {
		return appError(engineErr.Category())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return appError(policyengine.ErrorDeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) {
		return appError(policyengine.ErrorCanceled)
	}
	return appError(fallback)
}

func checkFingerprint(request policyengine.CheckRequest) [sha256.Size]byte {
	hash := sha256.New()
	writeFingerprintString(hash, request.Namespace())
	if slot, ok := request.Selector().Slot(); ok {
		writeFingerprintString(hash, "slot")
		writeFingerprintString(hash, slot)
	} else if revision, ok := request.Selector().ExactRevision(); ok {
		writeFingerprintString(hash, "revision")
		writeFingerprintString(hash, revision)
	}
	writeEntityFingerprint(hash, request.Subject())
	writeEntityFingerprint(hash, request.Resource())
	writeFingerprintString(hash, request.Action())
	keys := make([]string, 0, len(request.Arguments()))
	for key := range request.Arguments() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	arguments := request.Arguments()
	for _, key := range keys {
		writeFingerprintString(hash, key)
		writeValueFingerprint(hash, arguments[key])
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], request.MinimumGeneration())
	_, _ = hash.Write(number[:])
	for _, tuple := range request.ContextualData().Tuples() {
		value := tuple.Tuple()
		writeEntityFingerprint(hash, value.Resource)
		writeFingerprintString(hash, value.Relation)
		writeFingerprintString(hash, value.Subject.Type)
		writeFingerprintString(hash, value.Subject.ID)
		writeFingerprintString(hash, value.Subject.Relation)
		if expiry, ok := tuple.ExpiresAt(); ok {
			writeFingerprintString(hash, expiry.UTC().Format(time.RFC3339Nano))
		} else {
			writeFingerprintString(hash, "")
		}
	}
	for _, attribute := range request.ContextualData().Attributes() {
		writeEntityFingerprint(hash, attribute.Entity())
		for _, segment := range attribute.Path() {
			writeFingerprintString(hash, segment)
		}
		writeValueFingerprint(hash, attribute.Value())
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeEntityFingerprint(hash interface{ Write([]byte) (int, error) }, entity dsl.EntityRef) {
	writeFingerprintString(hash, entity.Type)
	writeFingerprintString(hash, entity.ID)
}

func writeFingerprintString(hash interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(value))
}

func writeValueFingerprint(hash interface{ Write([]byte) (int, error) }, value policyengine.Value) {
	_, _ = hash.Write([]byte{byte(value.Kind())})
	switch value.Kind() {
	case policyengine.ValueKindString:
		text, _ := value.StringValue()
		writeFingerprintString(hash, text)
	case policyengine.ValueKindInteger:
		integer, _ := value.Integer()
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(integer))
		_, _ = hash.Write(encoded[:])
	case policyengine.ValueKindBoolean:
		boolean, _ := value.Boolean()
		if boolean {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
	}
}
