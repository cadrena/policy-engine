package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	artifactloader "github.com/cadrena/policy-engine/internal/artifact"
	"github.com/cadrena/policy-engine/internal/cache"
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
	session, err := s.openEvaluationSession(ctx, caller, validated, checkFingerprint(validated), nil)
	if err != nil {
		return policyengine.CheckResponse{}, err
	}
	result, resultErr := s.evaluateSessionItem(ctx, session, validated.Subject(), validated.Resource(), validated.Action(), validated.Arguments())
	closeErr := session.close()
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
	s.deliverDecisionEvent(ctx, result)
	return response, nil
}

func (s *AuthorizationService) deliverDecisionEvent(ctx context.Context, result policyengine.DecisionResult) {
	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision: result.Decision(), ReasonCode: result.ReasonCode(), RevisionID: result.RevisionID(),
		SlotGeneration: result.SlotGeneration(), DataGeneration: result.DataGeneration(),
		CompletedAt: result.EvaluatedAt(), UsedContextualData: result.UsedContextualData(),
		UsedApproval: result.UsedApproval(), UsedDelegation: result.UsedDelegation(),
	})
	if err == nil {
		_ = policyengine.DeliverDecisionEvent(ctx, s.dependencies.DecisionSink, event)
	}
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

func (s *AuthorizationService) openExactSnapshot(ctx context.Context, request interface {
	Namespace() string
	MinimumGeneration() uint64
}, readAt time.Time) (store.Snapshot, error) {
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

func (s *AuthorizationService) evaluateSessionItem(
	ctx context.Context,
	session evaluationSession,
	subject dsl.EntityRef,
	resource dsl.EntityRef,
	action string,
	inputArguments map[string]policyengine.Value,
) (policyengine.DecisionResult, error) {
	arguments, err := evaluator.ResolveArguments(inputArguments)
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	dslResult, err := session.program.Check(ctx, dsl.Request{
		Subject: subject, Resource: resource, Action: action, Arguments: arguments,
	}, session.tupleReader)
	if err != nil {
		return policyengine.DecisionResult{}, sanitizeEvaluationError(err)
	}
	if session.graphBudget != nil {
		if err := session.graphBudget.add(len(dslResult.Trace), 0); err != nil {
			return policyengine.DecisionResult{}, err
		}
	}
	decision, requirements, usedApproval, err := s.finalizeApproval(ctx, session.binding, session.approvalEvidence, dslResult, session.verifierBudget)
	if err != nil {
		return policyengine.DecisionResult{}, err
	}
	itemFingerprint := sha256.New()
	batchBinding := session.binding.Fingerprint().Bytes()
	_, _ = itemFingerprint.Write(batchBinding[:])
	if session.batch {
		writeEntityFingerprint(itemFingerprint, subject)
		writeEntityFingerprint(itemFingerprint, resource)
		writeFingerprintString(itemFingerprint, action)
		writeArgumentsFingerprint(itemFingerprint, inputArguments)
	}
	_, _ = itemFingerprint.Write([]byte{byte(decision)})
	decisionDigest := itemFingerprint.Sum(nil)
	result, err := policyengine.NewDecisionResult(policyengine.DecisionResultInput{
		Decision: decision, DecisionID: hex.EncodeToString(decisionDigest), ReasonCode: dslResult.Reason,
		RevisionID: session.revisionID, SlotGeneration: session.slotGeneration, DataGeneration: session.dataGeneration,
		EvaluatedAt: session.evaluatedAt, Requirements: requirements, UsedContextualData: session.usedContextualData,
		UsedApproval: usedApproval, UsedDelegation: session.usedDelegation,
	})
	if err != nil {
		return policyengine.DecisionResult{}, appError(policyengine.ErrorInternal)
	}
	return result, nil
}

func (s *AuthorizationService) finalizeApproval(ctx context.Context, binding policyengine.EvidenceBinding, evidence []byte, result dsl.Result, budget *batchWorkBudget) (policyengine.Decision, []string, bool, error) {
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
	verifiedBytes := 8
	for _, identifier := range satisfied {
		verifiedBytes += 8 + len(identifier)
	}
	if err := budget.add(len(satisfied), verifiedBytes); err != nil {
		return 0, nil, false, err
	}
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
	if engineErr, ok := err.(*policyengine.EngineError); ok && engineErr != nil {
		return appError(engineErr.Category())
	}
	if err == context.DeadlineExceeded {
		return appError(policyengine.ErrorDeadlineExceeded)
	}
	if err == context.Canceled {
		return appError(policyengine.ErrorCanceled)
	}
	return appError(fallback)
}

func sanitizeEvaluationError(err error) error {
	checkErr, ok := err.(*dsl.CheckError)
	if !ok || checkErr == nil {
		return sanitizeRuntimeError(err, policyengine.ErrorFailedPrecondition)
	}
	switch checkErr.Code {
	case "E_CHECK_MAX_DEPTH":
		return appError(policyengine.ErrorResourceExhausted)
	case "E_CHECK_CONTEXT", "E_CHECK_TUPLE_READER":
		return sanitizeRuntimeError(checkErr.Cause, policyengine.ErrorFailedPrecondition)
	default:
		return appError(policyengine.ErrorFailedPrecondition)
	}
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
	writeArgumentsFingerprint(hash, request.Arguments())
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], request.MinimumGeneration())
	_, _ = hash.Write(number[:])
	writeContextualFingerprint(hash, request.ContextualData())
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeArgumentsFingerprint(hash interface{ Write([]byte) (int, error) }, arguments map[string]policyengine.Value) {
	keys := make([]string, 0, len(arguments))
	for key := range arguments {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeFingerprintString(hash, key)
		writeValueFingerprint(hash, arguments[key])
	}
}

func writeContextualFingerprint(hash interface{ Write([]byte) (int, error) }, contextual policyengine.ContextualData) {
	for _, tuple := range contextual.Tuples() {
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
	for _, attribute := range contextual.Attributes() {
		writeEntityFingerprint(hash, attribute.Entity())
		for _, segment := range attribute.Path() {
			writeFingerprintString(hash, segment)
		}
		writeValueFingerprint(hash, attribute.Value())
	}
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
