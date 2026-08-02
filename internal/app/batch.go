package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/domain"
	"github.com/cadrena/policy-engine/internal/evaluator"
)

type evaluationSession struct {
	revisionID     string
	slotGeneration uint64
	dataGeneration uint64
	evaluatedAt    time.Time
	program        *dsl.Program
	artifact       *dsl.Artifact
	reader         *evaluator.SnapshotReader
	close          func() error

	binding            policyengine.EvidenceBinding
	usedContextualData bool
	usedDelegation     bool
	approvalEvidence   []byte
	tupleReader        dsl.TupleReader
	verifierBudget     *batchWorkBudget
	graphBudget        *batchWorkBudget
	batch              bool
}

type sharedEvaluationRequest interface {
	Namespace() string
	Selector() policyengine.Selector
	ContextualData() policyengine.ContextualData
	ApprovalEvidence() []byte
	DelegationEvidence() []byte
	MinimumGeneration() uint64
}

type batchWorkBudget struct {
	items    int
	bytes    int
	maxItems int
	maxBytes int
}

func (b *batchWorkBudget) add(items, bytes int) error {
	if b == nil {
		return nil
	}
	if items < 0 || bytes < 0 || items > b.maxItems-b.items || bytes > b.maxBytes-b.bytes {
		return appError(policyengine.ErrorResourceExhausted)
	}
	b.items += items
	b.bytes += bytes
	return nil
}

type budgetedTupleReader struct {
	reader dsl.TupleReader
	budget *batchWorkBudget
}

func (r *budgetedTupleReader) ReadTuples(ctx context.Context, resource dsl.EntityRef, relation string) ([]dsl.SubjectRef, error) {
	subjects, err := r.reader.ReadTuples(ctx, resource, relation)
	if err != nil {
		return nil, err
	}
	if err := r.budget.add(1+len(subjects), 0); err != nil {
		return nil, err
	}
	return subjects, nil
}

// BatchCheck evaluates every item against one exact revision and data snapshot.
func (s *AuthorizationService) BatchCheck(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.BatchCheckRequest,
) (policyengine.BatchCheckResponse, error) {
	validated, err := policyengine.NewBatchCheckRequest(policyengine.BatchCheckRequestInput{
		Namespace: request.Namespace(), Selector: request.Selector(), Items: request.Items(),
		ContextualData: request.ContextualData(), ApprovalEvidence: request.ApprovalEvidence(),
		DelegationEvidence: request.DelegationEvidence(), MinimumGeneration: request.MinimumGeneration(),
	})
	if err != nil {
		return policyengine.BatchCheckResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(ctx, s.dependencies.CallerAuthorizer, caller,
		validated.Namespace(), validated.RequiredCapabilities()); err != nil {
		return policyengine.BatchCheckResponse{}, err
	}
	verifierBudget := &batchWorkBudget{maxItems: policyengine.MaxVerifierOutputItems, maxBytes: policyengine.MaxVerifierOutputBytes}
	session, err := s.openEvaluationSession(ctx, caller, validated, batchFingerprint(validated), verifierBudget)
	if err != nil {
		return policyengine.BatchCheckResponse{}, err
	}

	items := validated.Items()
	results := make([]policyengine.DecisionResult, 0, len(items))
	graphBudget := &batchWorkBudget{maxItems: policyengine.MaxAggregateWorkItems}
	session.batch = true
	session.graphBudget = graphBudget
	session.tupleReader = &budgetedTupleReader{reader: session.reader, budget: graphBudget}
	for _, item := range items {
		if err := sanitizeRuntimeError(ctx.Err(), policyengine.ErrorInternal); err != nil {
			_ = session.close()
			return policyengine.BatchCheckResponse{}, err
		}
		result, evaluateErr := s.evaluateSessionItem(ctx, session, item.Subject(), item.Resource(), item.Action(), item.Arguments())
		if evaluateErr != nil {
			_ = session.close()
			return policyengine.BatchCheckResponse{}, evaluateErr
		}
		results = append(results, result)
	}
	if closeErr := session.close(); closeErr != nil {
		return policyengine.BatchCheckResponse{}, sanitizeRuntimeError(closeErr, policyengine.ErrorInternal)
	}
	response, err := policyengine.NewBatchCheckResponse(validated, results)
	if err != nil {
		return policyengine.BatchCheckResponse{}, sanitizeRuntimeError(err, policyengine.ErrorInternal)
	}
	for _, result := range results {
		s.deliverDecisionEvent(ctx, result)
	}
	return response, nil
}

func (s *AuthorizationService) openEvaluationSession(
	ctx context.Context,
	caller policyengine.Caller,
	request sharedEvaluationRequest,
	fingerprint [sha256.Size]byte,
	verifierBudget *batchWorkBudget,
) (evaluationSession, error) {
	pin, err := s.resolveRevision(ctx, request)
	if err != nil {
		return evaluationSession{}, err
	}
	hydrated, err := s.loadRevision(ctx, pin)
	if err != nil {
		return evaluationSession{}, err
	}
	evaluatedAt, err := s.evaluationTime()
	if err != nil {
		return evaluationSession{}, err
	}
	snapshot, err := s.openExactSnapshot(ctx, request, evaluatedAt)
	if err != nil {
		return evaluationSession{}, err
	}
	fail := func(err error) (evaluationSession, error) {
		_ = snapshot.Close()
		return evaluationSession{}, err
	}
	binding, err := policyengine.NewEvidenceBinding(policyengine.EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: request.Namespace(), Selector: request.Selector(),
		RevisionID: pin.revisionID, SlotGeneration: pin.slotGeneration,
		DataGeneration: snapshot.Generation(), EvaluatedAt: evaluatedAt,
		Fingerprint: policyengine.NewEvidenceFingerprint(fingerprint),
	})
	if err != nil {
		return fail(appError(policyengine.ErrorInternal))
	}
	schema, err := domain.NewDataSchema(hydrated.Artifact())
	if err != nil {
		return fail(err)
	}
	contextual := request.ContextualData()
	if err := schema.ValidateContextualTuples(contextual); err != nil {
		return fail(err)
	}
	contextual, err = schema.NormalizeContextualData(ctx, snapshot, contextual)
	if err != nil {
		return fail(sanitizeRuntimeError(err, policyengine.ErrorInternal))
	}
	usedDelegation := false
	if evidence := request.DelegationEvidence(); len(evidence) != 0 {
		verification, requestErr := policyengine.NewDelegationVerificationRequest(binding, evidence)
		if requestErr != nil {
			return fail(requestErr)
		}
		verified, verifyErr := policyengine.InvokeDelegationVerifier(ctx, s.dependencies.DelegationVerifier, verification)
		if verifyErr != nil {
			return fail(verifyErr)
		}
		delegated := verified.ContextualData()
		delegatedItems := len(delegated.Tuples()) + len(delegated.Attributes())
		if budgetErr := verifierBudget.add(delegatedItems, contextualDataVerifierBytes(delegated)); budgetErr != nil {
			return fail(budgetErr)
		}
		if err := schema.ValidateContextualTuples(delegated); err != nil {
			return fail(err)
		}
		contextual, err = policyengine.NewContextualData(
			append(contextual.Tuples(), delegated.Tuples()...),
			append(contextual.Attributes(), delegated.Attributes()...),
		)
		if err != nil {
			return fail(err)
		}
		contextual, err = schema.NormalizeContextualData(ctx, snapshot, contextual)
		if err != nil {
			return fail(sanitizeRuntimeError(err, policyengine.ErrorInternal))
		}
		usedDelegation = true
	}
	usedContextualData := !contextual.Empty()
	reader, err := evaluator.NewSnapshotReader(snapshot, contextual)
	if err != nil {
		return fail(err)
	}
	return evaluationSession{
		revisionID: pin.revisionID, slotGeneration: pin.slotGeneration,
		dataGeneration: snapshot.Generation(), evaluatedAt: evaluatedAt,
		program: hydrated.Program(), artifact: hydrated.Artifact(), reader: reader, close: snapshot.Close,
		binding:            binding,
		usedContextualData: usedContextualData, usedDelegation: usedDelegation,
		approvalEvidence: request.ApprovalEvidence(), tupleReader: reader, verifierBudget: verifierBudget,
	}, nil
}

func batchFingerprint(request policyengine.BatchCheckRequest) [sha256.Size]byte {
	hash := sha256.New()
	writeFingerprintString(hash, request.Namespace())
	if slot, ok := request.Selector().Slot(); ok {
		writeFingerprintString(hash, "slot")
		writeFingerprintString(hash, slot)
	} else if revision, ok := request.Selector().ExactRevision(); ok {
		writeFingerprintString(hash, "revision")
		writeFingerprintString(hash, revision)
	}
	items := request.Items()
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(len(items)))
	_, _ = hash.Write(number[:])
	for _, item := range items {
		writeEntityFingerprint(hash, item.Subject())
		writeEntityFingerprint(hash, item.Resource())
		writeFingerprintString(hash, item.Action())
		arguments := item.Arguments()
		binary.BigEndian.PutUint64(number[:], uint64(len(arguments)))
		_, _ = hash.Write(number[:])
		writeArgumentsFingerprint(hash, arguments)
	}
	binary.BigEndian.PutUint64(number[:], request.MinimumGeneration())
	_, _ = hash.Write(number[:])
	contextual := request.ContextualData()
	binary.BigEndian.PutUint64(number[:], uint64(len(contextual.Tuples())))
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(len(contextual.Attributes())))
	_, _ = hash.Write(number[:])
	writeContextualFingerprint(hash, contextual)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func contextualDataVerifierBytes(contextual policyengine.ContextualData) int {
	const (
		fieldMetadata      = 8
		collectionMetadata = 8
		valueMetadata      = 9
		timestampBytes     = 40
	)
	textBytes := func(value string) int { return fieldMetadata + len(value) }
	bytes := 2 * collectionMetadata
	for _, tuple := range contextual.Tuples() {
		value := tuple.Tuple()
		bytes += textBytes(value.Resource.Type) + textBytes(value.Resource.ID) + textBytes(value.Relation)
		bytes += textBytes(value.Subject.Type) + textBytes(value.Subject.ID) + textBytes(value.Subject.Relation)
		bytes += fieldMetadata + 1
		if _, expires := tuple.ExpiresAt(); expires {
			bytes += fieldMetadata + timestampBytes
		}
	}
	for _, attribute := range contextual.Attributes() {
		bytes += textBytes(attribute.Entity().Type) + textBytes(attribute.Entity().ID) + collectionMetadata
		for _, segment := range attribute.Path() {
			bytes += textBytes(segment)
		}
		bytes += valueMetadata
		if text, ok := attribute.Value().StringValue(); ok {
			bytes += len(text)
		}
	}
	return bytes
}
