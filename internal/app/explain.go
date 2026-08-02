package app

import (
	"context"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
)

// Explain evaluates one request once and returns only static, redacted trace metadata.
func (s *AuthorizationService) Explain(
	ctx context.Context,
	caller policyengine.Caller,
	request policyengine.ExplainRequest,
) (policyengine.ExplainResponse, error) {
	check := request.Check()
	validatedCheck, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: check.Namespace(), Selector: check.Selector(), Subject: check.Subject(),
		Resource: check.Resource(), Action: check.Action(), Arguments: check.Arguments(),
		ContextualData: check.ContextualData(), ApprovalEvidence: check.ApprovalEvidence(),
		DelegationEvidence: check.DelegationEvidence(), MinimumGeneration: check.MinimumGeneration(),
	})
	if err != nil {
		return policyengine.ExplainResponse{}, err
	}
	validated, err := policyengine.NewExplainRequest(validatedCheck)
	if err != nil {
		return policyengine.ExplainResponse{}, err
	}
	if err := policyengine.AuthorizeCaller(ctx, s.dependencies.CallerAuthorizer, caller,
		validatedCheck.Namespace(), validated.RequiredCapabilities()); err != nil {
		return policyengine.ExplainResponse{}, err
	}

	verifierBudget := &batchWorkBudget{maxItems: policyengine.MaxVerifierOutputItems, maxBytes: policyengine.MaxVerifierOutputBytes}
	session, err := s.openEvaluationSession(ctx, caller, validatedCheck, checkFingerprint(validatedCheck), verifierBudget)
	if err != nil {
		return policyengine.ExplainResponse{}, err
	}
	result, trace, resultErr := s.evaluateSessionItemWithTrace(ctx, session, validatedCheck.Subject(), validatedCheck.Resource(), validatedCheck.Action(), validatedCheck.Arguments())
	closeErr := session.close()
	if resultErr != nil {
		return policyengine.ExplainResponse{}, resultErr
	}
	if closeErr != nil {
		return policyengine.ExplainResponse{}, sanitizeRuntimeError(closeErr, policyengine.ErrorInternal)
	}
	steps, err := redactedExplainSteps(ctx, session.artifact, trace)
	if err != nil {
		return policyengine.ExplainResponse{}, err
	}
	response, err := policyengine.NewExplainResponse(validated, result, steps)
	if err != nil {
		return policyengine.ExplainResponse{}, sanitizeRuntimeError(err, policyengine.ErrorInternal)
	}
	s.deliverDecisionEvent(ctx, result)
	return response, nil
}

func redactedExplainSteps(ctx context.Context, artifact *dsl.Artifact, trace []dsl.TraceStep) ([]policyengine.ExplainStep, error) {
	if len(trace) > policyengine.MaxExplainSteps {
		return nil, appError(policyengine.ErrorResourceExhausted)
	}
	if err := sanitizeRuntimeError(ctx.Err(), policyengine.ErrorInternal); err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, appError(policyengine.ErrorInternal)
	}
	schema, err := dsl.Parse("artifact.cdr", artifact.CanonicalSource())
	if err != nil {
		return nil, appError(policyengine.ErrorInternal)
	}
	type declarationKey struct {
		entity string
		name   string
		kind   string
	}
	declarations := make(map[declarationKey]struct{})
	for _, entity := range schema.Entities {
		for _, relation := range entity.Relations {
			declarations[declarationKey{entity: entity.Name, name: relation.Name, kind: "relation"}] = struct{}{}
		}
		for _, permission := range entity.Permissions {
			declarations[declarationKey{entity: entity.Name, name: permission.Name, kind: "permission"}] = struct{}{}
		}
		for _, action := range entity.Actions {
			declarations[declarationKey{entity: entity.Name, name: action.Name, kind: "action"}] = struct{}{}
		}
	}
	steps := make([]policyengine.ExplainStep, 0, len(trace))
	for _, item := range trace {
		if err := sanitizeRuntimeError(ctx.Err(), policyengine.ErrorInternal); err != nil {
			return nil, err
		}
		if _, ok := declarations[declarationKey{entity: item.Resource.Type, name: item.Declaration, kind: item.Kind}]; !ok {
			return nil, appError(policyengine.ErrorInternal)
		}
		step, err := policyengine.NewExplainStep(item.Resource.Type+"."+item.Declaration, item.Kind, item.Matched)
		if err != nil {
			return nil, appError(policyengine.ErrorInternal)
		}
		steps = append(steps, step)
	}
	return steps, nil
}
