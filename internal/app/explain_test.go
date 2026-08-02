package app_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cadrena/dsl"
	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/internal/app"
	"github.com/cadrena/policy-engine/internal/cache"
)

func TestExplainNeverReturnsDynamicValues(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	selector, err := policyengine.NewSelector("production", "")
	requireNoError(t, err)
	tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
		Resource: dsl.EntityRef{Type: "document", ID: "secret-resource"},
		Relation: "viewer",
		Subject:  dsl.SubjectRef{Type: "user", ID: "alice"},
	}, nil)
	requireNoError(t, err)
	contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, nil)
	requireNoError(t, err)
	card, err := policyengine.NewStringValue("4111111111111111")
	requireNoError(t, err)
	check, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "tenant-a", Selector: selector,
		Subject:  dsl.EntityRef{Type: "user", ID: "alice"},
		Resource: dsl.EntityRef{Type: "document", ID: "secret-resource"},
		Action:   "view", Arguments: map[string]policyengine.Value{"card": card}, ContextualData: contextual,
	})
	requireNoError(t, err)
	request, err := policyengine.NewExplainRequest(check)
	requireNoError(t, err)

	response, err := fixture.service.Explain(context.Background(), mustCaller(t), request)
	requireNoError(t, err)

	encoded := fmt.Sprintf("%+v", response)
	for _, forbidden := range []string{
		"alice",
		"secret-resource",
		"4111111111111111",
		"approval-token",
		"delegation-token",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("Explain leaked %q", forbidden)
		}
	}
}

func TestExplainRedactsConsumedEvidenceAndDelegatedFacts(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	revision := publishSource(context.Background(), t, fixture.policyService, mustCaller(t), "explain-approval.cdr", approvalCheckSource).Revision().ID()
	fixture.activate(t, revision)
	delegation := delegationVerifierFunc(func(context.Context, policyengine.DelegationVerificationRequest) (policyengine.DelegationVerificationResult, error) {
		tuple, err := policyengine.NewRelationshipTuple(dsl.Tuple{
			Resource: dsl.EntityRef{Type: "document", ID: "secret-resource"}, Relation: "viewer",
			Subject: dsl.SubjectRef{Type: "user", ID: "secret-subject"},
		}, nil)
		if err != nil {
			return policyengine.DelegationVerificationResult{}, err
		}
		contextual, err := policyengine.NewContextualData([]policyengine.RelationshipTuple{tuple}, nil)
		if err != nil {
			return policyengine.DelegationVerificationResult{}, err
		}
		return policyengine.NewDelegationVerificationResult(contextual)
	})
	approval := approvalVerifierFunc(func(context.Context, policyengine.ApprovalVerificationRequest) (policyengine.ApprovalVerificationResult, error) {
		return policyengine.NewApprovalVerificationResult([]string{"finance"})
	})
	service := fixture.newService(t, approval, delegation, policyengine.DefaultDecisionEventSink(), fixture.adapter)
	selector, err := policyengine.NewSelector("production", "")
	requireNoError(t, err)
	card, err := policyengine.NewStringValue("4111111111111111")
	requireNoError(t, err)
	check, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: "tenant-a", Selector: selector,
		Subject:  dsl.EntityRef{Type: "user", ID: "secret-subject"},
		Resource: dsl.EntityRef{Type: "document", ID: "secret-resource"}, Action: "view",
		Arguments:        map[string]policyengine.Value{"card": card},
		ApprovalEvidence: []byte("approval-token"), DelegationEvidence: []byte("delegation-token"),
	})
	requireNoError(t, err)

	response, err := service.Explain(context.Background(), mustCaller(t), mustExplainRequest(t, check))
	requireNoError(t, err)
	if !response.Result().UsedApproval() || !response.Result().UsedDelegation() {
		t.Fatal("test evidence was not consumed")
	}
	encoded := fmt.Sprintf("%+v", response)
	for _, forbidden := range []string{"secret-subject", "secret-resource", "4111111111111111", "approval-token", "delegation-token"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("Explain leaked %q", forbidden)
		}
	}
}

func TestExplainResponseEnforcesAggregateOutputBudget(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	request := mustExplainRequest(t, fixture.checkRequest(t))
	baseline, err := fixture.service.Explain(context.Background(), mustCaller(t), request)
	requireNoError(t, err)
	large := strings.Repeat("x", policyengine.MaxIdentifierBytes)
	step, err := policyengine.NewExplainStep(large, large, true)
	requireNoError(t, err)
	steps := make([]policyengine.ExplainStep, policyengine.MaxExplainSteps)
	for index := range steps {
		steps[index] = step
	}

	_, err = policyengine.NewExplainResponse(request, baseline.Result(), steps)
	requireCategory(t, err, policyengine.ErrorResourceExhausted)
}

func TestExplainRequiresOrdinaryCheckAndExplainCapabilities(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	request := mustExplainRequest(t, fixture.checkRequest(t))

	for _, test := range []struct {
		name         string
		capabilities []policyengine.Capability
		namespace    string
	}{
		{
			name: "missing explain", namespace: "tenant-a",
			capabilities: []policyengine.Capability{
				policyengine.CapabilityAuthorizationCheck,
				policyengine.CapabilityAuthorizationContextualData,
			},
		},
		{
			name: "missing ordinary check", namespace: "tenant-a",
			capabilities: []policyengine.Capability{
				policyengine.CapabilityAuthorizationContextualData,
				policyengine.CapabilityAuthorizationExplain,
			},
		},
		{
			name: "namespace mismatch", namespace: "tenant-b",
			capabilities: request.RequiredCapabilities(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := fixture.newExplainService(t, grantAuthorizer{
				namespace: test.namespace, capabilities: test.capabilities,
			})
			response, err := service.Explain(context.Background(), mustCaller(t), request)
			requireCategory(t, err, policyengine.ErrorPermissionDenied)
			if len(response.Steps()) != 0 {
				t.Fatal("unauthorized explain returned steps")
			}
		})
	}
}

func TestExplainCancellationClosesSnapshotExactlyOnce(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	ctx, cancel := context.WithCancel(context.Background())
	data := &cancelingDataReader{DataReader: fixture.adapter, cancel: cancel, cancelAt: 1}
	service := fixture.newService(t, policyengine.DefaultApprovalVerifier(), policyengine.DefaultDelegationVerifier(), policyengine.DefaultDecisionEventSink(), data)

	response, err := service.Explain(ctx, mustCaller(t), mustExplainRequest(t, fixture.checkRequest(t)))
	requireCategory(t, err, policyengine.ErrorCanceled)
	if len(response.Steps()) != 0 {
		t.Fatal("canceled explain returned steps")
	}
	if data.opened == nil || data.opened.closeCalls.Load() != 1 {
		t.Fatal("Explain snapshot was not closed exactly once")
	}
}

func TestExplainKeepsPolicyDenyDistinctFromEngineFailure(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.denyRevision)
	deniedCheck := checkRequestForSelector(t, "production", "", nil)
	denied, err := fixture.service.Explain(context.Background(), mustCaller(t), mustExplainRequest(t, deniedCheck))
	requireNoError(t, err)
	if denied.Result().Decision() != policyengine.DecisionDeny {
		t.Fatalf("decision = %v, want deny", denied.Result().Decision())
	}

	missingAction, err := policyengine.NewCheckRequest(policyengine.CheckRequestInput{
		Namespace: deniedCheck.Namespace(), Selector: deniedCheck.Selector(),
		Subject: deniedCheck.Subject(), Resource: deniedCheck.Resource(), Action: "missing",
	})
	requireNoError(t, err)
	failed, err := fixture.service.Explain(context.Background(), mustCaller(t), mustExplainRequest(t, missingAction))
	requireCategory(t, err, policyengine.ErrorFailedPrecondition)
	if len(failed.Steps()) != 0 {
		t.Fatal("engine failure returned explanation steps")
	}
}

func TestExplainPinsRevisionAcrossConcurrentActivation(t *testing.T) {
	fixture := newAuthorizationFixture(t)
	fixture.activate(t, fixture.allowRevision)
	fixture.revisions.pauseNextGet()
	results := make(chan policyengine.ExplainResponse, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := fixture.service.Explain(context.Background(), mustCaller(t), mustExplainRequest(t, fixture.checkRequest(t)))
		if err != nil {
			failures <- err
			return
		}
		results <- response
	}()

	fixture.revisions.waitUntilGet(t)
	fixture.activate(t, fixture.denyRevision)
	fixture.revisions.resumeGet()
	select {
	case err := <-failures:
		t.Fatal(err)
	case response := <-results:
		if response.Result().RevisionID() != fixture.allowRevision {
			t.Fatal("Explain switched revision after pinning")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Explain did not complete")
	}
}

func mustExplainRequest(t testing.TB, check policyengine.CheckRequest) policyengine.ExplainRequest {
	t.Helper()
	request, err := policyengine.NewExplainRequest(check)
	requireNoError(t, err)
	return request
}

type grantAuthorizer struct {
	namespace    string
	capabilities []policyengine.Capability
}

func (a grantAuthorizer) Authorize(context.Context, policyengine.Caller, string, []policyengine.Capability) (policyengine.CallerAuthorization, error) {
	grant, err := policyengine.NewGrant(a.namespace, a.capabilities)
	if err != nil {
		return policyengine.CallerAuthorization{}, err
	}
	return policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
}

func (f *authorizationFixture) newExplainService(t testing.TB, authorizer policyengine.CallerAuthorizer) *app.AuthorizationService {
	t.Helper()
	revisionCache, err := cache.NewRevisionCache(cache.RevisionLimits{MaxEntries: 8, MaxBytes: 1 << 20})
	requireNoError(t, err)
	pointerCache, err := cache.NewPointerCache(8)
	requireNoError(t, err)
	service, err := app.NewAuthorizationService(app.AuthorizationDependencies{
		Revisions: f.adapter, Slots: f.adapter, Data: f.adapter, RevisionCache: revisionCache,
		PointerCache: pointerCache, CallerAuthorizer: authorizer,
		ApprovalVerifier: policyengine.DefaultApprovalVerifier(), DelegationVerifier: policyengine.DefaultDelegationVerifier(),
		DecisionSink: policyengine.DefaultDecisionEventSink(), Clock: func() time.Time { return time.Unix(100, 0).UTC() },
	})
	requireNoError(t, err)
	return service
}
