package policyengine

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

type blockingAuthorizer struct {
	started chan<- struct{}
	release <-chan struct{}
	result  CallerAuthorization
}

type internalAuthorizerFunc func(context.Context, Caller, string, []Capability) (CallerAuthorization, error)

func (f internalAuthorizerFunc) Authorize(ctx context.Context, caller Caller, namespace string, required []Capability) (CallerAuthorization, error) {
	return f(ctx, caller, namespace, required)
}

type blockingApprovalVerifier struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (v blockingApprovalVerifier) VerifyApproval(context.Context, ApprovalVerificationRequest) (ApprovalVerificationResult, error) {
	v.started <- struct{}{}
	<-v.release
	return ApprovalVerificationResult{}, engineError(ErrorPermissionDenied)
}

func (a blockingAuthorizer) Authorize(context.Context, Caller, string, []Capability) (CallerAuthorization, error) {
	a.started <- struct{}{}
	<-a.release
	return a.result, nil
}

func TestExtensionInvocationBoundsAbandonedWork(t *testing.T) {
	caller, err := NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewGrant("acme", []Capability{CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := NewCallerAuthorization([]Grant{grant})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, maxConcurrentExtensionCallsPerPort)
	release := make(chan struct{})
	authorizer := blockingAuthorizer{started: started, release: release, result: authorization}
	var calls sync.WaitGroup
	calls.Add(maxConcurrentExtensionCallsPerPort)
	for range maxConcurrentExtensionCallsPerPort {
		go func() {
			defer calls.Done()
			if err := AuthorizeCaller(context.Background(), authorizer, caller, "acme", []Capability{CapabilityAuthorizationCheck}); err != nil {
				t.Errorf("bounded authorizer call error = %v", err)
			}
		}()
	}
	for range maxConcurrentExtensionCallsPerPort {
		<-started
	}
	if err := AuthorizeCaller(context.Background(), authorizer, caller, "acme", []Capability{CapabilityAuthorizationCheck}); !isEngineCategory(err, ErrorResourceExhausted) {
		t.Fatalf("saturated extension error = %#v, want RESOURCE_EXHAUSTED", err)
	}
	close(release)
	calls.Wait()
}

func TestApprovalSaturationDoesNotStarveAuthorizer(t *testing.T) {
	caller, err := NewCaller("caller", nil)
	if err != nil {
		t.Fatal(err)
	}
	revisionID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	selector, err := NewSelector("", revisionID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewEvidenceBinding(EvidenceBindingInput{
		Caller: caller.Binding(), Namespace: "acme", Selector: selector,
		RevisionID: revisionID, EvaluatedAt: time.Unix(1, 0).UTC(),
		Fingerprint: NewEvidenceFingerprint(sha256.Sum256([]byte("request"))),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewApprovalVerificationRequest(binding, []string{"admin"}, []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, maxConcurrentExtensionCallsPerPort)
	release := make(chan struct{})
	verifier := blockingApprovalVerifier{started: started, release: release}
	var calls sync.WaitGroup
	calls.Add(maxConcurrentExtensionCallsPerPort)
	for range maxConcurrentExtensionCallsPerPort {
		go func() {
			defer calls.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_, callErr := InvokeApprovalVerifier(ctx, verifier, request)
			if !isEngineCategory(callErr, ErrorDeadlineExceeded) {
				t.Errorf("blocked approval error = %#v, want DEADLINE_EXCEEDED", callErr)
			}
		}()
	}
	for range maxConcurrentExtensionCallsPerPort {
		<-started
	}
	grant, err := NewGrant("acme", []Capability{CapabilityAuthorizationCheck})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := NewCallerAuthorization([]Grant{grant})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = AuthorizeCaller(context.Background(), internalAuthorizerFunc(func(context.Context, Caller, string, []Capability) (CallerAuthorization, error) {
		called = true
		return authorization, nil
	}), caller, "acme", []Capability{CapabilityAuthorizationCheck})
	if err != nil || !called {
		t.Fatalf("healthy authorizer called=%v error=%#v", called, err)
	}
	calls.Wait()
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(approvalCallSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(approvalCallSlots) != 0 {
		t.Fatal("approval invocation slots were not released")
	}
}
