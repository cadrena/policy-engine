package authorization_test

import (
	"context"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/conformance/authorization"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
)

func TestEmbeddedEngineAuthorizationConformance(t *testing.T) {
	authorization.Run(t, func(t *testing.T) policyengine.Engine {
		storage, err := memory.New()
		requireNoError(t, err)
		engine, err := embedded.New(
			embedded.WithStore(storage),
			embedded.WithCallerAuthorizer(conformanceAuthorizer{}),
		)
		requireNoError(t, err)
		return engine
	})
}

type conformanceAuthorizer struct{}

func (conformanceAuthorizer) Authorize(
	_ context.Context,
	caller policyengine.Caller,
	namespace string,
	capabilities []policyengine.Capability,
) (policyengine.CallerAuthorization, error) {
	if caller.ID() == authorization.DeniedCallerID {
		errorValue, _ := policyengine.NewEngineError(policyengine.ErrorPermissionDenied)
		return policyengine.CallerAuthorization{}, errorValue
	}
	grant, err := policyengine.NewGrant(namespace, capabilities)
	if err != nil {
		return policyengine.CallerAuthorization{}, err
	}
	return policyengine.NewCallerAuthorization([]policyengine.Grant{grant})
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
