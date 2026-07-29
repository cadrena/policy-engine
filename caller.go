package policyengine

import (
	"context"
	"sort"
	"strings"
)

// Capability is one stable caller permission checked by the shared core.
type Capability string

const (
	// CapabilityPolicyRead permits authorized local policy metadata reads.
	CapabilityPolicyRead Capability = "policy.read"
	// CapabilityPolicyPublish permits publication without activation.
	CapabilityPolicyPublish Capability = "policy.publish"
	// CapabilityPolicyActivate permits atomic local slot activation.
	CapabilityPolicyActivate Capability = "policy.activate"
	// CapabilityAuthorizationCheck permits basic checks through a slot.
	CapabilityAuthorizationCheck Capability = "authorization.check"
	// CapabilityAuthorizationContextualData permits trusted additive contextual facts.
	CapabilityAuthorizationContextualData Capability = "authorization.contextual_data"
	// CapabilityAuthorizationExplicitRevision permits exact revision selection.
	CapabilityAuthorizationExplicitRevision Capability = "authorization.explicit_revision"
	// CapabilityAuthorizationExplain permits privileged redacted explanation.
	CapabilityAuthorizationExplain Capability = "authorization.explain"
	// CapabilityDataWrite permits atomic persistent authorization-data writes.
	CapabilityDataWrite Capability = "data.write"
	// CapabilityEventsRead permits bounded local state-event reads.
	CapabilityEventsRead Capability = "events.read"
	// CapabilitySystemStatus permits detailed component and readiness status.
	CapabilitySystemStatus Capability = "system.status"
)

func capabilityRank(capability Capability) int {
	switch capability {
	case CapabilityPolicyRead:
		return 0
	case CapabilityPolicyPublish:
		return 1
	case CapabilityPolicyActivate:
		return 2
	case CapabilityAuthorizationCheck:
		return 3
	case CapabilityAuthorizationContextualData:
		return 4
	case CapabilityAuthorizationExplicitRevision:
		return 5
	case CapabilityAuthorizationExplain:
		return 6
	case CapabilityDataWrite:
		return 7
	case CapabilityEventsRead:
		return 8
	case CapabilitySystemStatus:
		return 9
	default:
		return -1
	}
}

func (c Capability) valid() bool {
	return capabilityRank(c) >= 0
}

// Caller is an adapter-authenticated or explicitly configured embedded identity.
type Caller struct {
	id         string
	attributes map[string]string
}

// NewCaller validates and copies an authenticated caller identity.
// Attributes are identity metadata only and never assert capabilities.
func NewCaller(id string, attributes map[string]string) (Caller, error) {
	if len(attributes) > MaxCallerAttributes {
		return Caller{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addCallerCost(&budget, id, attributes); err != nil {
		return Caller{}, err
	}
	if err := validateIdentifier(id); err != nil {
		return Caller{}, err
	}
	for key, value := range attributes {
		if err := validateIdentifier(key); err != nil {
			return Caller{}, err
		}
		if err := validateText(value, MaxIdentifierBytes, true); err != nil {
			return Caller{}, err
		}
	}
	return Caller{id: id, attributes: cloneMap(attributes)}, nil
}

// ID returns the adapter-authenticated caller identifier.
func (c Caller) ID() string { return c.id }

// Attributes returns a defensive copy of identity metadata.
// Attributes do not and cannot grant capabilities.
func (c Caller) Attributes() map[string]string { return cloneMap(c.attributes) }

func (c Caller) valid() bool {
	if !validIdentifier(c.id) || len(c.attributes) > MaxCallerAttributes {
		return false
	}
	for key, value := range c.attributes {
		if !validIdentifier(key) || validateText(value, MaxIdentifierBytes, true) != nil {
			return false
		}
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	return addCallerCost(&budget, c.id, c.attributes) == nil
}

// Grant scopes a validated set of capabilities to one namespace pattern.
type Grant struct {
	namespacePattern string
	capabilities     []Capability
}

// NewGrant validates and copies one namespace-pattern-scoped capability grant.
// A pattern is exact or has one final wildcard; "*" matches every namespace.
func NewGrant(namespacePattern string, capabilities []Capability) (Grant, error) {
	if len(capabilities) == 0 {
		return Grant{}, invalidArgument("grant requires capabilities")
	}
	if len(capabilities) > MaxCapabilitiesPerGrant {
		return Grant{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	if err := addGrantCost(&budget, Grant{namespacePattern: namespacePattern, capabilities: capabilities}); err != nil {
		return Grant{}, err
	}
	if err := validateNamespacePattern(namespacePattern); err != nil {
		return Grant{}, err
	}
	canonical, err := canonicalCapabilities(capabilities)
	if err != nil {
		return Grant{}, err
	}
	return Grant{namespacePattern: namespacePattern, capabilities: canonical}, nil
}

// NamespacePattern returns the validated exact or trailing-wildcard pattern.
func (g Grant) NamespacePattern() string { return g.namespacePattern }

// Capabilities returns a deterministic defensive copy of granted capabilities.
func (g Grant) Capabilities() []Capability { return cloneSlice(g.capabilities) }

// MatchesNamespace reports whether the grant pattern covers an opaque namespace.
func (g Grant) MatchesNamespace(namespace string) bool {
	if !validNamespace(namespace) || !validNamespacePattern(g.namespacePattern) {
		return false
	}
	if g.namespacePattern == "*" {
		return true
	}
	if strings.HasSuffix(g.namespacePattern, "*") {
		return strings.HasPrefix(namespace, strings.TrimSuffix(g.namespacePattern, "*"))
	}
	return namespace == g.namespacePattern
}

func (g Grant) valid() bool {
	if !validNamespacePattern(g.namespacePattern) || len(g.capabilities) == 0 || len(g.capabilities) > MaxCapabilitiesPerGrant {
		return false
	}
	for index, capability := range g.capabilities {
		if !capability.valid() || (index > 0 && capabilityRank(g.capabilities[index-1]) >= capabilityRank(capability)) {
			return false
		}
	}
	budget := budgetCounter{max: MaxAggregateInputBytes}
	return addGrantCost(&budget, g) == nil
}

// CallerAuthorization is bounded structured output from CallerAuthorizer.
type CallerAuthorization struct {
	grants []Grant
}

// NewCallerAuthorization validates and copies namespace-scoped grants.
func NewCallerAuthorization(grants []Grant) (CallerAuthorization, error) {
	if len(grants) == 0 {
		return CallerAuthorization{}, invalidArgument("caller authorization requires grants")
	}
	if len(grants) > MaxCallerGrants {
		return CallerAuthorization{}, resourceExhausted()
	}
	budget := budgetCounter{max: MaxAuthorizerOutputBytes}
	if err := addCallerAuthorizationCost(&budget, grants); err != nil {
		return CallerAuthorization{}, err
	}
	for _, grant := range grants {
		if len(grant.capabilities) > MaxCapabilitiesPerGrant {
			return CallerAuthorization{}, resourceExhausted()
		}
	}
	patterns := make(map[string]struct{}, len(grants))
	cloned := make([]Grant, len(grants))
	for index, grant := range grants {
		if !grant.valid() {
			return CallerAuthorization{}, invalidArgument("caller authorization contains an invalid grant")
		}
		if _, duplicate := patterns[grant.namespacePattern]; duplicate {
			return CallerAuthorization{}, invalidArgument("caller authorization contains a duplicate namespace pattern")
		}
		patterns[grant.namespacePattern] = struct{}{}
		grant.capabilities = cloneSlice(grant.capabilities)
		cloned[index] = grant
	}
	sort.Slice(cloned, func(i, j int) bool { return grantLess(cloned[i], cloned[j]) })
	return CallerAuthorization{grants: cloned}, nil
}

// Grants returns a defensive copy of namespace-scoped grants.
func (a CallerAuthorization) Grants() []Grant {
	grants := make([]Grant, len(a.grants))
	for index, grant := range a.grants {
		grant.capabilities = cloneSlice(grant.capabilities)
		grants[index] = grant
	}
	return grants
}

func (a CallerAuthorization) valid() bool {
	if len(a.grants) == 0 || len(a.grants) > MaxCallerGrants {
		return false
	}
	budget := budgetCounter{max: MaxAuthorizerOutputBytes}
	if addCallerAuthorizationCost(&budget, a.grants) != nil {
		return false
	}
	for index, grant := range a.grants {
		if !grant.valid() || (index > 0 && !grantLess(a.grants[index-1], grant)) {
			return false
		}
	}
	return true
}

func grantLess(left, right Grant) bool {
	leftWildcard := strings.HasSuffix(left.namespacePattern, "*")
	rightWildcard := strings.HasSuffix(right.namespacePattern, "*")
	if leftWildcard != rightWildcard {
		return !leftWildcard
	}
	return left.namespacePattern < right.namespacePattern
}

// CallerAuthorizer maps authenticated identity to namespace-scoped grants.
// It receives every additive capability required by the request.
type CallerAuthorizer interface {
	Authorize(context.Context, Caller, string, []Capability) (CallerAuthorization, error)
}

// DefaultCallerAuthorizer returns the public reject-all authorizer.
func DefaultCallerAuthorizer() CallerAuthorizer { return rejectAllAuthorizer{} }

type rejectAllAuthorizer struct{}

func (rejectAllAuthorizer) Authorize(context.Context, Caller, string, []Capability) (CallerAuthorization, error) {
	return CallerAuthorization{}, engineError(ErrorPermissionDenied)
}

// AuthorizeCaller validates bounded authorizer output and requires exactly the
// requested capabilities for grants matching the target namespace. Request
// assertions never grant capabilities.
func AuthorizeCaller(ctx context.Context, authorizer CallerAuthorizer, caller Caller, namespace string, required []Capability) error {
	if ctx == nil || !caller.valid() || !validNamespace(namespace) || len(required) == 0 {
		return engineError(ErrorInvalidArgument)
	}
	if len(required) > MaxCapabilitiesPerGrant {
		return engineError(ErrorResourceExhausted)
	}
	if err := contextEngineError(ctx); err != nil {
		return err
	}
	canonicalRequired, err := canonicalCapabilities(required)
	if err != nil {
		return engineError(ErrorInvalidArgument)
	}
	if isNilInterface(authorizer) {
		return engineError(ErrorPermissionDenied)
	}
	result, callErr := callAuthorizer(ctx, authorizer, caller, namespace, canonicalRequired)
	if err := contextEngineError(ctx); err != nil {
		return err
	}
	if callErr != nil {
		return sanitizedExtensionError(callErr, ErrorUnavailable)
	}
	if !result.valid() {
		return engineError(ErrorInternal)
	}
	requested := make(map[Capability]struct{}, len(canonicalRequired))
	for _, capability := range canonicalRequired {
		requested[capability] = struct{}{}
	}
	granted := make(map[Capability]struct{}, len(canonicalRequired))
	for _, grant := range result.grants {
		if !grant.MatchesNamespace(namespace) {
			continue
		}
		for _, capability := range grant.capabilities {
			if _, ok := requested[capability]; !ok {
				return engineError(ErrorInternal)
			}
			granted[capability] = struct{}{}
		}
	}
	for _, capability := range canonicalRequired {
		if _, ok := granted[capability]; !ok {
			return engineError(ErrorPermissionDenied)
		}
	}
	return nil
}

// RequiredCapabilities returns the capability needed to publish source.
func (PublishRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyPublish}
}

// RequiredCapabilities returns the capability needed to read a revision.
func (GetRevisionRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyRead}
}

// RequiredCapabilities returns the capability needed to list revisions.
func (ListRevisionsRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyRead}
}

// RequiredCapabilities returns the capability needed to activate a slot.
func (ActivateRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyActivate}
}

// RequiredCapabilities returns the capability needed to resolve a slot.
func (ResolveRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyRead}
}

// RequiredCapabilities returns the capability needed to list activation history.
func (ListActivationHistoryRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityPolicyRead}
}

// RequiredCapabilities returns every additive capability needed by the check.
func (r CheckRequest) RequiredCapabilities() []Capability {
	required := []Capability{CapabilityAuthorizationCheck}
	if !r.contextualData.Empty() {
		required = append(required, CapabilityAuthorizationContextualData)
	}
	if _, exact := r.selector.ExactRevision(); exact {
		required = append(required, CapabilityAuthorizationExplicitRevision)
	}
	canonical, _ := canonicalCapabilities(required)
	return canonical
}

// RequiredCapabilities returns every additive capability needed by the batch.
func (r BatchCheckRequest) RequiredCapabilities() []Capability {
	required := []Capability{CapabilityAuthorizationCheck}
	if !r.contextualData.Empty() {
		required = append(required, CapabilityAuthorizationContextualData)
	}
	if _, exact := r.selector.ExactRevision(); exact {
		required = append(required, CapabilityAuthorizationExplicitRevision)
	}
	canonical, _ := canonicalCapabilities(required)
	return canonical
}

// RequiredCapabilities returns check requirements plus privileged explanation.
func (r ExplainRequest) RequiredCapabilities() []Capability {
	required := append(r.check.RequiredCapabilities(), CapabilityAuthorizationExplain)
	canonical, _ := canonicalCapabilities(required)
	return canonical
}

// RequiredCapabilities returns data.write; the head discloses no data.
func (GetDataGenerationRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityDataWrite}
}

// RequiredCapabilities returns the capability needed for persistent data writes.
func (WriteDataRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityDataWrite}
}

// RequiredCapabilities returns the capability needed to read local state events.
func (ListEventsRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilityEventsRead}
}

// RequiredCapabilities returns the capability needed for detailed local status.
func (StatusRequest) RequiredCapabilities() []Capability {
	return []Capability{CapabilitySystemStatus}
}

func canonicalCapabilities(capabilities []Capability) ([]Capability, error) {
	set := make(map[Capability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if !capability.valid() {
			return nil, invalidArgument("capability is invalid")
		}
		set[capability] = struct{}{}
	}
	result := make([]Capability, 0, len(set))
	for capability := range set {
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool {
		return capabilityRank(result[i]) < capabilityRank(result[j])
	})
	return result, nil
}

func validNamespacePattern(pattern string) bool {
	return validateNamespacePattern(pattern) == nil
}
