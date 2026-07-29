# Conductera Policy Engine

Conductera Policy Engine is an open-source, complete local policy runtime for
relationship-based authorization of AI-agent and tool actions.

> **Status:** Pre-V1 implementation. This README describes the frozen V1 release
> contract; availability is established only by a tagged release and its
> changelog.

The contract below describes the target V1 surface, not a claim that every
feature is available at the current commit. Consult release notes before relying
on an API in production.

## V1 scope

- Local relationship-based authorization for AI-agent and tool actions
- Tagged Conductera textual DSL artifacts
- Embedded module-root Go API and standalone ConnectRPC server
- `Check`, bounded snapshot-pinned `BatchCheck`, and privileged redacted
  `Explain`
- Local immutable revisions and optional local CAS slots
- Persistent and contextual tuples plus typed attributes
- Memory and SQLite storage
- Bounded compiled-artifact and slot-pointer caching
- Bounded local state events and privacy-safe metrics and traces
- Approval, delegation, caller-authorization, and decision-event extension
  ports
- Reject-by-default evidence handling and privacy-safe telemetry

Local publication, activation, storage, and events make the standalone runtime
coherent. They are not a central registry, distribution service, rollout
system, fleet manager, or enterprise audit platform.

## Embedded package

Consumers import the package from the module root:

```go
import policyengine "github.com/conductera/policy-engine"
```

> The embedded package is located at the module root. Do not import a redundant
> `/policyengine` subpackage.

The embedded API and standalone ConnectRPC transport share one evaluator core.
The standalone server is compatible with Connect, gRPC, and gRPC-Web.

## Policy language

<!-- markdown-link-check-disable -->

<!--
The canonical URL becomes reachable when the pre-V1 public DSL is published.
-->

Policies are authored in the Conductera textual DSL provided by tagged releases
of [`github.com/conductera/dsl`](https://github.com/conductera/dsl). V1 does not
execute CEL, Rego, JavaScript, Go plugins, WASM, or network-backed policy
functions.

<!-- markdown-link-check-enable -->

The tagged DSL owns parsing, validation, canonicalization, deterministic
artifact encoding, compilation semantics, and graph and guard evaluation
semantics. The policy engine owns local lifecycle, authorization-data
orchestration, capability enforcement, storage, caching, transport mapping, and
operational failure behavior.

## Security defaults

The runtime denies execution on every engine error. Policy decisions are
`ALLOW`, `DENY`, or `REQUIRE_APPROVAL`; typed engine errors remain distinct from
policy denial. Callers must be explicitly authenticated or configured and
authorized for capability-scoped namespace patterns. An omitted caller
authorizer rejects all operations.

> Approval and delegation services are not bundled. The public engine exposes
> typed verifier ports, and the default verifiers reject supplied evidence.
> Deployments that need those capabilities must explicitly provide conforming
> implementations.

Normal checks expose compact decision metadata. `Explain` is a separately
authorized operation that redacts dynamic identifiers, arguments, attributes,
tuples, contextual facts, and evidence. Public decision-event delivery is
best-effort and does not constitute durable audit.

See the [V1 specification](./SPEC.md), [security policy](./SECURITY.md), and
[public and commercial boundary](./docs/public-private-boundary.md) for the
normative contract.

## Explicit V1 non-goals

- No `filter`, `FilterCandidates`, global reverse lookup, candidate discovery,
  or global graph-expansion API
- No streaming Watch or final-decision cache
- No PostgreSQL or distributed or multi-region storage
- No central registry, distribution, promotion, rollout, scheduling, or drift
  management
- No built-in delegation issuance, attenuation, lineage, chain, registry, key,
  or revocation service
- No approval issuance, workflow, inbox, registry, key, or revocation service
- No required-durable enterprise audit, long-term search, SIEM export,
  compliance retention, or forensic replay
- No dataset-wide compatibility scan, simulation, or impact analysis at scale
- No managed backup or restore, HA, SSO, fleet, inventory, or dashboard
- No dynamic Go, WASM, HTTP, or RPC evaluator plugins
- No exact historical data-generation reads
- No additional REST or grpc-gateway surface

## Distribution

V1 is intended to be available as public source, a Go module, a standalone
binary, and a public container image. Every public artifact must build and run
without commercial source, services, credentials, or infrastructure.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
