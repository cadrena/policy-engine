# Cadrena Policy Engine

Cadrena Policy Engine is an open-source, complete local policy runtime for
relationship-based authorization of AI-agent and tool actions.

The cross-repository ownership contract is the
[Cadrena V1 capability matrix](./docs/capability-matrix.md).

> **Status:** Pre-V1 implementation. The Batch 1 decision core is available on
> `main`, but SQLite, ConnectRPC, the standalone binary, the public image, and
> `v1.0.0` remain in development. This README distinguishes source availability
> from the frozen target V1 release contract.

## Current availability

Available on `main`:

- the public module-root policy-engine contracts;
- public composition through `embedded.New`;
- memory-backed local policy publication, activation, authorization-data
  generation reads and writes, and state events;
- snapshot-pinned `Check` and `BatchCheck`;
- privileged redacted `Explain`;
- public authorization and verifier conformance suites.

Still in development:

- SQLite storage;
- the ConnectRPC transport and standalone binary;
- the public image;
- `v1.0.0` and its release artifacts.

The contract below describes the complete target V1 surface. Source
availability at a checkpoint is not a production-readiness or compatibility
promise; consult tagged release notes before relying on an API in production.

## V1 scope

- Local relationship-based authorization for AI-agent and tool actions
- Tagged Cadrena textual DSL artifacts
- Embedded module-root Go API and standalone ConnectRPC server
- `Check`, bounded snapshot-pinned `BatchCheck`, and privileged redacted
  `Explain`
- Local immutable revisions and optional local CAS slots
- Persistent and contextual tuples plus typed attributes
- Memory and SQLite storage
- Bounded compiled-artifact and slot-pointer caching
- Bounded local state events and privacy-safe OpenTelemetry metrics and traces
- Approval, delegation, caller-authorization, and decision-event extension
  ports
- Reject-by-default evidence handling and privacy-safe telemetry

Local publication, activation, storage, and events make the standalone runtime
coherent. They are not a central registry, distribution service, rollout
system, fleet manager, or enterprise audit platform.

## Embedded package

Consumers import contracts from the module root:

```go
import policyengine "github.com/cadrena/policy-engine"
```

> The public contracts are located at the module root. Do not import a
> redundant `/policyengine` subpackage.

The available embedded composition package is imported separately:

```go
import "github.com/cadrena/policy-engine/embedded"

engine, err := embedded.New(/* sealed options */)
```

The embedded API and planned standalone ConnectRPC transport share one
evaluator core. The standalone server is intended to be compatible with
Connect, gRPC, and gRPC-Web; that transport remains in development.

## Policy language

Policies are authored in the Cadrena textual DSL provided by tagged releases
of [`github.com/cadrena/dsl`](https://github.com/cadrena/dsl). V1 does not
execute CEL, Rego, JavaScript, Go plugins, WASM, or network-backed policy
functions.

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

## Offline audit backup export

Stop the SQLite store before you export its image. Use a new output path:

```sh
go run ./cmd/cadrena-policy-store --db /absolute/source.db --out /absolute/backup.db backup
```

The command copies the store into a fresh SQLite image. It removes
`state_events` older than 22 days and preserves each namespace's event expiry
watermark. It rejects a source with events older than 30 days. It also rejects
an existing output path or output sidecar. Restore the image as a new store and
run `integrity` before use. This command does not set retention rules for other
records or manage backup storage. If an interrupted export leaves an
`.audit-backup-*` directory beside the output, inspect and remove it before
you retry. The command refuses to run while that directory remains.

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
