# Cadrena Policy Engine V1 Specification

## 1. Status and normative language

This document defines the normative contract for Cadrena Policy Engine V1. The
cross-repository ownership contract is the
[Cadrena V1 capability matrix](../control-plane/docs/product/capability-matrix.md).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be
interpreted as described by RFC 2119 and RFC 8174 only when they appear in all
capitals.

This repository is currently pre-V1. This specification defines the frozen
target V1 contract, not the availability of every surface at the current commit.
Availability is established by a tagged release and its changelog.

The engine depends only on tagged public modules. Public correctness,
buildability, tests, generated code, examples, and release artifacts MUST NOT
require commercial source, credentials, services, or infrastructure.

## 2. Scope

Public V1 is a complete local policy runtime and MUST include:

- a module-root embedded Go API;
- one evaluator core shared with ConnectRPC;
- Connect, gRPC, and gRPC-Web compatibility;
- local content-addressed immutable revisions;
- optional local compare-and-swap slot selection;
- `Check`;
- bounded snapshot-pinned `BatchCheck`;
- privileged redacted `Explain`;
- persistent and contextual relationship tuples;
- typed entity attributes;
- atomic data generations;
- memory and SQLite stores;
- bounded compiled-artifact and slot-pointer caches;
- bounded local state events;
- privacy-safe metrics and traces;
- public typed extension ports and their safe defaults.

> Local publication, activation, storage, and event operations exist only to
> make the standalone public runtime coherent. They do not constitute a central
> registry, distribution service, rollout system, fleet manager, or enterprise
> audit platform.

## 3. Package and dependency contract

Package `policyengine` MUST live at the module root. Public consumers MUST
import it as follows:

```go
import policyengine "github.com/cadrena/policy-engine"
```

The engine MUST consume the Artifact API from a tagged
`github.com/cadrena/dsl` release. The DSL owns parsing, canonicalization,
deterministic artifact encoding, compilation semantics, and graph and guard
evaluation semantics. The engine owns local lifecycle, authorization-data
orchestration, capability enforcement, storage, caching, transport mapping, and
operational failure behavior.

The compatibility-stable language-version identifier `conductera/v1` and
evaluator-ABI identifier `conductera-evaluator/v1` are preserved for V1 wire
compatibility. They are legacy protocol identifiers only, not current product
or repository names.

The engine MUST NOT duplicate DSL artifact encoding or compiler internals.
Runtime-specific Go `Program` values are non-durable cache entries. Protobuf and
Connect types MUST remain outside the embedded core API.

The engine, tests, examples, generated code, CI, and image build MUST resolve
without non-public dependencies or credentials. Released modules MUST NOT
require a local module replacement.

## 4. Terminology and trust model

The following definitions are normative:

- **Caller:** authenticated or explicitly configured embedded identity invoking
  an engine operation.
- **Capability:** caller permission scoped to an operation and namespace
  pattern.
- **Namespace:** opaque isolation key; organizational meaning is external.
- **Revision:** immutable content-addressed DSL artifact.
- **Slot:** optional local mutable pointer to one revision.
- **Slot generation:** monotonic generation increased by successful CAS
  activation.
- **Data generation:** exact monotonic generation of the atomic tuple-and-attribute
  dataset.
- **Contextual data:** trusted request-scoped additive facts.
- **Policy decision:** `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.
- **Engine error:** typed non-OK result that is not a policy decision.
- **State event:** bounded cursor-addressable record of a successful local state
  mutation.
- **Decision event sink:** best-effort extension hook, not an authoritative audit
  store.

Trusted inputs MUST come from an authenticated adapter or explicit embedded
composition. Request assertions MUST NOT grant capabilities. Authorization MUST
be enforced by the shared core in embedded and standalone modes.

## 5. Caller authorization and capability matrix

<!-- markdownlint-disable MD013 -->

| Capability | Operations authorized | Additional rules |
| --- | --- | --- |
| `policy.read` | Get or list revision metadata, resolve a slot, list local activation history | Does not authorize evaluation |
| `policy.publish` | Publish a local immutable revision | Does not activate it |
| `policy.activate` | CAS activation or rollback of a local slot | Target revision must already exist in the same namespace |
| `authorization.check` | `Check` and basic `BatchCheck` through a slot | Does not permit contextual data, explicit revision selection, or `Explain` |
| `authorization.contextual_data` | Add trusted request-scoped tuples or attributes | Requires `authorization.check` too |
| `authorization.explicit_revision` | Evaluate an exact revision instead of a slot | Requires `authorization.check`; does not grant policy read or mutation |
| `authorization.explain` | Request redacted `Explain` output | Requires `authorization.check`; other additive capabilities still apply |
| `data.write` | Read current data-generation metadata; atomically write or delete persistent tuples and attributes | Includes selecting the explicit validation revision for that write only; does not disclose stored data |
| `events.read` | Bounded `ListEvents` | Does not imply decision-audit access |
| `system.status` | Detailed component and readiness status | Coarse liveness exposure remains a deployment decision |

<!-- markdownlint-enable MD013 -->

Capabilities are additive: every capability required by a request MUST be
granted. `BatchCheck` uses `authorization.check`, not a broader lookup
capability. `Explain` with contextual data requires
`authorization.check`, `authorization.explain`, and
`authorization.contextual_data`. `Explain` against an exact revision also
requires `authorization.explicit_revision`.

Authorization MUST occur before namespace-scoped existence is disclosed.
Capability grants MUST be restricted by namespace patterns. An absent
`CallerAuthorizer` MUST reject every operation; there is no implicit embedded
superuser. Embedded callers MUST be configured explicitly. Standalone
authentication MUST NOT trust caller-supplied capability lists. Authorizer
rejection, malformed output, or failure returns a typed engine error and
performs no operation.

## 6. Policy revision state machine

```text
ABSENT
  -- valid Publish --> PUBLISHED(revision_id)
  -- invalid Publish --> ABSENT + typed error

PUBLISHED(revision_id)
  -- canonically equivalent Publish --> same revision_id, no duplicate mutation
  -- same digest/different bytes --> unchanged + integrity error
  -- read/decode failure --> unchanged + typed error
```

Publish MUST parse, validate, compile, canonicalize, and encode through the
tagged DSL Artifact API before durable storage. Revision identity MUST derive
from canonical semantic artifact content and compilation-affecting metadata.
Canonically equivalent content MUST return the existing revision without a
second mutation or event.

Revisions MUST be immutable. Publish MUST NOT activate a slot. Failed
publication MUST store nothing and MUST NOT change active traffic.
Runtime-specific Go `Program` values MUST remain cache-only. V1 MUST NOT delete
semantic revisions. Lookup MUST be namespace-isolated and MUST NOT reveal
cross-namespace existence.

`policy.read` returns revision metadata only. It MUST NOT expose an artifact,
canonical source, IR, compiled program, or other policy content. Artifact bytes
and compiled values remain internal to the application and storage boundaries.

## 7. Optional local slot state machine

```text
UNSET
  -- Activate(target, expected=unset) --> ACTIVE(target, generation=1)
  -- Activate(target, expected!=unset) --> UNSET + conflict
  -- Activate(missing/incompatible target) --> UNSET + typed error

ACTIVE(current, generation=n)
  -- Activate(target, expected=(current,n)) --> ACTIVE(target, generation=n+1)
  -- Activate(target, stale expected revision or generation) --> unchanged + conflict
  -- Activate(missing/incompatible target) --> unchanged + typed error
```

Activation MUST be atomic, ABA-safe CAS. Its precondition MUST represent exactly
an unset slot or an active slot's revision and positive generation. Both the
expected revision and generation MUST match before an active slot changes. The
target revision MUST be durably readable in the same namespace before the slot
changes. Every successful activation MUST increase slot generation
monotonically. Rollback MUST be a normal CAS activation of an older revision.
Publish and activation MUST remain separate.

A failed or stale activation MUST leave slot state and history unchanged.
Activation history MUST be append-only and locally bounded. Canary, scheduling,
percentages, promotion, distribution, and drift reconciliation are not slot
semantics.

## 8. Authorization-data generation state machine

```text
GENERATION(g)
  -- valid WriteData(expected=g) commits --> GENERATION(g+1)
  -- stale expected generation --> GENERATION(g) + conflict
  -- validation/store failure --> GENERATION(g) + typed error
  -- idempotent replay, same digest --> original response, no second commit
  -- same idempotency key, different digest --> GENERATION(g) + conflict
```

Relationship tuples and typed attributes MUST share one generation. Writes and
deletes MUST commit atomically. Generation order MUST follow atomic commit
order, not transaction start time, timestamp, or random identifier. Each write
MUST provide an explicit loaded `validation_revision_id` and MUST be validated
against that revision before mutation.

An attribute is keyed by an entity and a non-empty sequence of DSL identifier
path segments and stores one typed scalar leaf. The path is structured; it MUST
NOT be flattened into a delimiter-joined string. The same entity cannot contain
both a path and one of its strict prefixes. Such prefix conflicts in a request
MUST be rejected before mutation or evaluation.
If a valid persistent write conflicts with a path already present at its exact
expected generation, the write MUST return `CONFLICT` and leave state,
generation, idempotency, and events unchanged.

The empty dataset starts at generation `0`; the first successful mutation
commits generation `1`. `GetDataGeneration` returns only the current generation
metadata, requires `data.write`, and MUST NOT disclose tuples or attributes.

The exact successful generation used by reads and decisions MUST be returned.
`minimum_generation` is a lower bound only and MUST NOT be treated as an exact
snapshot or cache identity. If the minimum cannot be satisfied before the
deadline, evaluation MUST return a typed error. V1 MUST NOT claim exact
historical generation reads.

The per-write mutation limit is not a maximum dataset size. A pinned snapshot
MUST support bounded exact resource-and-relation tuple queries and typed
attribute point reads without materializing the whole namespace. A tuple query
returns every matching live subject or `RESOURCE_EXHAUSTED`; it MUST NOT return
a truncated authoritative result. Closing a snapshot releases its resources,
and subsequent reads through it fail closed. A read admitted before `Close`
MUST retain its pinned resource and complete under its own context; `Close`
waits for every such read. Reads admitted after closing begins fail with
`FAILED_PRECONDITION`, and concurrent `Close` calls are idempotent.

Tuple expiry MUST be enforced at read time using a clock captured once for the
request. Cleanup MUST NOT be required for expired tuples to stop granting
access.

Contextual data MUST require `authorization.contextual_data`. It MUST be
request-scoped and additive. Contextual deletes MUST be rejected. An exact
duplicate MAY be deduplicated. A contextual attribute that conflicts by typed
value with persisted or already supplied data MUST produce an invalid-context
error. Contextual facts MUST NOT silently override persisted facts and MUST
undergo the same artifact and type validation as persistent values.

## 9. Evaluation and snapshot-pinning state machine

Every `Check`, `BatchCheck`, and `Explain` MUST perform the following sequence:

1. Validate request shape and hard size limits.
2. Authenticate or identify the caller through the adapter.
3. Authorize the operation, namespace, and additive capabilities.
4. Resolve exactly one selector: a normal slot selector, or an exact revision
   selector with `authorization.explicit_revision`.
5. Pin the revision ID and, when applicable, slot generation.
6. Capture evaluation time once.
7. Resolve and pin one exact committed data generation.
8. Validate and merge trusted contextual facts additively.
9. If delegation evidence is supplied, call `DelegationVerifier` and validate
   its typed result.
10. Evaluate the DSL graph and guards against the pinned inputs.
11. If approval requirements are returned, process approval evidence according
    to the evidence state machine.
12. Produce one policy result or one typed engine error.
13. Submit privacy-safe metadata to `DecisionEventSink` on a best-effort basis.

Failure at any of steps 1 through 12 stops the operation with a typed engine
error and MUST NOT fall through to evaluation, a stale result, or a partial
authoritative result. Step 13 is best-effort: a sink error or drop MUST be
reported safely and MUST NOT change the completed decision. In-flight
activation or data writes MUST NOT change a pinned request.

Evaluation MUST be deterministic, side-effect-free, and network-free after
trusted extension results and snapshot resolution. Request budgets MAY lower
configured budgets but MUST NOT raise them. Cache eviction or miss MUST NOT
change semantics. No final decision cache is permitted in V1.

The module-root V1 hard maxima for identifiers, source and artifact bytes,
collections, evidence, pages, extension outputs, aggregate bytes, and work are
stable public limits. Deployment or per-request configuration MAY lower these
maxima and MUST NOT raise them. Limit checks MUST occur before attacker-sized
allocation, cloning, sorting, or extension work.

## 10. Decision and evidence state machine

Base DSL decisions are combined as follows:

```text
graph denial                          -> DENY
graph allow + guard allow             -> ALLOW
graph allow + matching deny           -> DENY
graph allow + approval requirements   -> REQUIRE_APPROVAL
no guard match                        -> DENY
```

### Approval evidence

```text
outstanding requirements + no evidence
  -> REQUIRE_APPROVAL
no requirements + supplied evidence
  -> typed unexpected-evidence error
requirements + valid complete evidence
  -> ALLOW
requirements + valid partial evidence
  -> REQUIRE_APPROVAL(lexically sorted unsatisfied requirements)
requirements + invalid/unavailable verifier result
  -> typed engine error
```

Supplied evidence MUST be verified only through `ApprovalVerifier`. Verifier
success MUST identify satisfied requirement IDs through a typed result. If all
requirements are satisfied, the final decision MAY become `ALLOW`. Invalid
evidence, timeout, cancellation, verifier error, malformed output, or the reject
default MUST return a typed engine error. Approval evidence MUST never widen a
graph or guard `DENY`.

Each approval verification MUST receive an immutable evidence binding over the
authenticated caller, byte-exact namespace, original selector, resolved exact
revision, slot generation when applicable, exact data generation, one captured
evaluation time, and one fixed-size canonical request fingerprint.

### Delegation evidence

```text
no delegation evidence
  -> do not invoke DelegationVerifier
supplied valid evidence
  -> add only bounded typed request-scoped facts
supplied invalid evidence or verifier failure
  -> typed engine error
```

Supplied delegation evidence MUST be processed only by `DelegationVerifier`.
A successful verifier MAY return only typed request-scoped facts permitted by
the public contract. Returned facts MUST be additive and MUST NOT rewrite caller
identity, namespace, action, resource, selected revision, selector, or persisted
data. Invalid evidence, timeout, cancellation, verifier failure, malformed
output, or the reject default MUST return a typed engine error. Delegation
evidence MUST never bypass caller capability checks.

Each delegation verification MUST receive the same exact immutable evaluation
binding. Evidence or verifier output MUST NOT rewrite any binding field.

## 11. Basic BatchCheck

A batch MUST contain one namespace and one shared slot or exact revision
selector. The engine MUST pin one revision, slot generation when applicable,
evaluation time, and exact data generation for the entire batch.

All items MUST obey hard item, input, graph-work, and datastore-read limits.
Policy `DENY` and `REQUIRE_APPROVAL` are valid item results. Any engine error
MUST fail the complete batch; returned partial items MUST NOT be treated as
authoritative. Batch order and results MUST be deterministic.

When a batch supplies approval or delegation evidence, its evidence fingerprint
MUST canonically bind the complete ordered batch and every item semantic. It MUST
NOT be an item-level fingerprint and MUST NOT be reusable across a reordered or
otherwise different batch.

`BatchCheck` is not global reverse lookup, candidate discovery, graph expansion,
or fleet-scale evaluation.

## 12. Explain

`Explain` MUST be a separate operation, not a flag that weakens normal `Check`.
It MUST require `authorization.explain` in addition to every other capability
required by the request.

Normal `Check` MUST expose only compact metadata: decision ID, reason code,
revision, slot generation when applicable, data generation, evaluation time,
and whether contextual or evidence inputs were used.

`Explain` MUST redact all dynamic:

- subject and resource IDs;
- arguments;
- attributes;
- tuples;
- contextual facts;
- evidence and tokens.

It MAY expose stable schema paths, operators, rule and action names, boolean
outcomes, reason codes, and sorted requirement identifiers. The DSL may
internally produce a deterministic trace, but the engine MUST NOT expose its raw
dynamic values. `Explain` MUST preserve the exact decision semantics and pinned
snapshot of `Check`.

## 13. Typed errors and fail-closed behavior

Engine errors use these stable categories:

- `INVALID_ARGUMENT`
- `PERMISSION_DENIED`
- `NOT_FOUND`
- `CONFLICT`
- `FAILED_PRECONDITION`
- `RESOURCE_EXHAUSTED`
- `CANCELED`
- `DEADLINE_EXCEEDED`
- `UNAVAILABLE`
- `UNSUPPORTED_ARTIFACT`
- `CURSOR_EXPIRED`
- `INTEGRITY_ERROR`
- `INTERNAL`

Engine errors MUST NOT be encoded as policy `DENY`. An enforcement caller MUST
deny execution on every engine error. Audit or telemetry MAY classify this
fail-closed enforcement as `INDETERMINATE`; `INDETERMINATE` is not a policy
decision returned by the evaluator.

Errors MUST NOT disclose cross-namespace existence, raw evidence, policy inputs,
credentials, dynamic identifiers, or sensitive store values. No typed error may
carry an authoritative partial authorization result.

## 14. Events and telemetry

The state-event model is:

```text
successful new Publish -> RevisionPublished
successful Activate    -> SlotActivated
successful WriteData   -> DataWritten
idempotent replay      -> no duplicate state event
failed mutation        -> no state event; durable state unchanged
```

State events MUST commit atomically with the corresponding mutation. Cursors
MUST be monotonic within their namespace. `ListEvents` MUST be
capability-protected, cursor-based, and bounded. Expired cursors MUST return
`CURSOR_EXPIRED` and require full local-state resynchronization. Event retention
MUST be bounded. V1 MUST NOT expose streaming Watch.

Every revision, activation-history, and state-event response page MUST be bound
to its originating validated request, MUST NOT exceed the request limit or the
public hard maximum, and MUST reject out-of-scope or duplicate items. Revision
pages are ordered by publication time ascending and then revision ID ascending.
Activation-history pages are ordered by strictly increasing slot generation.
Event cursors are opaque: adapters MUST return store-monotonic order, while the
public constructor preserves that order and rejects duplicate cursors rather
than applying a lexical cursor comparison.

Decision events are separate from state events. `DecisionEventSink` delivery is
best-effort only in public V1. Sink failure MUST NOT change a completed decision.
Cancellation during sink delivery MUST report `CANCELED`; deadline expiry MUST
report `DEADLINE_EXCEEDED`, without exposing sink-provided details.
Public telemetry MUST NOT place raw IDs, arguments, attributes, tuples,
contextual facts, evidence, or tokens in labels or normal trace fields.
Security-sensitive exported values and construction inputs MUST also redact
those dynamic values under default `fmt` formatting and structured logging;
explicit typed accessors remain the only supported raw-value path.

## 15. Extension ports and defaults

<!-- markdownlint-disable MD013 -->

| Port | Contract | Public default |
| --- | --- | --- |
| Revision, slot, and data store | Authoritative immutable, CAS, and atomic-generation storage | A store is required; constructor rejects absence |
| `CallerAuthorizer` | Maps authenticated identity to capabilities and namespace patterns | Reject all |
| `ApprovalVerifier` | Verifies supplied approval evidence against exact request requirements | Reject supplied evidence |
| `DelegationVerifier` | Verifies supplied delegation evidence and returns bounded typed facts | Reject supplied evidence |
| `DecisionEventSink` | Receives privacy-safe completed-decision metadata | Best-effort no-op |

<!-- markdownlint-enable MD013 -->

Extension calls MUST receive the request context and obey cancellation and
deadlines. Verifier and authorizer output MUST be structurally validated.
Unknown or over-broad returned facts or capabilities MUST be rejected.
Extension-port absence MUST never silently grant authorization. The no-op sink
MUST never be described as durable audit.

The public invocation boundary MUST return on cancellation or deadline even
when an extension fails to cooperate. Panic-contained invocation workers and
abandoned calls MUST be concurrency-bounded; saturation MUST fail closed with
`RESOURCE_EXHAUSTED`. Extensions remain responsible for observing context so
their underlying work terminates. A matching authorizer grant MUST contain no
capability outside the exact canonical requested set.
Authorizer, approval-verifier, delegation-verifier, and sink quotas MUST be
independently bounded within the overall hard bound so one failing port cannot
starve another. Sanitization MUST NOT invoke extension-controlled `error`
methods; only a direct non-nil `*EngineError` may preserve a typed category.

Public configuration options MUST be sealed values produced by the module's
`With*` constructors. Their zero value is invalid; external packages MUST NOT be
able to supply arbitrary option callbacks. Nil and typed-nil extension ports,
option panics, and malformed option results MUST fail closed with sanitized typed
errors.

Public documentation and conformance suites describe interfaces and behavior,
not commercial implementations. Extension composition MUST be compile-time; V1
has no runtime Go plugin mechanism.

## 16. Cache semantics

The compiled cache key MUST include namespace, exact revision, and evaluator
ABI. The cache MUST be bounded by entry count and approximate bytes.
Singleflight MUST be scoped so different namespaces do not coalesce. Active
revisions MAY receive eviction preference but MUST remain evictable.

Slot-pointer cache state MUST be updated only after authoritative CAS commit.
Requests MUST retain their pinned revision after a concurrent pointer change.
Cache correctness MUST NOT depend on Watch or event delivery. Cache load,
decode, or compile failure is a typed engine error and MUST NOT use a stale
allow. V1 MUST NOT cache final authorization decisions.

## 17. Storage and deployment

Public V1 adapters are memory and SQLite. Memory is intended for tests,
development, and explicitly ephemeral embedding. SQLite is the durable local
adapter.

SQLite production defaults are WAL, foreign keys, configurable busy timeout,
`synchronous=FULL`, and explicit write transactions. Production auto-migration
MUST be off. Opening an incompatible, pending-required, corrupt, or
checksum-invalid schema MUST fail. `NORMAL` synchronization MUST be an explicit
development or benchmark override.

Embedded and standalone modes MUST run equivalent authorization conformance
scenarios. Caller authorization MUST be enforced in the shared core, not only
transport middleware. Standalone transport supports Connect, gRPC, and
gRPC-Web.

## 18. Explicit non-goals

The following are not part of public V1:

- Global reverse lookup, graph expansion, candidate discovery, or
  `FilterCandidates`
- Streaming Watch
- Final decision cache
- PostgreSQL or distributed or multi-region storage
- Central policy registry, distribution, promotion, rollout, scheduling, or
  drift management
- Approval issuance, workflow or inbox, key management, grant registry, or
  revocation distribution
- Delegation issuance, registry, lineage service, chain management, or
  revocation distribution
- Dataset-wide compatibility scans, simulation, or impact analysis at scale
- Required-durable decision audit, long-term search or retention, SIEM or
  compliance export, or forensic replay
- Managed online backup or restore, HA, SSO, fleet, inventory, or dashboard
- Dynamic Go, WASM, HTTP, or RPC evaluator plugins
- Exact historical data-generation reads
- REST or grpc-gateway in addition to Connect, gRPC, and gRPC-Web

The [security policy](./SECURITY.md) defines the mandatory operational and
reporting requirements for this contract.
