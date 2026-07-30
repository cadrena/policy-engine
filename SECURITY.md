# Security Policy

## 1. Supported versions and reporting

Conductera Policy Engine is currently pre-V1. Security fixes apply to the latest
published release and the current development branch as stated by release
notes. Unsupported versions may not receive fixes.

Do not open a public issue for a suspected vulnerability. Use GitHub Security
Advisories for the public `conductera/policy-engine` repository. Include only:

- the affected version or commit;
- a minimal reproduction using synthetic policy and data;
- the expected and actual decision or typed error;
- the potential security impact;
- redacted logs when necessary.

Never include production tuples, approval or delegation evidence tokens,
credentials, secrets, personal data, or sensitive identifiers in a report.

## 2. Security goals

The engine is designed to:

- deny execution on every engine failure;
- preserve namespace isolation and prevent existence leaks;
- pin exact policy and authorization-data inputs for each evaluation;
- reject untrusted or conflicting contextual facts;
- reject supplied approval and delegation evidence by default;
- bound parser, compiler, evaluator, datastore, cache, and event work;
- redact dynamic values from `Explain`, errors, logs, metrics, and traces;
- keep caches non-authoritative and semantically invisible.

`ALLOW`, `DENY`, and `REQUIRE_APPROVAL` are policy decisions. An engine failure
is a typed non-OK error, never a policy decision. Enforcement callers MUST deny
execution on all engine errors and may classify that enforcement outcome as
`INDETERMINATE` in privacy-safe audit or telemetry.

## 3. Trust boundaries

Policy source and encoded artifacts may be untrusted. The tagged Conductera DSL
must parse, validate, compile, canonicalize, and decode them under hard limits
before they are stored or evaluated.

Caller identity comes from an authenticated transport adapter or explicit
embedded composition. Caller request assertions and caller-supplied capability
lists are not authorization. The shared core authorizes every operation and
namespace before disclosing namespace-scoped existence.

Revision, slot, and data stores cross a correctness and security boundary. Their
responses are validated and failures become typed errors. `CallerAuthorizer`,
`ApprovalVerifier`, `DelegationVerifier`, and `DecisionEventSink` adapters also
cross trust boundaries; returned values must satisfy bounded typed contracts.

The deterministic evaluator does not establish transport identity, verify mTLS
certificates, make network calls, issue approvals or delegations, or manage
revocation registries. Transport authentication and TLS termination occur
outside deterministic evaluation. Approval and delegation lifecycle services
are not part of the public runtime.

## 4. Mandatory fail-closed matrix

<!-- markdownlint-disable MD013 -->

| Condition | Required result |
| --- | --- |
| Missing or rejecting caller authorizer | `PERMISSION_DENIED`; no operation |
| Unauthorized namespace or capability | `PERMISSION_DENIED`; no existence leak |
| Invalid or unsupported artifact | Typed error; no revision stored or used |
| Publish failure | Existing revisions and slot unchanged |
| Missing slot or revision | Typed error, never `DENY` or `ALLOW` |
| Stale activation revision or generation CAS | `CONFLICT`; slot unchanged |
| Stale data-generation CAS | `CONFLICT`; dataset unchanged |
| Persistent attribute path-prefix conflict | `CONFLICT`; dataset unchanged |
| Idempotency key reused with changed payload | `CONFLICT`; no mutation |
| Minimum generation unavailable by deadline | Typed timeout or precondition error |
| Untrusted contextual data | `PERMISSION_DENIED` or `INVALID_ARGUMENT` |
| Contextual attribute conflict | `INVALID_ARGUMENT`; no evaluation |
| Expired tuple | Must not grant |
| Supplied approval evidence with default verifier | Typed evidence error |
| Approval required but no evidence supplied | `REQUIRE_APPROVAL`, not engine failure |
| Supplied delegation evidence with default verifier | Typed evidence error |
| Verifier timeout, error, or malformed result | Typed error for that evidence-backed check |
| Datastore or read failure | Typed error |
| Cache load or decode failure | Typed error; no stale allow |
| Cancellation or deadline | `CANCELED` or `DEADLINE_EXCEEDED` |
| Depth, work, or item budget exhaustion | `RESOURCE_EXHAUSTED` |
| Malformed or cyclic runtime graph | Typed error or bounded safe failure; never allow |
| Any `BatchCheck` engine error | Entire batch non-authoritative |
| Decision sink failure | Decision unchanged; drop or failure reported safely |
| Expired event cursor | `CURSOR_EXPIRED`; require resynchronization |

<!-- markdownlint-enable MD013 -->

A failed mutation emits no state event. A failed or stale operation leaves the
last valid durable state authoritative.

## 5. Caller security

There is no implicit trust or superuser in embedded mode. An embedded caller
identity and authorizer must be composed explicitly; an omitted authorizer
rejects all operations. Standalone authentication MUST NOT trust capabilities
asserted in request content.

Capability grants are restricted by namespace patterns and are additive. Every
capability needed by a request must be present. Exact revision selection,
contextual data, `Explain`, and data writes require separate capabilities in
addition to basic check authorization where applicable. Authorization occurs
before revision, slot, data, or event lookup.

Coarse liveness exposure is a deployment choice. Detailed readiness and
component status require `system.status` and must not disclose namespaces,
artifact contents, identifiers, credentials, or component secrets.

## 6. Artifact and policy security

Durable policy revisions use only the deterministic, versioned Artifact API
from a tagged `github.com/cadrena/dsl` release. Public revisions MUST NOT
contain gob data, serialized Go objects, closures, function pointers, plugins,
user code, network functions, or executable implementation objects.

Revision identity binds canonical semantic content and compilation-affecting
metadata. Canonically equivalent policy returns the existing revision. A digest
collision or identical digest with different bytes is an `INTEGRITY_ERROR`.
Unsupported language, artifact, evaluator ABI, capability, corruption, or
decode failure is rejected before evaluation.

Publication stores nothing until parse, validation, compilation,
canonicalization, encoding, and durable commit succeed. Publication never
activates a slot, and failed publication cannot change active traffic.
Runtime-specific Go programs are cache-only.

Activation uses an ABA-safe expectation: either the slot is unset, or both its
active revision and positive generation match. `policy.read` exposes metadata
only; artifact bytes, canonical source, IR, and compiled programs remain inside
trusted application and storage boundaries.

## 7. Data and contextual-fact security

Comparisons are typed. The engine performs no string, number, boolean, null, or
identifier coercion that could widen authorization.

Persistent tuple and attribute mutations share one atomic generation. Each
write is validated against an explicit, loaded validation revision. Writes,
deletes, the generation increment, idempotency record, and state event commit
atomically or not at all. The exact committed data generation used by a read or
decision is returned.

Persistent and contextual attributes use immutable structured DSL field paths
to typed scalar leaves. Delimiter-joined path encodings are forbidden. A scalar
path and its strict descendant cannot coexist for the same entity; prefix
conflicts fail before state or evaluation changes.

The initial empty dataset is generation `0`, and the first successful mutation
commits generation `1`. The metadata-only `GetDataGeneration` operation requires
`data.write` and does not disclose tuples or attributes.

Contextual data requires separate authorization. It is request-scoped,
additive, bounded, and validated against the selected artifact. It cannot delete
or override persisted data. A typed attribute conflict is `INVALID_ARGUMENT`;
no evaluation occurs.

Tuple expiry is checked at read time against a clock captured once per request.
Cleanup timing cannot cause an expired tuple to grant access.

The mutation-batch bound does not cap accumulated dataset size. Pinned storage
reads are bounded per tuple query or attribute point lookup, remain fixed at one
exact generation across concurrent commits, and return all matches or a typed
resource error rather than a partial authorization input. Snapshot close waits
for reads that already own the pinned resource and prevents new reads; it never
rolls back a SQLite transaction underneath an admitted query.

## 8. Approval and delegation security

> Public V1 does not bundle approval or delegation issuance, workflow, registry,
> cryptographic key service, lineage, or revocation distribution.

Approval and delegation evidence is accepted only through typed verifier ports.
Omitted and default verifiers reject supplied evidence with a typed error. No
evidence does not invoke a verifier. Verifier outages therefore affect only
checks that supply the corresponding evidence; unrelated no-evidence checks
continue.

Evidence and verifier output never grant caller capabilities. Approval evidence
cannot widen graph or guard `DENY`. Delegation output may add only bounded typed
request-scoped facts and cannot rewrite caller identity, namespace, action,
resource, selector, selected revision, or persisted data. Invalid evidence,
timeout, cancellation, verifier failure, or malformed output produces a typed
engine error for that check.

Every verifier call is bound to the authenticated caller, byte-exact namespace,
original selector, resolved revision, slot generation when applicable, exact
data generation, one captured evaluation time, and a fixed-size canonical
request fingerprint. A batch fingerprint covers the complete ordered batch and
all item semantics; it is not reusable per item or across different batches.

Outstanding approval requirements without evidence produce
`REQUIRE_APPROVAL`. Valid verified evidence may satisfy identified requirements;
partial satisfaction leaves a lexically sorted set of unsatisfied requirements.
Unexpected evidence is rejected.

## 9. Resource-exhaustion defenses

Configured hard limits cover:

- request and transport body size;
- `BatchCheck` item count and aggregate input size;
- DSL source and artifact limits inherited from the tagged DSL;
- graph depth, node work, guard work, and datastore reads;
- contextual tuple and attribute count and size;
- compiled-cache entry count and approximate bytes;
- slot-pointer cache size;
- namespace-scoped singleflight work;
- event retention and event list size;
- SQLite lock waiting through a configurable busy timeout.

Cancellation and deadlines propagate to stores and extensions. Evaluation
captures time once. Per-request budgets MAY lower configured limits but MUST NOT
raise them. Exhaustion fails with `RESOURCE_EXHAUSTED`, `CANCELED`, or
`DEADLINE_EXCEEDED`; it never falls back to an allow.

Public extension invocation returns on cancellation or deadline even if an
adapter does not cooperate. Panic-contained workers and abandoned calls are
concurrency-bounded; saturation fails closed with `RESOURCE_EXHAUSTED`.
Adapters must still observe context to terminate their underlying work.
Each extension port has an independent quota within the overall bound, so a
verifier or sink outage cannot consume caller-authorizer capacity. Error
sanitization does not invoke adapter-controlled `As`, `Unwrap`, or equivalent
methods; only a direct non-nil `*EngineError` preserves its stable category.

The exported module-root hard maxima are stable V1 security boundaries. Checks
must reject oversized input before attacker-sized allocation, cloning, sorting,
or extension work. Deployment configuration may lower but never raise them.

## 10. Privacy and observability

Normal logs, metric labels, trace fields, errors, and `Explain` MUST NOT expose
raw dynamic subject or resource IDs, arguments, attributes, tuples, contextual
facts, evidence, tokens, credentials, or sensitive store values. Stable schema
paths, operators, action and rule names, boolean outcomes, reason codes,
revision identifiers, generations, and sorted requirement identifiers may be
reported when their disclosure is authorized and safe.

Security-sensitive exported request, input, collection, result, and
lifetime-bearing handle values must redact dynamic content under default `fmt`
formatting, Go-syntax formatting, and `slog`. Raw values are available only
through explicit typed accessors.
Logging and telemetry code MUST use those supported representations and MUST
NOT apply an incompatible explicit verb such as `%p` to a non-pointer value;
Go's invalid-verb diagnostic bypasses `fmt.Formatter` and is not a logging
redaction boundary. Pointer operands formatted with `%p` expose only addresses.
Store adapters must return direct sanitized `*EngineError` values. Adapter
wrappers and custom `As` or `Unwrap` chains are rejected at the conformance
boundary so alternate formatting cannot expose backend diagnostics.

`Explain` is a separate capability-protected operation. It redacts dynamic
values and preserves the exact `Check` decision and pinned snapshot. A DSL trace
may exist internally, but the engine does not expose its raw values.

`DecisionEventSink` is best-effort. Its default is a no-op, not durable or
enterprise audit. Sink or telemetry failure cannot authorize, deny, or alter an
otherwise completed decision. Drops and failures must be reported without
leaking request values.

Extension options are sealed module values: only package-provided `With*`
constructors create meaningful options. Zero options, nil or typed-nil ports,
option panics, and malformed option results fail closed. Sink cancellation and
deadline expiry retain their distinct sanitized `CANCELED` and
`DEADLINE_EXCEEDED` categories.

Revision, activation-history, and state-event pages are validated against their
originating request scope and limit. Duplicate or out-of-scope entries are
rejected. Revision and activation pages enforce their normative deterministic
orders. Event cursors remain opaque and store-monotonic; the public boundary
preserves adapter order and rejects duplicate cursors without lexical inference.

## 11. Operational responsibilities and non-goals

Operators are responsible for TLS or mTLS termination, caller identity mapping,
namespace-scoped capability policy, SQLite file and directory permissions,
secret handling, host hardening, capacity, monitoring, and backup policy.
Secrets and evidence must not be placed in policy source, command-line
arguments, normal logs, or telemetry.

The durable local SQLite adapter uses WAL, foreign keys, configurable busy
timeout, `synchronous=FULL`, and explicit write transactions by default.
`NORMAL` synchronization is an explicit development or benchmark override.
Production auto-migration is off. Operators must run explicit, checksum-verified
migrations and must refuse incompatible, pending-required, corrupt, or
checksum-invalid schemas.

Public V1 does not claim managed backup or restore, high availability, SSO,
fleet operations, centralized rollout, durable decision audit, long-term
search, SIEM export, or hosted operational services. State-event retention is
bounded; an expired cursor returns `CURSOR_EXPIRED` and requires full local-state
resynchronization.

The [V1 specification](./SPEC.md) defines the operations, capabilities, state
machines, decisions, and typed errors secured by this policy.
