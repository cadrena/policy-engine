# Public and Commercial Boundary

## 1. Purpose and frozen invariant

This document freezes the dependency and product boundary for Cadrena Policy
Engine V1.

> Cadrena Policy Engine is a public local runtime. Commercial products may
> compose it through tagged public APIs and extension ports, but public runtime
> correctness and buildability never depend on commercial source, credentials,
> services, or infrastructure.

Local lifecycle and storage features exist to make embedded and standalone use
complete. They do not turn the runtime into a centralized management product.

## 2. One-way dependency rules

```text
public DSL -> imports neither policy engine nor commercial modules
public policy engine -> imports tagged public DSL
commercial products -> may import tagged public DSL and policy engine
public policy engine -> MUST NOT import commercial modules
```

Public source, tests, generated files, examples, builds, and releases MUST NOT
contain or depend on:

- proprietary code hidden behind build tags;
- unadvertised branches, directories, or release inputs;
- source submodules;
- copied proprietary implementation;
- generated commercial APIs;
- examples that require commercial services;
- release-time local module replacements;
- commercial credentials or registry configuration.

Commercial products may implement public typed ports and consume public
conformance suites. Composition is compile-time and one-way. The public runtime
does not load runtime Go plugins or call a commercial service for correctness.

## 3. Normative capability ownership

The cross-repository
[Cadrena V1 capability matrix](../../control-plane/docs/product/capability-matrix.md)
is the sole normative OSS/commercial ownership table.

For the Policy Engine, Community OSS includes deterministic evaluation, memory
and SQLite local policy state, typed approval and delegation verifier ports,
local state events, and privacy-safe OpenTelemetry export. Approval or
delegation issuance and registries, central policy activation, organizational
durable audit and search, and managed operations are not public runtime
capabilities. Local lifecycle and best-effort export do not reclassify those
commercial responsibilities.

## 4. Safe public defaults

The public composition contract has these defaults:

- A revision, slot, and data store is required; construction rejects absence.
- An omitted `CallerAuthorizer` rejects every operation.
- An omitted or default `ApprovalVerifier` rejects supplied approval evidence.
- An omitted or default `DelegationVerifier` rejects supplied delegation
  evidence.
- The default `DecisionEventSink` is a best-effort no-op and is not durable
  audit.
- Evaluation has no network callback to commercial services.
- The distribution includes no placeholder commercial workflow or service.

No default may silently grant authorization. No verifier absence may be
interpreted as successful evidence verification.

## 5. Public clean-room acceptance

A clean environment with public network access only MUST be able to:

- download every public dependency;
- build and test the module;
- generate and verify public API artifacts;
- build the public image;
- run embedded and standalone examples;
- exercise a local policy, data, and check loop;
- complete all steps without commercial credentials or repositories.

The module graph, source archive, generated artifacts, examples, CI, and image
context MUST satisfy the same acceptance rule.

## 6. Change control

Any reclassification requires all of the following before implementation:

1. Explicit product approval.
2. An update to this matrix.
3. Corresponding updates to `SPEC.md` and `SECURITY.md`.
4. A dependency and module-graph review.
5. A clean-room build review.
6. A separate public API release before commercial code consumes the change.

A commercial implementation need does not by itself permit a public-to-commercial
dependency, an unreleased API dependency, or a hidden release input.

The [V1 specification](../SPEC.md) is the normative runtime contract governed by
this boundary.
