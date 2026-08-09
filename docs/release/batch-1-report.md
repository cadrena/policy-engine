# Policy Engine Batch 1 Report

> **Superseded for current release status.** This report remains historical
> evidence; use the [public Batch R rebaseline summary](batch-r-report.md) for
> current public release truth.

## Checkpoint status

Batch 1 closes the public decision-core checkpoint. Memory-backed local policy
lifecycle, authorization data, `Check`, snapshot-pinned `BatchCheck`, privileged
redacted `Explain`, and embedded composition are available at this source
checkpoint on `codex/policy-engine-v1-runtime`. This checkpoint is not
published to main yet. It authorizes development of durable adapters and
transports; it is not a stable V1 release.

SQLite, ConnectRPC, the standalone binary, the public container image, and the
stable V1 tag remain in development. No stable tag was created for this
checkpoint.

Landing is explicitly excluded from Batch 1 and was not modified. Batch 0
release readiness remains blocked only by its separate landing contract; that
does not block this Policy Engine source checkpoint.

## Public package and dependency boundary

- Contracts remain in the module-root package imported as
  `github.com/cadrena/policy-engine`.
- Public composition is `embedded.New` in
  `github.com/cadrena/policy-engine/embedded`, not a root `New` function. A root
  constructor would introduce a Go import cycle because the application and
  store layers already import the root contract package. The public correction
  preserves one-way composition without moving or duplicating root contracts.
- The engine consumes the corrective public DSL v1.1.1 contract. The DSL owns
  artifact and evaluator semantics; the engine owns local lifecycle, data,
  capability enforcement, snapshot pinning, operational failure behavior, and
  composition.
- The public runtime imports no commercial module, loads no runtime Go plugin,
  and requires no commercial credential or service for correctness.
- Approval and delegation remain typed verifier ports with reject defaults.
  The decision sink remains best-effort and is not durable audit.

## Package and API deviations

| Planned shape | Shipped public shape | Reason |
| --- | --- | --- |
| Root `policyengine.New(options ...Option)` | `embedded.New(options ...embedded.Option)` | Approved import-cycle correction; composition is public while root contracts remain cycle-free. |
| DSL `ReadSubjects` | DSL v1.1.1 `ReadTuples(context.Context, dsl.EntityRef, string)` | The brief used a stale pre-correction DSL name. |
| Exported DSL value type | DSL v1.1.1 `map[string]any` request arguments and `(any, bool, error)` attribute reads | The corrective DSL has no exported `dsl.Value`; the engine converts its closed public value set at the adapter boundary. |
| Delegation verification before data pinning | Pin the exact data generation, build the immutable evidence binding, then verify delegation | The frozen evidence contract requires the exact data generation in every verifier binding. |
| Revision-derived attribute-path enumeration alone | Public `store.Snapshot.HasAttributeDescendant` occupancy probe | Required to detect strict descendant conflicts created under an older revision without exposing stored values. |

These are the only approved public/package deviations in Batch 1. There is no
ConnectRPC, SQLite, standalone, image, or stable-tag claim in this checkpoint.

## Specification review: sections 8–16

| Section | Reviewed shipped behavior | Result |
| --- | --- | --- |
| §8 Authorization data | Atomic tuple/attribute generations, expected-generation CAS, idempotent replay, explicit validation revision, structured attribute paths, bounded pinned reads, expiry at captured time, and additive contextual facts | Conforms for the memory-backed checkpoint. Exact historical generation reads remain explicitly unsupported. |
| §9 Evaluation and pinning | Authorization before namespace disclosure; one pinned revision, slot generation, evaluation time, and exact data generation; deterministic DSL evaluation; all pre-result failures are typed and fail closed; no final-decision cache | Conforms. A data advance between head read and snapshot open is detected and fails closed because V1 has no historical-generation open operation. |
| §10 Decisions and evidence | DSL decisions map to `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`; unexpected or invalid evidence is an engine error; verifier bindings include the exact immutable request snapshot | Conforms, including reject-default verifiers and complete ordered-batch fingerprints. |
| §11 BatchCheck | One shared snapshot for the ordered batch, cumulative public budgets, deterministic order, and all-or-error behavior | Conforms for bounded local batch authorization; no reverse lookup or candidate discovery was added. |
| §12 Explain | Separate capability-protected operation, same pinned evaluator path as Check, artifact-validated schema metadata, and no dynamic values | Conforms. Forged trace metadata fails closed and no raw DSL trace is exposed. |
| §13 Typed errors | Policy denial remains distinct from typed engine failure; dependency errors are sanitized; no authoritative partial response is returned | Conforms. Hostile recursive error hooks are not invoked. |
| §14 Events and telemetry | Atomic memory-backed state events and privacy-safe best-effort completed-decision metadata | Conforms within the shipped memory runtime. Decision events are not durable audit. |
| §15 Extension ports | Required store and caller authorizer, reject-default verifiers, no-op decision sink, sealed embedded options, bounded invocation, cancellation, typed-nil and hostile-option rejection | Conforms at the public `embedded.New` boundary. |
| §16 Caches | Namespace/revision/ABI compiled-cache key, bounded caches, authoritative slot resolution before pointer optimization, retained request-local pin, and no decision cache | Conforms. Cache misses and eviction do not change decision semantics. |

## Specification and security findings

Every Batch 1 review finding that required a code change is recorded below.
Feature commits are included where a finding was caught during tests-first
implementation rather than a later fix round.

| Finding | Fix commit |
| --- | --- |
| Attribute paths were represented in a delimiter-flattened form and same-revision strict ancestor/descendant contextual conflicts were incomplete. | `4c221029ab4b7c166e3713ac4282872e2a13683a` (`fix: reject contextual attribute path conflicts`) |
| Revision-derived path enumeration could miss contextual conflicts with persistent paths written under older revisions. | `1c217110b861699dc8e51aba85b3c83bf423b440` (`fix: detect contextual conflicts across revisions`) |
| Snapshot attribute reads did not reject both directions of contextual/persistent path overlap; tuple union lacked bounded processing cancellation checks; duplicate raw tuple work could escape the pre-deduplication budget. | `b57cfee01866a5ee6f81af8ee07d87af379f5f38` (`fix: harden evaluator snapshot adapter`) |
| Direct or delegated contextual tuples could use undeclared schema shapes; recursive `errors.As`/`errors.Is` could invoke hostile dependency methods; exact-generation race handling required an adversarial close/fail-closed regression. | `7fff5e65c4e83698932cb2579b85045ab203f663` (`fix: harden pinned authorization check`) |
| The first Check mapping allowed approval evidence with no requirements to become a normal decision instead of a typed unexpected-evidence error. | `89fa91ce94e609b3543f09c1581079485b90740d` (`feat: add pinned authorization check`) |
| The initial BatchCheck implementation verified delegation more than once instead of once against the complete ordered-batch binding. | `8bbce2cfb20056bd8f6788be66dce991c4338d23` (`feat: add snapshot-pinned batch authorization`) |
| The shared evaluation session invoked `DelegationVerifier` before artifact-validating and additively normalizing direct contextual data. | This fix commit (`fix: validate contextual data before delegation`) |
| Explain conversion initially needed an exact-artifact allowlist so forged trace entity, declaration, or kind values could not cross the redaction boundary. | `eac9259de7900bf9fc9bf026c39d4f1ba656bc6f` (`feat: add privileged redacted explain`) |
| Initial public conformance tests did not force in-flight revision/data changes and verifier cancellation through the real invocation boundary, and delegation comparison was too shallow. | `23ce1bbd6146327c6c259402afeba9b010cf01cb` (`fix: harden embedded conformance suites`) |

The final whole-branch review found one additional ordering defect in the shared
evaluation session; the fix above restores the §9 requirement that invalid
direct contextual input fail before any delegation verifier call. The remaining
gaps are declared development work, not hidden availability:
SQLite, ConnectRPC, the standalone binary, the image, and stable release
packaging.

## Security review conclusion

- Caller capability and namespace authorization precede namespace-scoped
  existence disclosure.
- Missing or malformed authorization and verifier dependencies fail closed.
- Contextual and delegated facts are additive, schema-validated, bounded, and
  cannot rewrite the evaluation binding.
- Cancellation, deadlines, extension saturation, tuple/result cardinality,
  graph work, verifier output, and aggregate bytes are bounded by public
  contracts.
- Explain, typed errors, default formatting, and decision events do not expose
  dynamic identifiers, arguments, attributes, tuples, contextual facts,
  evidence, tokens, or dependency-controlled error text.
- The memory-backed checkpoint has no final-decision cache, runtime plugin,
  commercial correctness dependency, or durable-audit claim.

No unresolved specification or security finding blocks the Batch 1 source
checkpoint.

## Verification gates

The closeout gate was run from the repository root after the documentation
change. Every command exited zero:

| Gate | Result |
| --- | --- |
| `go test ./... -count=3` | PASS: all packages, three uncached runs |
| `go test -race ./...` | PASS: all packages under the race detector |
| `go test ./internal/app -run 'Test.*(Concurrent\|Cancellation\|Redact\|Replay\|Budget)' -count=20` | PASS: adversarial application selection, twenty runs |
| `go vet ./...` | PASS |
| `test -z "$(gofmt -l .)"` | PASS: no unformatted Go files |
| `python3 scripts/check_public_boundary.py` | PASS |
| `python3 -m unittest scripts.test_check_public_boundary` | PASS: 20 tests |
| `git diff --check` | PASS |

The checkpoint commit does not push, modify landing, or create a stable V1
tag.

## Fix round 1 evidence appendix

This evidence was captured with parent HEAD
`60ec784ccd055c7b0ad40ded6082c0dfc68701c9` plus the documentation corrections
in the commit containing this appendix, whose required subject is
`fix: correct Batch 1 checkpoint evidence`. A commit cannot contain its own
SHA; the exact resulting SHA is recorded in the ignored Task 7 execution
report. The commands below were run against the corrected working tree, and
the output and exit statuses are transcribed directly from those runs.

The availability predicate first demonstrated RED against `60ec784`:

```text
$ stale-main-availability predicate
docs/release/batch-1-report.md:7:redacted `Explain`, and embedded composition are available in source on main.
README.md:12:Available on main:
.superpowers/sdd/2026-07-30-batch-1-policy-engine-decision-core/task-7-report.md:35:  Explain and conformance as available on main, while SQLite, ConnectRPC, the
RED: branch-local checkpoint documentation still claims availability on main
exit 42
```

Fresh corrected-tree evidence:

```text
$ go test ./... -count=3
ok  github.com/cadrena/policy-engine  2.841s
ok  github.com/cadrena/policy-engine/conformance/authorization  0.400s
ok  github.com/cadrena/policy-engine/conformance/verifiers  0.371s
ok  github.com/cadrena/policy-engine/embedded  0.395s
ok  github.com/cadrena/policy-engine/internal/app  0.596s
?   github.com/cadrena/policy-engine/internal/artifact  [no test files]
ok  github.com/cadrena/policy-engine/internal/cache  0.379s
?   github.com/cadrena/policy-engine/internal/domain  [no test files]
ok  github.com/cadrena/policy-engine/internal/evaluator  0.474s
?   github.com/cadrena/policy-engine/store  [no test files]
ok  github.com/cadrena/policy-engine/store/conformance  1.094s
ok  github.com/cadrena/policy-engine/store/memory  1.887s
exit 0

$ go test -race ./...
ok  github.com/cadrena/policy-engine  (cached)
ok  github.com/cadrena/policy-engine/conformance/authorization  (cached)
ok  github.com/cadrena/policy-engine/conformance/verifiers  (cached)
ok  github.com/cadrena/policy-engine/embedded  (cached)
ok  github.com/cadrena/policy-engine/internal/app  (cached)
?   github.com/cadrena/policy-engine/internal/artifact  [no test files]
ok  github.com/cadrena/policy-engine/internal/cache  (cached)
?   github.com/cadrena/policy-engine/internal/domain  [no test files]
ok  github.com/cadrena/policy-engine/internal/evaluator  (cached)
?   github.com/cadrena/policy-engine/store  [no test files]
ok  github.com/cadrena/policy-engine/store/conformance  (cached)
ok  github.com/cadrena/policy-engine/store/memory  (cached)
exit 0

$ go test ./internal/app -run 'Test.*(Concurrent|Cancellation|Redact|Replay|Budget)' -count=20
ok  github.com/cadrena/policy-engine/internal/app  0.729s
exit 0

$ go vet ./...
(no output)
exit 0

$ test -z "$(gofmt -l .)"
(no output)
exit 0

$ python3 scripts/check_public_boundary.py
(no output)
exit 0

$ python3 -m unittest scripts.test_check_public_boundary
....................
----------------------------------------------------------------------
Ran 20 tests in 10.760s

OK
exit 0

$ git diff --check
(no output)
exit 0

$ corrected branch-local availability predicate
GREEN: availability is branch-local and explicitly unpublished
exit 0
```

## Final whole-branch fix evidence appendix

The verifier-order regression first demonstrated RED against parent HEAD
`4042a26da4d431c701177743e7d7c44e7106bc28`:

```text
$ go test ./internal/app -run '^TestCheckRejectsInvalidDirectContextualDataBeforeDelegationVerification$' -count=1
--- FAIL: TestCheckRejectsInvalidDirectContextualDataBeforeDelegationVerification (0.00s)
    check_test.go:178: delegation verifier calls = 1, want 0 for invalid direct contextual data
FAIL
exit 1
```

After reordering the shared session, the focused regression, exact-binding and
schema checks, and valid direct-plus-delegated additive batch behavior passed.
Fresh Check/Batch/Explain, repository, race, static-analysis, public-boundary,
formatting, and diff gates all exited zero:

```text
$ go test ./internal/app -run 'Test(Check|BatchCheck|Explain)' -count=1
ok  github.com/cadrena/policy-engine/internal/app  0.299s

$ go test ./... -count=1
PASS: all packages

$ go test -race ./... -count=1
PASS: all packages under the race detector

$ go vet ./...
exit 0

$ python3 scripts/check_public_boundary.py
exit 0

$ python3 -m unittest scripts.test_check_public_boundary
Ran 20 tests in 10.541s
OK

$ test -z "$(gofmt -l .)" && git diff --check
exit 0
```
