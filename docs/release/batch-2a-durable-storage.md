# Policy Engine Batch 2A — Durable SQLite Storage Release Evidence

## Decision

The original implementation and repository gates passed on candidate
`c81ccabe5af4901027dc5ab68ea87cf00dfa650c`; the corrective Task 6 gate passed
on `affc22304524f9afb48c2321a9c73abbfeac54f3`; and the final whole-branch
review remediation gate passed on
`5e730d32ad160c09ce88d48f1c8ee2880bec2c73`. The required fresh Task 6 review
and required fresh whole-branch review have still not occurred. This document
therefore records a blocked decision rather than inferring authorization from
test results or remediation work.

## Candidate and commit chain

Merge base: `846fb7b0a6bb24eff31d350d727b0ff68ea3f9a9`.

| Task | commits |
| --- | --- |
| 1 | `3d922f3`, `9eb98c8` |
| 2 | `2edc312`, `a37d58e` |
| 3 | `62cdd9b`, `a2fc373` |
| 4 | `bbb84a1`, `6d8151a` |
| 5 | `b079ed0`, `b3e1e1b`, `44494d5` |
| 6 | `084ffd6` (integrity/recovery implementation), `cf0e558` (lint gate cleanup), `c81ccab` (verified gitleaks false-positive allowlist), `cf4765` (initial blocked evidence), `affc223` (corrective integrity invariants and WAL preservation), `3aaf5c2` (final review hardening), `5e730d3` (test-only lint correction) |

The initial implementation candidate used for the first final green gate was
`c81ccabe5af4901027dc5ab68ea87cf00dfa650c`. The latest remediation candidate
is `5e730d32ad160c09ce88d48f1c8ee2880bec2c73`.

## Durable format and environment

- Schema version: `1`.
- Embedded migration: `store/sqlite/migrations/0001_initial.sql`, exactly
  3,580 bytes, SHA-256
  `3063fb53855921e7f4ec734acde3426aa194f6573b37166f53f41eb690428b9e`.
- Module language version: Go `1.25.0`; enforced toolchain: `go1.25.12`.
- Final gate runtime: `go version go1.25.12 darwin/arm64`.
- SQLite driver module: `modernc.org/sqlite v1.56.0`; bundled SQLite engine
  source: `3.53.3` (`3053003`); libc module:
  `modernc.org/libc v1.74.4`.
- Locking boundary: only Darwin and Linux local filesystems are supported.
  Runtime and maintenance coordination uses owner-only (`0600`) `<database>.lock`
  sidecars and nonblocking `flock` shared/exclusive locks. The runtime and
  maintenance entry boundaries now classify the database parent with a
  fail-closed platform allowlist: Darwin APFS/HFS; Linux ext4, XFS, Btrfs,
  F2FS, tmpfs, and overlayfs. Network, FUSE, unknown, and all other operating
  systems return `FAILED_PRECONDITION` before lock or SQLite setup. Database
  and sidecar setup opens the final component with no-follow flags, verifies
  the descriptor is regular with `fstat`, then sets `0600`; symlinks and
  nonregular objects fail without changing their target.

## Task 6 behavior and focused evidence

The initial RED probe on 2026-08-10 used:

```text
rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test ./store/sqlite ./cmd/cadrena-policy-store -run 'Test(Integrity|Recovery|Crash|Subprocess|RunIntegrity)' -v
```

It first failed to compile because `FullIntegrityCheck` did not exist, then
failed behaviorally because `integrity` was not an accepted CLI command. The
same focused command passed after implementation. The repeat gate also passed:

```text
rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test ./store/sqlite ./cmd/cadrena-policy-store -run 'Test(Integrity|Recovery|Crash|Subprocess|RunIntegrity)' -count=10
```

The focused SQLite/CLI suite covered all of the following concrete cases:

- clean reopen reconstructs revision, activation generation, tuple, events,
  and idempotent replay;
- subprocess exit after a committed WAL transaction recovers the complete
  public values before checkpoint, while exit before commit exposes no staged
  row;
- truncated main database and malformed nonempty WAL both fail closed with
  `INTEGRITY`, and neither recovery path touches an outside canary;
- bounded `Open` checks schema/ledger/meta/heads but does not scan malformed
  tuple rows; `FullIntegrityCheck` performs the exhaustive durable scan;
- ledger, foreign-key, cursor-key, head/history, codec, idempotency, future
  schema, cancellation/deadline, raw SQLite busy, live runtime, and second
  maintenance-process cases return their required public categories;
- CLI `integrity` accepts only a closed migrated store, emits one safe `VALID`
  line on success, and emits only sanitized categories on all tested failures.

`batch-2a-focused` is an explicit Make target that repeats approval binding,
SQLite/conformance/CLI, and integrity/recovery tests under `GOTOOLCHAIN=go1.25.12`.
`batch-2a-final` spells out the complete gate sequence below and inherits the
same toolchain; it does not replace the directly captured candidate gate.

## Final candidate gate

All commands below ran serially without edits on
`c81ccabe5af4901027dc5ab68ea87cf00dfa650c` within the UTC gate window
`2026-08-10T04:16:38Z` through `2026-08-10T04:19:53Z`. Each command exited 0.

The approval-binding repetition command, shown outside the table so its regular
expression remains copyable, was:

```text
rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test . ./internal/app ./conformance/authorization -run 'Test.*(ApprovalBinding|AuthorizationDigest|ApprovalContinuation)' -count=10
```

| command | observed result |
| --- | --- |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go version` | exact `go1.25.12 darwin/arm64` |
| approval-binding repetition command above | approval binding repetition passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test ./store/sqlite ./store/conformance ./cmd/cadrena-policy-store -count=10` | SQLite, shared conformance, and CLI repetition passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test ./... -count=3` | complete suite passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go test -race ./... -count=1` | complete race suite passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go vet ./...` | passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 go mod verify` | `all modules verified` |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make fmt-check lint generated-check` | formatting clean, golangci-lint reported `0 issues`, generation clean |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make boundary boundary-test` | public-boundary scan and 20 Python boundary tests passed |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make vuln-check` | `No vulnerabilities found.` |
| `rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make gitleaks` | directory and 54-commit history scans reported no leaks |
| `rtk git diff --check` | passed |
| `rtk git status --short --branch` | clean `batch-2a-durable-storage` worktree |

## Failed attempts, fixes, and reruns

1. The expected RED failures described above preceded the implementation.
2. A focused lock test initially rejected a zero-length SQLite-created `-wal`
   sidecar as corrupt. The checker now treats an empty sidecar as no recovery
   state while continuing to reject nonempty malformed headers/frames; the
   focused `-count=10` and race reruns passed.
3. A new corruption assertion showed `Open` accepted a malformed nonempty WAL
   that SQLite would otherwise ignore. A bounded header/frame-shape startup
   validation was added, while only the offline command performs the exhaustive
   WAL-frame scan. The corrupt-WAL `Open` test then passed.
4. Candidate `084ffd6` failed the exact lint gate with 86 findings under the
   pinned linter. A merge-base audit found one pre-existing revive finding at
   `846fb7b`; the other 85 were Batch 2A findings. `cf0e558` fixed all 86
   mechanically without changing lint configuration or suppressing rules; the
   rerun reported `0 issues`.
5. Candidate `cf0e558` failed the warmed directory secret scan on four verified
   false positives: three intentional privacy-test canaries and one ignored
   local review diff containing a public Go checksum. `c81ccab` added only
   their exact gitleaks fingerprints. Warmed directory and history scans then
   both reported no leaks.

The first vulnerability and secret runs performed dependency bootstrap; the
definitive warmed reruns are the passing results recorded in the final gate.

## Corrective Task 6 integrity follow-up

This corrective record follows the initial blocked evidence commit `cf4765`
and the implementation fix
`affc22304524f9afb48c2321a9c73abbfeac54f3`. It changes no authorization
decision.

The corrective implementation enforces these durable relations during the
offline full check:

- each namespace data generation in the closed interval `1..data_generation`
  has exactly one decoded durable idempotency response, with no duplicate
  generation under a different key;
- retained activation rows are a sorted, consecutive suffix ending exactly at
  the slot-head generation; a legitimately pruned prefix remains allowed;
- the checker opens one original source connection, asserts the pinned
  `modernc.org/sqlite v1.56.0` `FileControl` interface, sets
  `FileControlPersistWAL("main", 1)` before `BEGIN EXCLUSIVE`, revalidates the
  now-locked WAL, scans in that transaction, rolls back, and closes without
  restoring the close-time persistence mode.

The last point is deliberate: restoring the mode on the final checker
connection can cause the prohibited close-time cleanup. The test fixture keeps
a committed WAL hot after abrupt child exit. It snapshots both `-wal` and
`-shm` before and after the checker, requires the WAL bytes to be identical,
requires any pre-existing SHM sidecar to remain present and non-empty, then
opens the original database directly and verifies complete recovered public
state. Exact SHM byte equality is not a durable-state contract: SQLite may
refresh WAL-index and lock bookkeeping while acquiring `BEGIN EXCLUSIVE`; the
unchanged WAL plus successful fresh recovery is the relevant no-checkpoint
proof.

The strengthened crash/reopen oracle derives its expected revision and data
fixture independently of the writer path and compares all public values:
revision namespace/ID/publication time/artifact/provenance/digest, complete
activation including time, data generation and idempotent replay, snapshot and
complete tuple result, and every event's namespace, cursor semantics, kind,
payload-derived fields, generation, and timestamp. A subprocess raw SQLite
`BEGIN IMMEDIATE` writer that does not hold Cadrena's advisory sidecar now
also proves the original source `BEGIN EXCLUSIVE` returns `UNAVAILABLE` while
contended and succeeds after the writer exits.

### Corrective TDD record

The relation RED probe first reported five failures: the containing table plus
the four newly uncovered gaps (activation history `{1,3}`, missing idempotency
generation, duplicate idempotency generation under a second key, and a
non-contiguous idempotency sequence). The hot-WAL probe first showed that the
old checker deleted the durable `-wal` at close. Enabling the supported file
control on the original checker connection made the WAL preservation test
green; the test intentionally permits transient SHM bookkeeping changes for
the reason stated above. The contiguous pruned history acceptance fixture and
the subprocess raw-writer contention fixture both pass.

### Committed-input corrective gate

Candidate `affc22304524f9afb48c2321a9c73abbfeac54f3` was clean before the
gate. The aggregate target ran with command-local module verification in the
UTC window `2026-08-10T04:59:10Z` through `2026-08-10T05:01:53Z` and exited 0:

```text
rtk run 'env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make batch-2a-final'
```

The target reported `go1.25.12 darwin/arm64`, repeated approval binding,
SQLite/conformance/CLI, and integrity/recovery tests, then completed the
complete `-count=3` suite, full race suite, vet, module verification,
format/lint/generation, boundary checks, vulnerability scan, gitleaks,
whitespace diff check, and clean-status check. Post-target
`rtk git status --short --branch` was clean and `rtk git diff --check` passed.

### Post-evidence aggregate gate

Corrective evidence commit `cf0ae2e0d86c42e50869f31fcc4737a899c92781`, which
records implementation commit `affc22304524f9afb48c2321a9c73abbfeac54f3`,
also passed the complete post-evidence aggregate target. The command used the
same command-local checksum database setting in UTC window
`2026-08-10T05:03:46Z` through `2026-08-10T05:06:00Z`, exited 0, and left a
clean worktree:

```text
rtk run 'env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make batch-2a-final'
```

This post-evidence PASS is evidence only; it does not replace either required
fresh review or change the terminal blocked decision below.

## Final whole-branch review remediation

Implementation commit `3aaf5c21a5cecfc8da48d03dda9f323d1b0a1786` and
test-only lint correction `5e730d32ad160c09ce88d48f1c8ee2880bec2c73` address
the final review findings without changing the schema or authorizing a later
batch.

- Bounded runtime validation now rejects a persisted `state_events.sequence`
  above its namespace head through a `SELECT EXISTS` relation probe. The
  existing namespace-head metadata scan remains the outer bounded startup
  work; the event lookup uses the `(namespace, sequence)` primary key and does
  not decode or scan event payloads. The existing `expired_through <=
  event_sequence` validation remains in place.
- Runtime `Open` and every maintenance entry (`PlanMigrations`,
  `ApplyMigrations`, `ValidateSchema`, and `FullIntegrityCheck`) classify their
  storage parent before lock or SQLite setup. Unsupported filesystem outcomes
  are sanitized to `FAILED_PRECONDITION`; unexpected classifier failures are
  sanitized to `INTERNAL`.
- Owner-only database and lock setup now reject final-component symlinks,
  directories, FIFOs, and other nonregular objects using platform-specific
  no-follow open plus descriptor `fstat`; a rejected outside canary is neither
  chmodded nor migrated.
- Migration ledger timestamps now use the same panic-safe, nonzero,
  representable UTC canonical-clock boundary as runtime clocks. A panicking or
  zero clock produces sanitized `INTERNAL` and rolls back the migration
  transaction before a schema-migration or cursor-key ledger record commits.

The RED probes were captured before implementation: `Open` accepted a
persisted event beyond its head; all injected unsupported-filesystem entry
calls reached their normal paths; symlink setup chmodded disposable `0644`
canaries while directories returned `INTERNAL`; the no-follow FIFO helper was
absent; a migration clock panic escaped and a zero clock committed. The focused
GREEN regressions and `go test ./store/sqlite -count=1` passed. A Linux
`GOOS=linux GOARCH=amd64` compile-only SQLite test binary also built cleanly;
an initial cross-platform `go test` run was not used as evidence because it
correctly could not execute a Linux test binary on Darwin.

The first aggregate attempt on `3aaf5c2` passed tests, race, vet, and module
verification, then failed only the pinned `revive` lint rule on test helper
signature/unused-parameter style. Commit `5e730d3` changes only those test
signatures, preserves the RED/GREEN assertions, and passed the pinned lint
command before the clean candidate rerun.

Candidate `5e730d32ad160c09ce88d48f1c8ee2880bec2c73` was clean before the
complete pre-evidence aggregate command. It ran from
`2026-08-10T05:53:19Z` through `2026-08-10T05:55:29Z`, exited 0, and left the
worktree clean:

```text
rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make batch-2a-final
```

The target reported `go1.25.12 darwin/arm64` and passed all focused repeats,
complete normal and race suites, vet, module verification, format/lint/
generation checks, public-boundary checks and 20 Python boundary tests,
vulnerability scan, directory and 60-commit-history gitleaks scans, whitespace
diff check, and clean-status check.

Deferred minor — retain only `.gitleaksignore:1`: it is the exact fingerprint
for the ignored local SDD review artifact
`.superpowers/sdd/2026-08-10-batch-2a-policy-engine-durable-storage/review-9eb98c8..2edc312.diff`
and no other allowlist entry was added or changed by this remediation. Remove
that line only in the same cleanup change that removes this ignored artifact
from the scanned worktree; then record a passing
`rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make gitleaks` report
covering both directory and history scans. The SDD artifact remains retained
for this review, so line 1 remains necessary and unchanged.

### Post-remediation-evidence aggregate gate

Evidence commit `670bb8ee3769f73452a9685e06ef5f574af5d95c`, which records the
remediation implementation and its committed-input gate, also passed the exact
post-evidence aggregate target. The clean committed-input run used the same
command-local checksum and toolchain settings from `2026-08-10T05:57:23Z`
through `2026-08-10T05:59:36Z`:

```text
rtk env GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.12 make batch-2a-final
```

It passed focused repeats, normal and race suites, vet, module verification,
format/lint/generation, boundary and vulnerability checks, gitleaks directory
and 61-commit-history scans, whitespace diff check, and clean-status check.
This final evidence record does not replace the pending fresh reviews or alter
the blocked decision.

## Review state and non-goals

| scope | fresh review verdict |
| --- | --- |
| Tasks 1–5 | clean according to their recorded implementation-ledger reviews |
| Task 6 | pending — corrective `affc223` and remediation `3aaf5c2`/`5e730d3` have not yet received a fresh review |
| Full Task 1–6 branch/evidence | pending — not yet performed after the remediation evidence update |

The two pending reviews above are the sole blockers. This work creates no tag,
does not publish an artifact, and is not a v1.0 release decision. Batch 2B may
only be considered after the pending reviews complete and a separately captured
evidence update authorizes it.

BLOCKED — Batch 2B is not authorized.
