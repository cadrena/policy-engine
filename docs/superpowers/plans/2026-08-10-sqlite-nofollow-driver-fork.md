# SQLite NOFOLLOW Driver Fork Implementation Plan

**Status:** completed on 2026-08-10.

**Goal:** Make every durable SQLite connector reject a database symlink even
when SQLite has a reusable descriptor for the symlink target in the current
process.

## Settled architecture

- `internal/sqlitenofollow` mirrors the 23 top-level driver source files from
  `modernc.org/sqlite v1.56.0`; the generated `lib` and `vtab` packages remain
  the pinned upstream module.
- The fork has two reviewed behavior deltas:
  1. `conn.go` adds `SQLITE_OPEN_NOFOLLOW` to every `sqlite3_open_v2` call.
  2. `sqlite.go` registers the private `cadrena-sqlite-nofollow` name, allowing
     consumers to import upstream `modernc.org/sqlite` without a duplicate
     global driver-registration panic.
- The store resolves an existing parent directory to its physical path,
  preserves the database basename, rejects an existing final symlink or
  non-regular file, and uses the canonical path consistently for locks,
  connectors, migrations, runtime validation, and integrity checks.
- SQLite remains authoritative for a final-component swap after validation;
  the canonical-parent boundary only avoids rejecting benign ancestor aliases
  such as macOS `/var -> /private/var`.

## Completed work

- [x] Captured a red regression against upstream's Unix `pUnused` cached-FD
  path, then added runtime writer/reader, migration writer/reader, and full
  integrity canary regressions. Each keeps a real target read transaction,
  closes sibling descriptors, swaps the source to a symlink at connect time,
  and verifies the target remains unchanged.
- [x] Added canonical-parent and final-symlink regression coverage, including
  alias/canonical lock sharing across all public store entrypoints.
- [x] Routed all production SQLite driver imports and error mapping through the
  internal fork. Direct test `database/sql` opens use the private driver name.
- [x] Added an external registration regression that imports both the policy
  SQLite store and upstream `modernc.org/sqlite`, asserting both distinct names
  are registered without an initialization panic.
- [x] Added upstream provenance, retained BSD-3-Clause license, a local
  source SHA-256 manifest, version-pin assertion, update procedure, Makefile
  target, and release-gate wiring.
- [x] Removed the temporary cached-FD probe directory.

## Verification record

- `make sqlitenofollow-manifest`
- `go test ./store/sqlite -count=1`
- `go test ./... -count=1`
- `go test -race ./... -count=1`
- `make batch-2a-focused`
- `make fmt-check lint vet boundary boundary-test`
- `go mod verify`, `go generate ./...`, `make vuln-check`, and `make gitleaks`
- Linux compile coverage with `GOOS=linux GOARCH=amd64 go test -exec /usr/bin/true ./...`

The final clean-tree `make batch-2a-final` is run after the implementation
commit so its generated-file assertion can evaluate the committed input.
