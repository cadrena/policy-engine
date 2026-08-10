# `modernc.org/sqlite` no-follow fork

This directory is a deliberately small, source-level fork of the top-level
`modernc.org/sqlite` driver package. It makes every driver connection request
SQLite's `SQLITE_OPEN_NOFOLLOW` pathname protection and registers under a
private driver name so library consumers can import upstream unchanged.

## Upstream provenance

- Module: `modernc.org/sqlite`
- Pinned source release: `v1.56.0`
- License: BSD 3-Clause; the upstream license is retained verbatim in
  [`LICENSE`](LICENSE).
- The generated SQLite runtime (`modernc.org/sqlite/lib`) and extension helper
  package (`modernc.org/sqlite/vtab`) are **not** copied. The fork imports them
  from the same pinned upstream module.

The copied top-level source files are:

```text
backup.go
conn.go
connector.go
convert.go
dbstatus.go
dmesg.go
driver.go
error.go
fcntl.go
mutex.go
nodmesg.go
norlimit.go
pagecache.go
pagecache_trampolines.go
pre_update_hook.go
result.go
rlimit.go
rows.go
rulimit.go
sqlite.go
stmt.go
tx.go
vtab.go
```

`version.go` and `version_test.go` are local provenance metadata and are not
upstream copies. [`FORK_MANIFEST.sha256`](FORK_MANIFEST.sha256) pins the exact
contents of the copied source files plus the retained license, including the
intentional delta described below.

The copied source is excluded from the repository's project-style lint rules.
Its preserved FFI implementation also produces upstream `go vet` `unsafeptr`
diagnostics, so the repository vet target runs every other standard analyzer on
this package and retains the normal analyzer set for all project packages.

## Intentional behavior deltas

The reviewed behavior changes from the listed upstream files are:

1. In [`conn.go`](conn.go), `newConn` adds `sqlite3.SQLITE_OPEN_NOFOLLOW` to
   the existing `sqlite3_open_v2` flags.
2. In [`sqlite.go`](sqlite.go), `DriverName` is
   `cadrena-sqlite-nofollow` instead of upstream's process-global `sqlite`.
   This prevents a duplicate `sql.Register("sqlite")` panic when a
   policy-engine consumer also imports `modernc.org/sqlite`. Production opens
   use `NewConnector`, not the registered name. The related registration-name
   documentation in `connector.go` and `driver.go` is updated accordingly.

SQLite's Unix VFS can otherwise reuse a cached target descriptor after a
follow-link `stat` in its `pUnused` fast path, before the final-component
`open(2)` would enforce `O_NOFOLLOW`. SQLite's own pathname-resolution check
for `SQLITE_OPEN_NOFOLLOW` closes that gap. The policy store separately
canonicalizes an existing parent directory while preserving the final basename:
that keeps ordinary ancestor aliases (such as macOS `/var`) usable, while the
driver remains authoritative for a final-component swap that occurs after
validation. Do not weaken this flag to a final-component-only check.

## Updating this fork

1. Update the `modernc.org/sqlite` module pin in the repository `go.mod` and
   `go.sum`.
2. Copy the 23 files listed above and `LICENSE` from that exact module release,
   preserving upstream headers. Do not copy or patch `lib` or `vtab`.
3. Reapply exactly the `SQLITE_OPEN_NOFOLLOW` flag in `conn.go` and the unique
   `DriverName` in `sqlite.go`; update the corresponding registration-name
   documentation in `connector.go` and `driver.go`. Inspect the resulting diff
   to confirm no other behavioral change was introduced.
4. Update `UpstreamModuleVersion` in `version.go`, this document's version,
   and `FORK_MANIFEST.sha256`.
5. Run `make sqlitenofollow-manifest`, `go test ./internal/sqlitenofollow`,
   the fork/upstream driver-registration regression, and the SQLite symlink
   regressions before the normal repository gates.
