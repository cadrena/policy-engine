# Public Dependencies

## Cadrena DSL

The policy engine pins the public module `github.com/cadrena/dsl` at tag
`v1.1.1`. That tag resolves to commit
`3b243c002d9dbb425ff7ada085ce533de2abf16f` through normal public Go module
resolution without credentials.

The dependency direction is strictly one way:

```text
github.com/cadrena/dsl -> does not import the policy engine
github.com/cadrena/policy-engine -> imports tagged public DSL APIs
commercial products -> may import tagged public DSL and policy-engine APIs
```

The DSL owns parsing, validation, compilation, canonicalization, deterministic
Artifact encoding, and graph and guard evaluation semantics. The policy engine
uses the tagged Artifact API and public DSL value types; it does not duplicate
the Artifact codec or durable Program internals.

## Resolution rules

This module has no local `replace` directive, workspace dependency, nested Go
module, private module, or private registry dependency. Public source, tests,
examples, generated code, and releases must resolve using public module
infrastructure only. Commercial code may implement public extension ports, but
the dependency graph remains public and one way.

## SQLite no-follow driver fork

The durable SQLite store uses a bounded internal fork of the top-level
`modernc.org/sqlite` driver at the module pin recorded in `go.mod`. Its
`SQLITE_OPEN_NOFOLLOW` open flag protects the driver's cached-file-descriptor
path from a post-validation database symlink swap, and its private registered
driver name lets consumers import upstream `modernc.org/sqlite` without a
duplicate-registration panic. The generated SQLite runtime remains the
original pinned module. The full source provenance, update procedure, and
checksum manifest are in
[`internal/sqlitenofollow/UPSTREAM.md`](../internal/sqlitenofollow/UPSTREAM.md).
