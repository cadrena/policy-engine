# Public Dependencies

## Conductera DSL

The policy engine pins the public module `github.com/cadrena/dsl` at tag
`v1.0.0`. That tag resolves to commit
`54080d9aa503812645058d507631a9c04fb7ab2e` through normal public Go module
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
