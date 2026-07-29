# Policy Engine

Open-source authorization core for AI agents and tool actions.

## Scope

- Relationship-based authorization
- Agent, principal, task, tool, action, and resource model
- Deterministic policy compilation and evaluation
- A small declarative YAML/JSON policy DSL with typed conditions
- `check`, `batch check`, `filter`, and `explain` APIs
- Task-bound delegation and scope attenuation primitives
- Embedded-library and standalone-server modes
- In-memory, SQLite, and PostgreSQL storage adapters

## Policy DSL

The user-facing policy language is maintained as the standalone [`conductera/dsl`](../dsl/) Go module. V1 is intentionally declarative and limited; it does not execute embedded CEL, Rego, JavaScript, or other user code.

## Non-goals

This repository does not contain the commercial dashboard, organization management, SSO, gateway fleet management, approval orchestration, or enterprise audit and governance.

## Distribution

The engine will be available as source code, a Go library, a standalone binary, and a public container image.

## License

Planned: Apache License 2.0.

## Status

Product definition and technical design phase. No runtime implementation yet.
