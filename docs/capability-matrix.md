# Cadrena V1 Capability Matrix

This document is the normative V1 ownership contract for the Cadrena repository
family. When another current product or strategy document differs from this
matrix, this matrix controls.

| Capability | Community OSS | Commercial pilot |
| --- | --- | --- |
| DSL compile and deterministic evaluation | Included | Uses tagged OSS |
| Memory and SQLite local policy state | Included | Uses tagged OSS |
| MCP discovery and invocation enforcement | Included | Uses tagged OSS |
| Approval and delegation verifier ports | Included | Implements ports |
| Local durable invocation safety journal | Included | Mirrors into durable timeline |
| Approval issuance, inbox, consume, revocation | Not included | Included |
| Delegation issuance, registry, lineage | Not included | Included |
| Organizational durable audit and search | Not included | Included |
| Central policy activation and environment coordination | Not included | Included |
| Managed isolated operations | Not included | Included |

Community OSS is independently usable and fail-closed. It does not require a
Cadrena account, commercial credentials, private services, phone-home behavior,
or licensing checks in the authorization path. Privacy-safe OpenTelemetry
export remains part of Community OSS; it is not an organizationally durable
audit service.

The commercial column describes the isolated V1 pilot composition. Public
self-service cloud tiers, shared multi-tenant SaaS, billing, and the capabilities
explicitly deferred by the approved V1 design are not V1 commitments.
