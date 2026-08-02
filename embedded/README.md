# Embedded composition

Package `embedded` composes the transport-neutral policy engine without
creating an import cycle in the root contract package.

Construction requires `WithStore` and `WithCallerAuthorizer`. Approval and
delegation verifiers default to the public reject implementations, and the
decision-event sink defaults to the privacy-safe best-effort no-op.

```go
engine, err := embedded.New(
    embedded.WithStore(storage),
    embedded.WithCallerAuthorizer(authorizer),
)
```

The root `policyengine` package remains the frozen interface and value contract;
it deliberately does not import storage or application-service packages.
