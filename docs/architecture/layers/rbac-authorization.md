# Layer 2: RBAC Authorization

Layer 2 answers a narrower question than mTLS: once a caller is allowed to connect, what is it allowed to do?

## Enforcement Inputs

The sidecar evaluates:

- caller SPIFFE ID
- HTTP method
- normalized request path
- optional JWT requirements declared on the matching rule

Rules are evaluated in order and the policy is default-deny.

## Policy Model

The protected resource keeps a YAML policy with entries such as:

```yaml
rules:
  - path: "/budget/read"
    methods: ["GET"]
    action: allow
    require_jwt: true
    required_roles: ["Budget.Read"]
```

Common patterns supported by the gateway:

- exact path matches
- prefix path matches
- method-specific rules
- explicit deny rules

The runtime also normalizes paths to avoid bypasses through encoded segments, dot segments, or duplicated slashes.

## Management Path

RBAC policy is managed through the protected sidecar's `/mgmt/policy` endpoint. External tools do not call that endpoint directly from the Internet. Instead:

1. The browser calls the portal backend.
2. The portal backend calls `admin-control-plane`.
3. `admin-control-plane` calls the protected service's `/mgmt/*` API with the management key.

That separation keeps the business agents governed while still leaving a recovery path available.

## Why Layer 2 Matters Separately

`budget-report` and `budget-approval` may both pass Layer 1 for `budget-backend`, but they do not get the same business permissions:

- `budget-report` can read
- `budget-approval` can read and submit

Transport identity alone cannot express that distinction.

## Failure Behavior

Layer 2 must fail closed:

- no rule match means deny
- invalid policy means do not silently broaden access
- management API failures must not fabricate success

## Related Reading

- [Management APIs](../../reference/management-apis.md)
- [Portal Runtime](../../developer/portal-runtime.md)
- [ADR-004: Transparent proxy, not SDK](../../decisions/004-transparent-proxy-not-sdk.md)
