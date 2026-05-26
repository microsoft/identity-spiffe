# Layer 1: Transport mTLS

Layer 1 is the first gate in the system. It decides whether a caller may establish a connection to the target sidecar at all.

## Where It Runs

- Caller app sends plain HTTP to its local egress proxy
- Egress proxy opens an mTLS connection to the target ingress proxy
- Target ingress proxy validates the caller SPIFFE ID from the peer certificate
- If the caller is not allowed, the TLS handshake is rejected before RBAC or JWT checks happen

## Identity Source

The mTLS identity comes from SPIRE-issued X.509 SVIDs derived from Microsoft Entra Agent Identity:

```text
spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>
```

That mapping lets the platform carry Entra identity into transport-layer mutual TLS without changing the business app code.

## Policy Surface

The Layer 1 allow list is maintained by the sidecar management API and surfaced in the portal mTLS tab.

Typical decisions:

- `budget-report` is allowed to connect to `budget-backend`
- `budget-approval` is allowed to connect to `budget-backend`
- `employee-menus` is not allowed to connect to `budget-backend`

When a caller is absent from the allow list, the request fails during the handshake. The protected app never sees the request.

## What This Protects

Layer 1 provides three important properties:

1. It blocks unauthorized east-west traffic even if an RBAC rule is misconfigured later.
2. It prevents non-members from reaching the policy engine or application code.
3. It makes caller identity cryptographic instead of header-based.

## Operational Notes

- Certificates rotate through SPIRE, not through the app containers.
- Join-token attestation means a new agent revision needs fresh bootstrap unless the token path is repaired.
- `./deploy.sh --portal-only` is safe because it skips agent sidecars entirely.

## Related Reading

- [System Overview](../system-overview.md)
- [Enforcement Flow](../enforcement-flow.md)
- [ADR-001: Sidecar, not gateway](../../decisions/001-sidecar-not-gateway.md)
- [ADR-002: SPIFFE/SPIRE, not custom mTLS](../../decisions/002-spiffe-not-custom-mtls.md)
