# Layer 4: Conditional Access and Admin Governance

Layer 4 is the admin override plane. It answers whether the organization currently allows the caller to operate, even when the developer-configured transport and RBAC layers would otherwise allow it.

## Two Enforcement Moments

### Layer 4a: Token-Time Governance

Microsoft Entra can block or shape token issuance before the request reaches the resource:

- deny token issuance
- require stronger conditions
- apply organization-wide policy to the caller identity

### Layer 4b: Data-Plane Governance

The platform also re-evaluates governance at request time through sidecar or app-layer checks:

- current agent risk
- current custom security attribute values
- current policy/tag match state
- current `agent_state` kill-switch behavior

This closes the gap between token issuance time and request time.

## What Is Shared Versus Scoped

Shared across environments:

- Conditional Access policy model
- custom security attribute schema such as `AgentIdentity.Department`
- tenant-wide admin and viewer groups for portal access

Scoped per environment:

- Agent Identity Blueprint for new scoped environments
- agent identities
- federated identity credentials
- env-scoped portal app registrations

That split keeps the governance model reusable while isolating the actual governed service principals per environment.

## Common Governance Controls In This Repo

- risk-based deny
- tag matching through Entra custom security attributes
- `agent_state` enabled or disabled
- sync from Microsoft Graph into the local policy and risk views

## Why Layer 4 Is Separate

Layers 1 to 3 express what the application owner intended. Layer 4 expresses what the enterprise currently allows. In regulated environments those are different authorities and both must exist.

## Related Reading

- [Admin Governance Layer](../admin-governance-layer.md)
- [Authentication Flows](../../reference/authentication-flows.md)
- [ADR-010: Conditional Access as admin governance](../../decisions/010-conditional-access-admin-governance.md)
