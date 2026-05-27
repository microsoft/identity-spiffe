# Identity Research for Agent Management Using SPIFFE Documentation

Identity Research for Agent Management Using SPIFFE demonstrates sidecar-enforced authorization for agent-to-agent traffic on Azure Container Apps using Microsoft Entra Agent Identity, SPIFFE/SPIRE, Conditional Access-style governance, and live admin policy.

## What This Repo Proves

The platform combines five independent enforcement checks:

| Layer | Enforcement point | What it answers |
|---|---|---|
| Layer 1 | SPIFFE/SPIRE mTLS in the sidecar | Which callers may establish a connection |
| Layer 2 | RBAC policy in the sidecar ingress pipeline | Which methods and paths the connected caller may use |
| Layer 3 | Entra OAuth2/JWT validation in the sidecar or app | Whether the caller holds a valid token for the target resource |
| Layer 4a | Conditional Access-style risk evaluation | Whether the organization currently allows the caller to operate |
| Layer 4b | Admin tag governance backed by Graph | Whether live caller attributes still satisfy policy |

Those checks are intentionally independent. A caller that clears RBAC can still fail token validation. A caller with a valid token can still be blocked by Conditional Access-style risk. A caller blocked by mTLS never reaches the later layers.

## Core Runtime Components

| Component | Purpose |
|---|---|
| Agent apps | Business workloads and direct A2A targets |
| `spiffe-proxy` sidecar | mTLS, RBAC, JWT enforcement, management API |
| SPIRE server VM | Issues and rotates X.509 SVIDs for workload identity |
| `admin-control-plane` | Dedicated external management service for `/mgmt/*` access |
| `isp-portal` | Management portal for execute, policy, scan, health, and CA operations |
| `securityportal-mock` | Mock SOC portal that pushes risk signals into Identity Research for Agent Management Using SPIFFE |

## Documentation Map

- [Quickstart](getting-started/quickstart.md): install prerequisites, deploy, verify, and choose the right deploy mode.
- [System Overview](architecture/system-overview.md): current runtime topology and how requests move through the system.
- [Enforcement Flow](architecture/enforcement-flow.md): request-by-request examples of allow and deny paths.
- [Transport mTLS](architecture/layers/transport-mtls.md): Layer 1 design, allow lists, and failure modes.
- [RBAC Authorization](architecture/layers/rbac-authorization.md): Layer 2 policy model and management behavior.
- [OAuth2 and JWT](architecture/layers/oauth-jwt.md): Layer 3 token validation and Entra identity proof.
- [Conditional Access Governance](architecture/layers/conditional-access.md): Layer 4 admin controls, risk, and custom attributes.
- [Management APIs](reference/management-apis.md): portal, admin-control-plane, and backend management endpoints.
- [Authentication Flows](reference/authentication-flows.md): browser auth, management auth, agent auth, and Graph/OData usage.
- [Portal Runtime](developer/portal-runtime.md): the modular `portal/app` package, storage, health, and request flow.
- [Parallel Deployments](developer/parallel-deployments.md): safe multi-environment Entra scoping and what stays shared.
- [Docs Site](developer/docs-site.md): local doc build and GitHub Pages publishing behavior.

## Start Here

For most developers:

1. Read [Quickstart](getting-started/quickstart.md).
2. Read [System Overview](architecture/system-overview.md).
3. Keep [Management APIs](reference/management-apis.md) and [Authentication Flows](reference/authentication-flows.md) open while changing portal, admin-control-plane, or sidecar behavior.

For portal work:

1. Read [Portal Runtime](developer/portal-runtime.md).
2. Use `./deploy.sh --portal-only` when the change does not affect agent sidecars or attestation.

For identity/bootstrap work:

1. Read [Parallel Deployments](developer/parallel-deployments.md).
2. Verify whether the current environment is `legacy` or `scoped` before touching Entra provisioning.
