# System Overview

This document describes the current runtime architecture after the portal modularization and parallel-deployment Entra scoping work.

## Topology

```text
                            Azure Container Apps Environment

  Browser
    -> aim-portal ------------------------\
    -> crowdstrike-mock                    \
                                           -> admin-control-plane -> budget-backend /mgmt/*

  budget-report app -> egress sidecar ----\
  budget-approval app -> egress sidecar ---+-> mTLS tunnel -> budget-backend ingress sidecar -> budget-backend app
  employee-menus app -> egress sidecar ---/

  Direct A2A path:
    caller app -> target app /a2a/status

  Azure VM:
    SPIRE server -> issues X.509 SVIDs to workload identities
```

## Major Components

| Component | Responsibility |
|---|---|
| Agent app | business logic or direct A2A behavior |
| `spiffe-proxy` egress | outbound mTLS client path |
| `spiffe-proxy` ingress | Layer 1 to Layer 4 enforcement for protected resources |
| SPIRE agent | obtains and rotates SVIDs for the workload |
| SPIRE server VM | trust domain authority and workload attestation |
| `admin-control-plane` | public management proxy for protected `/mgmt/*` APIs |
| `aim-portal` | operator UX for execute, policy, health, and governance |
| `crowdstrike-mock` | mock SOC signal source for risk changes |

## The Four Enforcement Layers

| Layer | Enforcement point | Decision |
|---|---|---|
| Layer 1 | mTLS allow list in ingress sidecar | may this caller connect at all |
| Layer 2 | RBAC policy in ingress sidecar | may this caller use this method and path |
| Layer 3 | JWT validation in sidecar or target app | does this caller hold a valid Entra token for the resource |
| Layer 4 | Conditional Access, risk, tags, and kill-switch logic | is the caller currently allowed by admin governance |

## Request Paths

### Governed SPIFFE Path

1. Caller app sends plain HTTP to its local egress proxy.
2. Egress proxy opens an mTLS connection to the target ingress proxy.
3. Ingress proxy extracts caller SPIFFE identity from the certificate.
4. Layer 1 checks the allow list.
5. Layer 2 checks RBAC policy.
6. Layer 3 validates the JWT requirements for the resource.
7. Layer 4 checks governance state such as risk and `agent_state`.
8. If all layers pass, the request is forwarded to the target app.

### Direct A2A Path

1. Caller app acquires an Entra token for the target app.
2. Caller app calls the target app over HTTPS.
3. Target app validates the token and evaluates app-layer governance checks.

This path does not use the SPIFFE tunnel, but it still participates in JWT and admin-governance enforcement.

## Management Path

External management traffic should follow this path:

1. Browser calls the portal backend.
2. Portal backend calls `admin-control-plane`.
3. `admin-control-plane` proxies to the protected service's `/mgmt/*` endpoints using `X-AIM-Admin-Key`.

That keeps business services governed while preserving a recovery and operator path.

## Identity Model

Workload transport identity is derived from Microsoft Entra Agent Identity and expressed as SPIFFE IDs:

```text
spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>
```

New environments scope the Blueprint, Agent Identities, FICs, and portal app registrations by `AZURE_ENV_NAME`. Shared portal groups and shared CA schema stay tenant-wide.
