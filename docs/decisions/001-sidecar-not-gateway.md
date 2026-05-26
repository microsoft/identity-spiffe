# ADR-001: Sidecar Proxy, Not Central Gateway

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

We needed to enforce caller-level authorization between agents in Azure AI Foundry. Two patterns were available: a central API gateway (APIM-style) or per-agent sidecar proxies.

## Decision

**Sidecar proxy pattern.** Each agent gets its own Go proxy sidecar that handles mTLS and RBAC enforcement. The agent sends plain HTTP to `localhost:8080`; the proxy handles all cryptographic complexity.

## Rationale

- **Enforcement at the agent, not a central chokepoint.** East-west traffic between agents never transits a shared gateway. Each agent pair enforces identity directly.
- **Scales with agents.** No single point of failure. Adding a new agent means adding a new sidecar — no gateway config changes.
- **Zero code changes to agent apps.** Python agents don't know SPIFFE exists. They talk HTTP to localhost. This matters for Foundry adoption — you can't ask every agent developer to integrate an SDK.
- **Same pattern as Envoy / Istio service mesh.** Industry-proven. Not inventing a new architecture.
- **Complements APIM, doesn't compete.** APIM handles north-south (ingress from users/external). Sidecars handle east-west (agent-to-agent). Different planes, complementary roles.

## Consequences

- Each agent deployment includes a sidecar container (adds ~20MB memory overhead)
- RBAC policy is distributed per-sidecar (managed via management API on port 9443)
- The Identity Research for Agent Management Using SPIFFE Control Panel needed to proxy management API calls through a trusted agent (BudgetApproval) since BudgetBackend is internal-only
- Debugging requires checking sidecar logs alongside agent logs

## Alternatives Considered

| Alternative | Why Not |
|---|---|
| Central APIM gateway for east-west | Creates a chokepoint; agents inside a project bypass APIM today; single point of failure |
| Agent-embedded SDK | Requires code changes in every agent; language-specific; fragments enforcement |
| Network-level ACLs only | No application-layer granularity (can't distinguish GET /read from POST /submit) |

## Related

- ADR-004 (Transparent Proxy, Not SDK) — elaborates on the "zero code changes" principle
- ADR-008 (OPA Complementary) — why cluster-level policy doesn't replace sidecar enforcement
