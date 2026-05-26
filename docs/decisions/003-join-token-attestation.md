# ADR-003: Join Token Attestation (Not azure_msi)

**Status:** Accepted (workaround — production path requires upstream contribution)
**Date:** February 2026
**Deciders:** Project contributors

## Context

SPIRE agents must "attest" their identity to the SPIRE server — prove they are who they claim to be. Azure workloads typically use the `azure_msi` NodeAttestor, which verifies the workload's Managed Identity via Azure IMDS. We attempted this first. It failed.

## Decision

**Use `join_token` attestation.** SPIRE Server generates single-use tokens; deploy.sh passes them to Container Apps as environment variables. SPIRE Agents present tokens on first connect.

## The Problem with azure_msi

The `azure_msi` NodeAttestor plugin has a **server-side resolver** that queries the Azure ARM API to validate the agent's identity. The resolver calls:

```
GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}
```

It **only queries `Microsoft.Compute/virtualMachines` and `Microsoft.Compute/virtualMachineScaleSets`**. Container Apps are `Microsoft.App/containerApps` — a completely different resource provider. The resolver returns "resource not found" and attestation fails.

This is not a configuration issue. It's a code limitation in SPIRE's Azure plugin. The plugin was written for VMs and VMSS; Container Apps didn't exist when it was authored.

## The Workaround

Join tokens are SPIRE's simplest attestation method:
1. `deploy.sh` calls `spire-server token generate -spiffeID spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid>` on the SPIRE Server VM
2. Token is injected as `SPIRE_JOIN_TOKEN` env var into the Container App
3. SPIRE Agent presents the token on startup
4. SPIRE Server validates and issues the SVID

## Consequences

- **Tokens are single-use.** If a container restarts, the token is consumed and the agent can't re-attest. Container must be redeployed with a fresh token.
- **Not production-grade.** Acceptable for PoC; unacceptable for GA. Every container restart requires operator intervention.
- **deploy.sh handles orchestration.** Step 5 generates tokens, Step 6 deploys with tokens as env vars.

## Production Path

**Upstream SPIRE contribution.** Add `Microsoft.App/containerApps` (and ideally `Microsoft.App/managedEnvironments`) to the `azure_msi` resolver's resource type queries. Estimated effort: ~200-300 lines of Go in the SPIRE repository. This is bounded, well-understood work.

Alternatively: Azure Managed Identity attestation via a new attestor plugin that uses the Container Apps' managed identity token directly, bypassing the ARM resource type check.

## What We Tried First (Failure Log)

1. **azure_msi with Container Apps Managed Identity** — Resolver fails (wrong resource type)
2. **IMDS shim (Python)** — Injected a fake IMDS endpoint into the container. SPIRE agent called it, got a token, but the server-side resolver still failed because the ARM query returned not-found.
3. **Binary patching** — Attempted to modify the resolver's resource type query at the binary level. Too fragile; abandoned.
4. **ACI (Azure Container Instances)** — Explored moving agents to ACI for better IMDS support. ACI's networking limitations made it incompatible with the sidecar pattern.

Sessions 1-9 in the transcript catalog document this multi-day journey in detail.

## Related

- ADR-007 (Container Apps, Not AKS) — why we're on Container Apps despite this limitation
- `docs/runbooks/hard-won-learnings.md` — Learnings #1, #2, #3 cover the attestation journey
- `docs/runbooks/spire-operations.md` — Operational commands for token management
