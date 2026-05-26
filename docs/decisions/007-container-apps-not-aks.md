# ADR-007: Container Apps, Not AKS

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

Azure AI Foundry hosted agents run on Container Apps, not AKS. The PoC needed to match the production deployment model.

## Decision

**Deploy on Azure Container Apps** to match the actual Foundry agent hosting environment. This proves the SPIFFE sidecar pattern works where Foundry agents actually run — not just in a Kubernetes-ideal environment.

## Rationale

- **Fidelity to production.** If the PoC runs on AKS but agents run on Container Apps, we haven't proven anything useful. The point is demonstrating security in the actual deployment environment.
- **Container Apps is where the gap exists.** AKS has Istio, network policies, and pod-to-pod mTLS options. Container Apps has none of these. The security gap we're closing is specifically the Container Apps gap.
- **Harder PoC = more credible.** Proving SPIFFE sidecars work on Container Apps (where nothing is built-in) is more compelling than proving they work on K8s (where service mesh is a checkbox).

## Consequences

- Multi-container sidecar support in Container Apps has undocumented behaviors (see `docs/runbooks/container-apps-quirks.md`)
- No Istio, no network policies, no pod security contexts
- SPIRE `azure_msi` attestation doesn't work (see ADR-003)
- Internal TCP routing between containers uses `app-name` hostnames to avoid TLS termination
- Container restarts don't preserve join tokens

## Related

- ADR-003 (Join Token Attestation) — the attestation workaround this decision forced
- ADR-005 (SPIRE, Not Istio) — why standalone SPIRE is required here
- `docs/runbooks/container-apps-quirks.md` — detailed platform-specific gotchas
