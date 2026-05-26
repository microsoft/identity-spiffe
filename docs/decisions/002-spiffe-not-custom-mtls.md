# ADR-002: SPIFFE/SPIRE, Not Custom mTLS

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

Agent-to-agent mTLS requires a certificate authority and identity model. We could roll our own PKI, use Azure-native certificate solutions, or adopt an open standard.

## Decision

**SPIFFE as identity standard, SPIRE as implementation.** All agents receive X.509 SVIDs (SPIFFE Verifiable Identity Documents) from SPIRE. Identity is expressed as SPIFFE IDs: `spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>`.

## Rationale

- **CNCF graduated open standard.** Not proprietary. Customers and partners can verify the trust model independently.
- **Auto-rotates certificates.** 1-hour TTL with automatic renewal via the SPIRE Workload API. No manual cert management, no expiry incidents.
- **Multi-cloud portable.** SPIFFE IDs are not Azure-specific. The same identity model works on GCP, AWS, on-prem. This is the core of the cross-cloud governance story.
- **Maps to the Agent Identity model in Identity Research for Agent Management Using SPIFFE.** Agent Blueprint → SPIFFE trust domain, Agent Identity → SPIFFE workload registration, Agent User → delegated identity chain.
- **Strategic positioning vs. Google.** Apigee is proprietary. SPIFFE gives Microsoft an open-standards differentiation narrative. See `docs/decisions/005-spire-not-istio.md` for the Istio interop story.
- **Aligned with workload identity guidance.** The "Workloads, Agents, and At-Scale Federation" direction explicitly recommends SPIFFE as a strategic foundation.

## Consequences

- Requires a SPIRE Server (we run it on an Azure VM)
- Requires SPIRE Agents as sidecars alongside the proxy
- The `azure_msi` NodeAttestor doesn't work with Container Apps (see ADR-003)
- Certificate material lives in the SPIRE Workload API Unix domain socket, not in files

## Alternatives Considered

| Alternative | Why Not |
|---|---|
| Custom PKI with Azure Key Vault | No standard identity model; manual rotation; Azure-only |
| Flexible FIC (Microsoft internal) | Proprietary; no cross-cloud story; would require standardization effort that duplicates SPIFFE |
| No mTLS (network ACLs only) | No cryptographic identity; no application-layer enforcement; doesn't prove the thesis |
| HashiCorp Vault PKI | Not a workload identity standard; just a cert issuer; doesn't define the identity model |

## Related

- ADR-003 (Join Token Attestation) — the attestation workaround for Container Apps
- ADR-005 (SPIRE, Not Istio) — why standalone SPIRE vs. Istio's built-in SPIFFE
- "Workloads, Agents, and At-Scale Federation" paper — the strategic recommendation this implements
