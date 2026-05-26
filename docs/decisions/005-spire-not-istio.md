# ADR-005: SPIRE, Not Istio (But They Interoperate)

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

The AKS team uses Istio, which has its own SPIFFE implementation built into `istiod`. Question from stakeholders: "Why are you using SPIRE instead of Istio?"

## Decision

**Standalone SPIRE for the PoC.** Istio is a Kubernetes-native service mesh. Our agents run on Container Apps, which is a managed abstraction where Istio sidecar injection is not available. SPIRE works anywhere — VMs, Container Apps, Kubernetes, bare metal.

## The Three-Layer Distinction

1. **SPIFFE** — The open standard/specification. Defines the identity format (`spiffe://` URIs) and the Workload API.
2. **SPIRE** — The CNCF reference implementation of SPIFFE. Standalone server + agent architecture.
3. **Istio** — A service mesh with its own independent SPIFFE-compatible identity system. Does NOT use SPIRE internally. `istiod` issues SPIFFE-format certificates directly.

SPIRE and Istio are both SPIFFE implementations, like Chrome and Firefox are both web browsers. They speak the same identity language but have different architectures suited to different contexts.

## Rationale

- **Container Apps doesn't support Istio.** No sidecar injection, no control plane. Non-starter.
- **Cross-platform identity federation.** The Cycle 2-3 vision is an Entra Agent Identity Bridge that federates SPIRE and Istio trust domains. This requires SPIRE running independently, not embedded in Istio.
- **Multi-cloud portability.** SPIRE runs on GCP, AWS, on-prem. Istio is Kubernetes-only.
- **Complements, doesn't compete with AKS team.** AKS agents on Istio and Container Apps agents on SPIRE both speak SPIFFE. They can federate trust.

## The Browser Analogy (For AKS Team Conversations)

> "SPIRE and Istio are like Chrome and Firefox — both speak HTTP, both render web pages, but they're built for different contexts. Istio is Chrome: tightly integrated into the Kubernetes ecosystem, great if you're all-in on K8s. SPIRE is Firefox: runs anywhere, independent of any single platform. Our agents are on Container Apps where Chrome isn't available. But because they both speak HTTP — or in our case, SPIFFE — they interoperate."

## Consequences

- SPIRE Server runs on a separate Azure VM (not in-mesh)
- We manage SPIRE lifecycle ourselves (upgrades, HA, monitoring)
- Interop with Istio-based AKS workloads is architecturally possible but not yet proven in PoC

## Related

- ADR-002 (SPIFFE, Not Custom mTLS) — the standard selection
- ADR-007 (Container Apps, Not AKS) — why we're not on K8s
- Cycle 2-3 vision: Entra Agent Identity Bridge
