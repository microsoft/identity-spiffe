# ADR-008: OPA/Gatekeeper as Complementary, Not Core Replacement

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

A Kubernetes-native review raised OPA/Gatekeeper as a policy enforcement option. It is a strong tool for cluster hardening. The question: should OPA replace the SPIRE + RBAC sidecar approach?

## Decision

**OPA is complementary cluster hardening. SPIRE + Dunloe is the core enforcement model for east-west agent-to-agent traffic.**

## Rationale

- **Different enforcement planes.** OPA/Gatekeeper enforces at the Kubernetes admission controller level — it decides what *can be deployed*. SPIRE + RBAC enforces at runtime — it decides what *can communicate*. Both are useful; neither replaces the other.
- **OPA doesn't provide cryptographic identity.** OPA can check labels, annotations, and resource specs. It can't verify that a specific caller is who they claim to be via X.509 certificates. SPIFFE provides identity; OPA provides policy on metadata.
- **Container Apps doesn't have Gatekeeper.** OPA/Gatekeeper is Kubernetes-native. Our agents run on Container Apps (ADR-007). Gatekeeper literally doesn't exist in this environment.
- **Dunloe is the strategic PDP.** Microsoft's investment in Entra Authorization (Dunloe) as a centralized policy decision point makes it the natural complement to SPIRE's identity layer. SPIRE authenticates; Dunloe authorizes. OPA is a third option that doesn't integrate with Entra's directory model.

## Where OPA Fits

- **AKS cluster hardening.** Enforce that only approved container images can deploy. Require SPIRE sidecar presence via admission webhook.
- **Pre-deployment policy.** Validate Bicep/ARM templates against security baselines.
- **Audit and compliance.** Query cluster state for policy violations.

## Where OPA Doesn't Fit

- **Runtime east-west authorization.** Can't intercept or authorize agent-to-agent HTTP calls.
- **Cryptographic identity verification.** Doesn't speak SPIFFE.
- **Container Apps enforcement.** No Kubernetes admission controller available.

## Related

- ADR-001 (Sidecar, Not Gateway) — the runtime enforcement model
- Dunloe integration (future work) — the strategic PDP direction
- `What_is_Microsoft_Entra_Authorization_Dunloe.pdf` — Dunloe product documentation
