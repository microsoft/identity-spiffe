# Architecture Decision Records

> Every significant design decision, with context and rationale. Read these to understand *why* things are the way they are.

| # | Decision | Status | Summary |
|---|----------|--------|---------|
| [001](001-sidecar-not-gateway.md) | Sidecar, not central gateway | Accepted | Enforcement at the agent, not a chokepoint. Complements APIM. |
| [002](002-spiffe-not-custom-mtls.md) | SPIFFE/SPIRE, not custom mTLS | Accepted | Open standard, auto-rotating certs, multi-cloud portable. |
| [003](003-join-token-attestation.md) | Join token attestation | Accepted (workaround) | azure_msi incompatible with Container Apps. Production needs upstream fix. |
| [004](004-transparent-proxy-not-sdk.md) | Transparent proxy, not SDK | Accepted | Zero code changes to agents. Works with any language. |
| [005](005-spire-not-istio.md) | SPIRE, not Istio | Accepted | Container Apps can't run Istio. Both speak SPIFFE — they interoperate. |
| [006](006-budget-backend-scenario.md) | Budget Backend scenario | Accepted | Business-relevant naming for the authorization demo. |
| [007](007-container-apps-not-aks.md) | Container Apps, not AKS | Accepted | Matches actual agent hosting. Proves the hard case (no K8s, no IMDS). |
| [008](008-opa-complementary-not-replacement.md) | OPA complementary, not core | Accepted | OPA is cluster hardening. SPIRE + Dunloe is runtime east-west. |
| [009](009-remove-foundry.md) | Remove Azure AI Foundry | Accepted | Zero enforcement value. All security layers work through SPIFFE + Entra. -597 lines. |
| [010](010-conditional-access-admin-governance.md) | Conditional Access as admin governance | Accepted | Fourth enforcement layer. Admin-defined policy via CA supersedes developer-defined RBAC. Regulatory non-negotiable. |

## How to Add a New ADR

1. Create `docs/decisions/NNN-short-descriptive-name.md`
2. Use the template: Status, Date, Deciders, Context, Decision, Rationale, Consequences, Alternatives Considered, Related
3. Add to this index
4. Reference from CLAUDE.md root if it affects always-on context
