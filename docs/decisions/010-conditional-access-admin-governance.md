# ADR-010: Conditional Access as the Admin Governance Layer

**Status:** Proposed
**Date:** March 2026
**Deciders:** Project contributors

## Context

The current enforcement architecture (ADR-001 through ADR-009) provides three layers of security — mTLS (transport), RBAC (application), and OAuth2/JWT (token) — all defined by the **agent developer**. The tenant administrator has no control surface. An enterprise IT admin cannot block a specific agent, require MFA step-up for sensitive resources, enforce location restrictions, or suspend all agent activity during an incident.

Regulated enterprises will not adopt an agent identity platform where the software developer — not the organizational administrator — controls what agents can access. Every major regulatory framework requires admin-controlled access policy over automated systems.

## Decision

**Add Conditional Access (CA) as a fourth enforcement layer — the admin governance layer.** CA is enforced at **two points**: at token issuance (Entra STS) and at the data plane (sidecar proxy ingress).

```
Layer 1: Transport    (mTLS)    — Developer-defined — Who can connect
Layer 2: Application  (RBAC)    — Developer-defined — What they can do
Layer 3: Token        (OAuth2)  — Developer-defined — Entra identity proof
Layer 4a: Governance  (CA-STS)  — Admin-defined     — Policy at token issuance
Layer 4b: Governance  (CA-Data) — Admin-defined     — Policy at every request
```

CA does not replace layers 1-3. Developer policies define capabilities. Admin policies define organizational constraints. Both are enforced independently.

## Rationale

### 1. Regulatory compliance is non-negotiable

Every major framework requires that organizational administrators — not software vendors — control access to sensitive systems:

- **SEC Rule 15c3-5** requires broker-dealers to maintain "direct and exclusive control" over all automated market access, with annual CEO certification. AI agents placing orders are explicitly in scope.
- **FINRA Rule 3110 + Notice 24-09** requires supervisory systems over AI tools. The 2026 Oversight Report states agents that "select intermediate actions that are not expressly authorized" must be "subject to the same controls applicable to any associated person."
- **HIPAA §164.312(a)(1)** requires access controls restricting ePHI to "authorized persons and software programs." The covered entity's administrator — not the developer — determines authorization.
- **EU AI Act Articles 14, 26** make enterprise IT admins "deployers" with direct legal obligations for oversight, log retention, and the ability to "override or reverse" AI system output. Not delegable to the developer.
- **OMB M-22-09 (Federal Zero Trust Strategy)** requires identity management for "person and non-person entities." EO 14144 (January 2025) explicitly makes NHI governance a federal cybersecurity priority.
- **SOC 2 Type II CC6.1** requires organizations to restrict logical access via access control mechanisms. SOX Section 404 requires management assessment of internal controls — agents without admin-governed access create a material control weakness.

**Enforcement actions — this is actively enforced:**

| Organization | Year | Regulation | Penalty | What Happened |
|---|---|---|---|---|
| Knight Capital | 2013 | SEC 15c3-5 | $12M fine + $460M loss | Flawed automated code sent 4M unintended orders in 45 minutes |
| Citigroup | 2024 | FCA MAR 7A.3 | GBP 61.6M | Trader error fed $444B to algorithm; $1.4B executed in minutes |
| Capital One | 2020 | OCC 12 CFR 30 | $80M fine | 106M records exposed — "failed to establish effective risk assessment" for automated cloud controls |
| Clearview AI | 2022 | GDPR | EUR 20M | Automated system processed biometric data without governance |
| Uber | 2017 | FTC Act | 20-year consent decree | Shared admin keys, no MFA, 25.6M records exposed |

Every case involved a failure to maintain organizational control over automated systems.

### 2. Developer-defined policies answer the wrong question for admins

Developer policies answer: **"What can this agent do?"** Admin policies answer: **"What is this agent allowed to do in *my* organization?"** A developer cannot know which resources are classified as sensitive, which compliance frameworks apply, or when a security incident requires all agent activity to be suspended. Only the tenant administrator has this context.

### 3. Customers already know CA

Every Entra ID P1/P2 customer already uses Conditional Access. Security teams have existing workflows, audit integrations, and operational playbooks. A separate policy system for agents would fragment the admin experience, require new training, and lose the benefit of CA's existing What If tool, sign-in log integration, and policy templates.

### 4. Token-time CA alone is insufficient — dual enforcement required

Access tokens have a default lifetime of 60 minutes. Three gaps remain after issuance: (1) **Token lifetime gap** — admin policy changes don't take effect until token expiry, (2) **Policy change lag** — new risk signals or location restrictions are invisible to already-issued tokens, (3) **Resource-level granularity** — token-time CA cannot distinguish `/budget/read` from `/budget/approve`. Data-plane CA (Layer 4b) closes all three by re-evaluating CA constraints on every request.

## What Already Exists (Production Today)

Agent identity as CA subject is **already deployed to 1,000+ customers.** This is not a proposal:

- Agent identities and agent users are first-class CA subjects ([docs](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id))
- Admins can scope policies by agent OID, blueprint, or custom security attributes
- Tokens carry CA claims (`acrs`, `capolids`) reflecting evaluation results
- Sign-in logs capture agent token requests with CA evaluation results
- The [CA optimization agent](https://learn.microsoft.com/en-us/entra/security-copilot/conditional-access-agent-optimization) already scans for agent coverage gaps — 73% of customers using it have improved their Zero Trust posture
- The [What If tool](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) already supports agent identity simulation

## Implementation Path

**Phase 1 (in production):** Token-time CA evaluation on agent tokens. Engineering cost: minimal — ensure agent platform identities register as Entra Agent ID constructs.

**Phase 2 (Q1 FY27):** Data-plane CA enforcement in sidecar. CA evaluation client in ingress pipeline, claims inspection (`acrs`/`capolids`), real-time CA endpoint calls, claims challenge flow. Engineering cost: moderate.

**Phase 3 (Q2 FY27):** Unified policy visibility, What If integration, bidirectional policy awareness. Sign-in logs show both token-time and data-plane CA results.

See `docs/architecture/admin-governance-layer.md` for technical details — diagrams, YAML schema, enforcement matrix, integration design.

## Consequences

- **Positive:** Regulated enterprises can adopt the platform — compliance officers verify admin control
- **Positive:** Unified audit trail — agent activity in the same sign-in logs as users
- **Positive:** Dual enforcement closes the token-lifetime gap — policy changes take effect immediately at the data plane
- **Negative:** CA evaluation adds latency (~10-50ms token-time, ~5-20ms data-plane with caching)
- **Negative:** Two policy systems (developer RBAC + admin CA) require clear documentation about precedence
- **Negative:** Data-plane CA introduces a dependency on the CA evaluation endpoint — fail-closed by default

## Alternatives Considered

| Alternative | Why Not |
|---|---|
| Admin YAML policies in the sidecar | Fragments admin experience. Admins manage policies in Entra portal, not YAML. No audit or What If integration. |
| OPA as the admin policy engine | Cluster-level (ADR-008). No tenant-admin identity, no Entra sign-in logs, no existing customer base. |
| Registry-only governance (quarantine) | Binary block/allow. CA provides conditional enforcement — MFA, location, time-of-day. |
| No admin governance | Non-starter for regulated industries. See enforcement actions above. |

## Related

- ADR-001: Sidecar, not gateway (CA complements the sidecar model)
- ADR-008: OPA complementary (CA fills the admin governance gap OPA cannot)
- ADR-009: Remove Foundry (CA anchors to Entra identity, consistent with Foundry removal)
- `docs/architecture/admin-governance-layer.md` — Technical architecture and integration design
