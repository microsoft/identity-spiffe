# Admin Governance Layer: Conditional Access for Agent Identities

> Developer-defined policies control what an agent *can* do. Admin-defined policies control what an agent *is allowed* to do in a specific organization. Both are required. See [ADR-010](../decisions/010-conditional-access-admin-governance.md) for the decision rationale and regulatory basis.

## What Is Conditional Access?

[Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) (CA) is Entra ID's policy engine for controlling access to resources. Admins create if/then rules in the Entra portal: *if* an identity matches certain conditions (location, risk level, device state), *then* enforce controls (block, require MFA, limit session). Every Entra ID P1/P2 tenant already uses CA for users — this extends the same mechanism to agent identities.

Key concepts referenced in this doc:

| Concept | What It Means |
|---|---|
| **Authentication context** | A label (C1–C99) that admins attach to CA policies. Apps and sidecars can require a specific context for sensitive operations (e.g., "C1 = MFA completed"). |
| **Claims challenge** | When a token lacks required claims, the resource returns a 403 with a challenge. MSAL uses this to re-acquire a token that satisfies the missing requirement (e.g., trigger MFA). |
| **`acrs` claim** | JWT claim listing which authentication contexts were satisfied at token issuance. |
| **`capolids` claim** | JWT claim listing which CA policy IDs were evaluated and satisfied. Used for audit and [What If analysis](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool). |
| **What If tool** | Entra portal tool that simulates CA policy evaluation — "what would happen if this agent requests this resource?" — without actually issuing a token. |

## Four-Layer Enforcement Model

```
  User interacts with Agent
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │  Layer 4a: Conditional Access — Token Time            │
  │  (Admin Governance · Entra STS)                       │
  │                                                       │
  │  Evaluated at Entra STS during token issuance         │
  │  (Agent identity as CA subject: in production today) │
  │                                                       │
  │  Inputs:                                              │
  │    • Agent identity / agent user (subject)            │
  │    • Target resource (audience)                       │
  │    • User context (delegated flows)                   │
  │    • Agent risk level (high/medium/low via IDP)       │
  │    • Location, device state, session controls         │
  │                                                       │
  │  Outputs:                                             │
  │    • Token issued (with CA claims: acrs, capolids)    │
  │    • Token denied (admin policy blocks agent)         │
  │    • Step-up required (MFA challenge returned)        │
  └──────────────────────────┬───────────────────────────┘
                             │
                       Token issued
                             │
                             ▼
  ┌──────────────────────────────────────────────────────┐
  │  Layer 4b: Conditional Access — Data Plane            │
  │  (Admin Governance · Sidecar Ingress)                 │
  │                                                       │
  │  Evaluated on EVERY request at the sidecar proxy      │
  │                                                       │
  │  Checks:                                              │
  │    • CA claims in token (acrs: auth context IDs,      │
  │    •   capolids: satisfied CA policy IDs)             │
  │    • Real-time CA evaluation endpoint call             │
  │    • Auth context requirements per resource path      │
  │                                                       │
  │  Outputs:                                             │
  │    • Request allowed (CA constraints satisfied)       │
  │    • Request denied (403 + insufficient_claims)       │
  │    • Step-up required (claims challenge returned)     │
  │                                                       │
  │  Catches:                                             │
  │    • Policy changes after token issuance              │
  │    • Risk level changes mid-session                   │
  │    • Cross-resource access beyond token audience      │
  └──────────────────────────┬───────────────────────────┘
                             │
                       Request allowed
                             │
                             ▼
  ┌──────────────────────────────────────────────────────┐
  │  Layer 3: OAuth2/JWT (Developer Identity Proof)       │
  │                                                       │
  │  Sidecar validates:                                   │
  │    • JWT signature (JWKS from Entra)                  │
  │    • Issuer, audience, expiry                         │
  │    • App roles (required_roles in RBAC policy)        │
  └──────────────────────────┬───────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────┐
  │  Layer 2: RBAC (Developer Application Policy)         │
  │                                                       │
  │  Sidecar evaluates:                                   │
  │    • Caller SPIFFE ID + HTTP method + path            │
  │    • First matching rule wins                         │
  │    • Default deny if no match                         │
  └──────────────────────────┬───────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────┐
  │  Layer 1: mTLS (Developer Transport Policy)           │
  │                                                       │
  │  Sidecar enforces:                                    │
  │    • SPIFFE ID in X.509 cert SAN                      │
  │    • Dynamic allow list check                         │
  │    • TLS handshake rejected if not in list            │
  └──────────────────────────────────────────────────────┘
```

**Key property:** Admin authority supersedes developer authority at both enforcement points. Layer 4a blocks agents before a token exists. Layer 4b blocks requests even when the agent holds a valid token.

## Current Repo Reality

The repo now demonstrates two different Layer 4 stories:

- **BudgetBackend data plane:** risk-level blocking enforced through the SPIFFE sidecar / admin-control-plane path.
- **Direct A2A app path:** Entra-backed custom-attribute tag matching enforced at the target app after JWT validation.

Today, the direct A2A demo is still **post-token** deny, not guaranteed **token issuance** deny. The CA policy in the tenant is currently report-only, and the live blocking behavior is produced by synced Entra attribute state plus target-side enforcement.

This distinction matters when debugging the portal:
- `JWT VALIDATED: Yes` + `403 CA DENIED` means the app/data-plane governance layer blocked the request after token issuance.
- It does **not** yet mean ESTS refused to issue the token.

## How CA Claims Flow Through the Stack

Two JWT claims carry Conditional Access decisions from Entra STS (Layer 4a) to the sidecar (Layer 4b):

- **`acrs`** — which authentication contexts (C1–C99) were satisfied at token issuance. The sidecar checks whether the token's `acrs` includes the context required for the requested path (`require_auth_context` in RBAC policy). If the context is missing, the sidecar returns a [claims challenge](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge) so MSAL can re-acquire a token with the missing requirement (e.g., MFA).
- **`capolids`** — which CA policy IDs were evaluated and satisfied. Used for audit, diagnostics, and compliance reporting.

Admins configure authentication contexts in **Entra ID > Conditional Access > Authentication context** and reference them in CA policies. The sidecar compares these against per-path requirements in the RBAC policy.

## Dual Enforcement: Why Both Points Are Necessary

Access tokens have a default lifetime of 60 minutes. Three categories of events invalidate token-time assumptions:

| Gap | Example | Without Data-Plane CA |
|---|---|---|
| **Token lifetime** | SOC triggers lockdown at minute 5 of a 60-minute token | Agent operates for 55 more minutes |
| **Policy change lag** | Admin adds location restriction after issuance | Agent accesses from prohibited location |
| **Resource granularity** | Token for `api://budget-service` | Cannot distinguish `/budget/read` from `/budget/approve` |

Data-plane CA (4b) re-evaluates on every request. Cache TTL of 30-60 seconds bounds the window.

## Real-World Scenarios

Each scenario shows what an admin can do with CA that is impossible with developer-defined policies alone. No code changes, no YAML edits — just Entra portal policy.

### Financial services — block unapproved agents

A bank's CISO discovers a vendor-deployed agent accessing SharePoint financial reports via OBO. Without CA, the agent has valid SPIFFE identity and RBAC allows it — the bank cannot block it without modifying the developer's YAML. With CA, the admin creates a policy: *"Block Agent Blueprint X from SharePoint."* Token denied at STS. No code changes, no vendor coordination.

### Healthcare — MFA step-up for PHI access

A hospital scheduling agent accesses patient records on behalf of nurses. Without CA, no mechanism exists for additional authentication on sensitive data. With CA, the admin requires MFA for the EHR resource. The OBO flow returns a claims challenge. The nurse completes MFA. HIPAA compliance is maintained.

### Incident response — emergency lockdown

SOC detects anomalous agent behavior. With token-time CA only, agents holding valid tokens continue for up to 60 minutes. With dual enforcement, the admin toggles a kill-switch policy. Token-time CA (4a) blocks new tokens immediately. Data-plane CA (4b) blocks existing sessions within 30-60 seconds.

## RBAC Policy v5.0 (with Admin Governance)

```yaml
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny

admin_governance:
  enabled: true
  ca_enforcement: dual              # "token-only" | "dual"
  enforcement_points:
    token_time: entra-sts           # Layer 4a
    data_plane: sidecar-ingress     # Layer 4b
  ca_evaluation_endpoint: "{resource_provider_data_plane}"  # e.g., the resource provider's CA evaluation surface
  ca_evaluation_cache_ttl_seconds: 45
  ca_evaluation_fail_mode: closed   # "closed" (deny) | "open" (allow)
  audit_integration: entra-sign-in-logs

policies:
  - spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/"
    name: "budget-report"
    entra_agent_id: ""
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Read"]
        # Token-time CA (4a): evaluated at STS.
        # Data-plane CA (4b): re-checked every request.

      - path: "/budget/submit"
        methods: ["POST"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Submit"]
        require_auth_context: "c1"
        # Sidecar verifies token carries auth context "c1"
        # (e.g., MFA completed). If not, returns claims
        # challenge for step-up.

      - path: "/budget/approve"
        methods: ["POST"]
        action: deny
```

## Data-Plane CA in the Sidecar Ingress Pipeline

```
                        ┌─────────────┐
                        │  Entra STS   │
                        │  (Layer 4a)  │
                        └──────┬──────┘
                               │
                  Token issued with acrs + capolids
                               │
                               ▼
┌─────────────────────────────────────────────────────────┐
│                   Sidecar Proxy Ingress                   │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │               Layer 4b: Data-Plane CA                │ │
│  │                                                      │ │
│  │  1. Extract acrs + capolids from JWT                 │ │
│  │  2. Match path → require_auth_context (RBAC policy)  │ │
│  │  3. Call CA evaluation endpoint (real-time check)     │ │
│  │  4. Compare token claims against current policy      │ │
│  │                                                      │ │
│  │  If insufficient → 403 + WWW-Authenticate: Bearer    │ │
│  │    claims="eyJ..." (base64 claims challenge)         │ │
│  │  If endpoint unreachable → fail closed (deny)        │ │
│  └─────────────────────────────────────────────────────┘ │
│                           │                               │
│  ┌────────────────────────▼────────────────────────────┐ │
│  │             Layers 1–3 (Developer Policies)          │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Caching:** CA evaluation results cached with short TTLs (30-60 seconds). Cache keys: token hash + resource path + HTTP method. Invalidated on CA policy change via webhook.

**Claims challenge flow:** When data-plane CA finds insufficient claims, it returns a `403` with a `WWW-Authenticate: Bearer claims="eyJ..."` header containing a base64-encoded claims challenge. The calling agent's MSAL instance uses this to re-acquire a token that satisfies the missing requirement — the same [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge) pattern used for users, extended to agents.

## Enforcement Matrix (Extended)

### Transport + Application (Developer — Layers 1-2)

| # | Caller | Action | Result | Authority |
|---|--------|--------|--------|-----------|
| 1 | BudgetReport | connects to BudgetBackend | ✅ | Developer (mTLS allow list) |
| 2 | EmployeeMenus | connects to BudgetBackend | ❌ | Developer (not in allow list) |
| 3 | BudgetReport | GET /budget/read | ✅ 200 | Developer (RBAC allow) |
| 4 | BudgetReport | POST /budget/submit | ❌ 403 | Developer (RBAC deny) |
| 5 | BudgetApproval | POST /budget/submit | ✅ 200 | Developer (RBAC + JWT) |

### Token-Time CA (Admin — Layer 4a)

| # | Agent | Scenario | Result | Authority |
|---|-------|----------|--------|-----------|
| 6 | BudgetReport | Admin blocks blueprint via CA | ❌ Token denied | Admin (CA at STS) |
| 7 | BudgetReport | Admin requires MFA for resource | ⏳ Step-up | Admin (CA at STS) |
| 8 | BudgetApproval | Admin restricts to US locations | ❌ or ✅ | Admin (named location) |
| 9 | Any agent | SOC emergency lockdown | ❌ All blocked | Admin (CA kill switch) |
| 10 | BudgetReport | IDP flags agent as risky | ❌ Token denied | Admin (risk-based CA) |

### Data-Plane CA (Admin — Layer 4b)

| # | Agent | Scenario | Result | Authority |
|---|-------|----------|--------|-----------|
| 11 | BudgetReport | Policy changed after token issued | ❌ 403 + challenge | Admin (re-evaluation) |
| 12 | BudgetReport | Risk elevated mid-session | ❌ 403 + challenge | Admin (risk re-check) |
| 13 | BudgetReport | Path requires auth context "c1", token lacks it | ❌ 403 + challenge | Admin (auth context) |
| 14 | BudgetApproval | CA endpoint returns deny | ❌ 403 | Admin (real-time eval) |
| 15 | Any agent | CA endpoint unreachable | ❌ 503 | Admin (fail-closed) |

20 total scenarios (5 developer + 5 token-time CA + 5 data-plane CA + 5 combined).

## Sidecar Integration

The sidecar enforces CA at two levels:

1. **Layer 4a (passive):** If CA denied the token at STS, there is no token to present. The agent never reaches the sidecar.
2. **Layer 4b (active):** Ingress pipeline evaluates CA on every request before Layers 1-3. Extracts claims, matches path requirements, calls evaluation endpoint, returns claims challenge if insufficient.
3. **Layer 3 (unchanged):** Standard JWT validation — signature, issuer, audience, expiry, app roles.

## Registry Complement

The Agent Registry's quarantine mechanism complements CA:

- **Registry quarantine:** Binary — blocks agent discovery entirely
- **CA policies:** Granular — conditional enforcement (MFA, location, time-of-day)

Registry handles "is this agent allowed to exist." CA handles "under what conditions can it operate."

## Audit Integration

CA evaluation results appear in **Entra sign-in logs** — the same logs admins use for users and apps:

- Agent access decisions auditable in existing SIEM and monitoring tools
- Compliance reports cover users, apps, and agents in one query
- [What If tool](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) already supports agent identity simulation — test policies before enforcement
- [What If Evaluation API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate) enables programmatic pre-deployment validation and CI/CD integration
- [CA optimization agent](https://learn.microsoft.com/en-us/entra/security-copilot/conditional-access-agent-optimization) scans for unprotected agent identities and recommends policies

## Implementation Phases

| Phase | Scope | Timeline | Cost |
|---|---|---|---|
| 1 | Token-time CA on agent tokens | **In production** (1K+ customers) | Minimal — register as Entra Agent ID constructs |
| 2 | Data-plane CA in sidecar | Q1 FY27 | Moderate — evaluation client, caching, claims challenge |
| 3 | Unified visibility + What If | Q2 FY27 | Moderate — portal integration, bidirectional policy awareness |

## Related

- [ADR-010](../decisions/010-conditional-access-admin-governance.md) — Decision record with regulatory analysis
- [system-overview.md](system-overview.md) — Current four-layer runtime architecture
- [enforcement-flow.md](enforcement-flow.md) — Existing enforcement sequence diagrams
