# Architecture Specification: Hierarchical SPIFFE Namespace Authorization

**Document Status:** Implementation-Ready Specification  
**Target Path:** `docs/architecture/hierarchical-spiffe-namespace-authorization.md`  
**Supersedes:** `docs/architecture/layers/rbac-authorization.md` (Legacy Path/OAuth-Role RBAC)

---

## 1. Executive Summary & Terminology

### 1.1 Problem Statement
The current gateway implementation in `src/spiffe-proxy/internal/rbac` couples SPIFFE workload identities with HTTP path/method filtering and OAuth application roles (`required_roles: ["Budget.Read"]`). This conflates transport identity, application routing, and token claims into a misnamed "RBAC" layer. Furthermore, `CallerPolicy` evaluation relies on linear first-match scans over `Policies`, causing ordering dependencies, fragile wildcard prefixes, and an inability to model organizational ownership hierarchies (such as Microsoft Entra Agent Identity Blueprints).

### 1.2 Terminology & Standards Disclaimer
* **SPIFFE Standards Compliance:** Under the SPIFFE ID and Workload API specifications, a SPIFFE ID is a URI (`spiffe://<trust-domain>/<path>`) identifying a workload. **SPIFFE standardizes workload identity and authentication, not authorization semantics or inheritance.** In SPIFFE, the path component is an opaque string or structured identifier defined by the local trust domain; SPIFFE explicitly does not mandate path hierarchy, namespace inheritance, or access control lists (ACLs).
* **Product-Defined Namespace Hierarchy:** The hierarchical authorization model specified here is an **application/product-defined authorization engine** implemented inside `spiffe-proxy`. It interprets segment-delimited paths within authenticated SPIFFE IDs to evaluate organizational hierarchy (Trust Domain → Authority → Blueprint → Agent).
* **Role of OAuth/JWT:** Entra ID OAuth tokens provide token validation and caller binding proof (signature, issuer, audience, expiration, caller claim binding). Entra app roles (`roles` claim) **must not** authorize requests; authorization decisions derive strictly from the authenticated SPIFFE ID namespace and admin governance policies.

---

## 2. SPIFFE Namespace Structure & Default Scenario

### 2.1 Namespace Scheme
Workloads deployed in Azure Container Apps are assigned SPIFFE IDs conforming to the Entra Agent Identity hierarchy:
```text
spiffe://<trust-domain>/ests/bp/<blueprint-object-id>/aid/<agent-object-id>
```

Path segments are strictly delimited by `/`:
1. `scheme`: Must be `spiffe://`
2. `trust-domain`: e.g., `aim.microsoft.com` (domestic) or `gcp.aim.microsoft.com` (federated)
3. `authority`: `ests` (Entra Security Token Service)
4. `blueprint-root`: `bp/<blueprint-object-id>` (organizational/architectural boundary)
5. `agent-leaf`: `aid/<agent-object-id>` (discrete workload instance)

### 2.2 Default Demo Policy Scenarios
The default environment models two distinct Entra Agent Identity Blueprints:
* **Blueprint 1 (Finance Operations):** `bp/11111111-1111-1111-1111-111111111111`
  * Subtree policy: `allow` (broadly allows all agents instantiated from the Finance Blueprint).
  * Exact Leaf Override: `bp/11111111-1111-1111-1111-111111111111/aid/33333333-3333-3333-3333-333333333333` (untrusted/quarantined agent) is explicitly set to `deny`.
* **Blueprint 2 (Operations / General Services):** `bp/22222222-2222-2222-2222-222222222222`
  * Subtree policy: `deny` (strictly blocks the entire blueprint namespace).
  * Exact Leaf Exception (Optional): Specific approved audit agent allowed if explicitly registered with higher specificity.

---

## 3. Policy Schema (`spiffe-namespace-policy.yaml`)

```yaml
version: "6.0"
trust_domain: "aim.microsoft.com"
default_action: deny

# Top-level Admin Governance (Layer 4)
admin_governance:
  enabled: true
  target_agent_tag: finance
  risk_enforcement: sts

# Domestic Namespace Authorization Rules
namespace_rules:
  # ── Blueprint 1: Finance Subtree (Broad Allow) ──
  - pattern: "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/*"
    action: allow
    description: "Finance Operations Blueprint - default allow for all child agents"
    require_oauth_token: true

  # ── Blueprint 1 Leaf Deny: Specific Agent Override ──
  - pattern: "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/aid/33333333-3333-3333-3333-333333333333"
    action: deny
    description: "Quarantined finance agent - exact leaf deny overrides blueprint allow"
    require_oauth_token: false

  # ── Blueprint 2: Operations Subtree (Restricted/Denied) ──
  - pattern: "spiffe://aim.microsoft.com/ests/bp/22222222-2222-2222-2222-222222222222/*"
    action: deny
    description: "Operations Blueprint - blocked from Budget Backend"
    require_oauth_token: false

  # ── Admin Control Plane: Dedicated Leaf Access ──
  - pattern: "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/aid/99999999-9999-9999-9999-999999999999"
    action: allow
    description: "Dedicated Admin Control Plane recovery identity"
    require_oauth_token: false
    ca:
      skip_target_tag_check: true

# Explicit Federated Namespace Delegation (Cross-Trust Domain)
federated_namespaces:
  - trust_domain: "gcp.aim.microsoft.com"
    allow_federated_subtree: false # Subtree wildcards strictly prohibited unless true
    rules:
      - pattern: "spiffe://gcp.aim.microsoft.com/ests/bp/44444444-4444-4444-4444-444444444444/aid/55555555-5555-5555-5555-555555555555"
        action: allow
        description: "Exact Google Budget Reader agent identity"
        require_oauth_token: true
```

---

## 4. Evaluator Algorithm & Specificity Rules

### 4.1 Canonicalization & Parsing Constraints
1. **SPIFFE Parsing:** The SPIFFE ID is parsed using `go-spiffe/v2/spiffeid.FromString(rawID)`.
2. **Rejection Rules (Fail-Closed at Handshake/Eval):**
   * Percent-encoding (`%2F`, `%20`, etc.) in trust domain or path: **REJECT**.
   * Query parameters (`?`) or fragments (`#`): **REJECT** (invalid per SPIFFE standard).
   * Empty path segments (`//`), dot segments (`/.` or `/..`): **REJECT**.
   * Trailing slashes (e.g., `spiffe://aim.microsoft.com/ests/bp/123/`): **REJECT**.
3. **Trust Domain Boundary Check:** Callers presenting an SVID with a trust domain differing from `policy.trust_domain` are immediately routed to `federated_namespaces`. Domestic rules cannot evaluate foreign trust domains.

### 4.2 Specificity Ranking & Precedence
When an incoming caller SPIFFE ID $ID$ is evaluated:
1. **Exact Match (Rank 1):** Matches a rule where rule pattern equals $ID$. Exact match outranks any prefix match regardless of prefix length or action.
2. **Longest Segment-Aligned Prefix (Rank 2):**
   * Patterns ending in `/*` match any ID having that exact prefix followed by `/` and one or more segments.
   * Prefix matching is strictly **segment-aligned**: `spiffe://aim.microsoft.com/ests/bp/111/*` matches `.../bp/111/aid/999`, but **never** matches `.../bp/1111-other/aid/999`.
   * Among multiple matching prefix rules, the rule with the highest segment depth (count of `/` path segments prior to `/*`) wins.
3. **Equal-Specificity Conflict Resolution:**
   * If two rules have identical specificity (e.g. identical exact pattern or identical prefix length) and opposing actions (`allow` vs `deny`):
     * **Compile/Load Time:** The policy **must be rejected** during validation (`LoadFromBytes`).
     * **Runtime Fallback (Defensive):** If ambiguity arises at runtime, the engine **fails closed to `deny`**.
4. **Default Action:** If no rule matches, evaluate `policy.default_action` (configured as `deny`).

### 4.3 Federated Subtree Delegation
* Federated rules apply only to authenticated callers from the matching foreign trust domain.
* If a federated rule contains a wildcard (`/*`), validation requires `allow_federated_subtree: true` on the parent domain entry. If `false`, wildcard rules in federated namespaces cause compile-time failure.

---

## 5. Evaluation Pipeline & Layer Interactions

```text
Incoming TLS Connection
          │
          ▼
┌────────────────────────────────────────────────────────┐
│ Layer 1: Transport mTLS (spiffe-proxy sidecar)         │
│ - Validate caller X.509 SVID against SPIRE trust bundle│
│ - Dynamic allowlist authorizer (spiffeid.ID match)     │
└─────────────────────────┬──────────────────────────────┘
                          │ (mTLS Established)
                          ▼
┌────────────────────────────────────────────────────────┐
│ Layer 2: Hierarchical SPIFFE Namespace Authorization   │
│ - Parse and validate caller SPIFFE ID canonical form   │
│ - Match Radix/Trie: Exact Leaf > Longest Prefix        │
│ - Decision: Allow or Deny (HTTP 403)                   │
└─────────────────────────┬──────────────────────────────┘
                          │ (Namespace Allowed)
                          ▼
┌────────────────────────────────────────────────────────┐
│ Layer 3: OAuth Token Validation & Caller Binding Proof │
│ - If rule.require_oauth_token == true:                 │
│   • Validate JWT signature (Entra JWKS), exp, iss, aud │
│   • Verify Caller Binding: token `oid` or `azp` must    │
│     match caller SPIFFE ID `<agent-object-id>`         │
│   • ROLES ARE IGNORED (Do not authorize)               │
└─────────────────────────┬──────────────────────────────┘
                          │ (Token & Binding Valid)
                          ▼
┌────────────────────────────────────────────────────────┐
│ Layer 4: Admin Governance (Conditional Access)         │
│ - 4a: Admin kill-switch (agent_state == disabled)      │
│ - 4b: Graph CA risk check (low/medium/high)            │
│ - 4c: Target tag match (caller_tag == target_tag)      │
└─────────────────────────┬──────────────────────────────┘
                          │ (CA Cleared)
                          ▼
Forward Request to Local Backend Application (port 8080)
```

### 5.1 OAuth Validation & Caller Binding Contract
When `require_oauth_token: true`:
1. **Signature & Expiry:** Token must be signed by Entra ID and valid at current time.
2. **Issuer:** Matches `https://login.microsoftonline.com/{tenant_id}/v2.0` (or v1.0).
3. **Audience:** Matches target backend application ID or URI.
4. **Caller Binding Verification:**
   * Extract `<agent-object-id>` from caller SPIFFE ID `spiffe://.../aid/<agent-object-id>`.
   * Compare extracted ID against JWT claims: `claims.OID` (Service Principal Object ID) or `claims.AZP` / `claims.AppID` (Client App ID).
   * If claim mismatch: Return **HTTP 401 Unauthorized** with `reason: "caller_identity_binding_mismatch"`.
5. **Roles Non-Enforcement:** The `roles` claim in the JWT is logged to audit logs for diagnostic visibility, but **never** evaluated to grant or deny access.

---

## 6. Radix Tree / Trie Compilation Engine

To provide $O(K)$ lookup (where $K$ is the segment count) and reject ambiguous policies at startup, the engine compiles rules into a Radix Trie:

```go
type RadixNode struct {
    Segment         string
    ExactRule       *CompiledRule
    PrefixRule      *CompiledRule // Applies to /*
    Children        map[string]*RadixNode
}

type CompiledRule struct {
    Pattern           string
    Action            Action
    RequireOAuthToken bool
    CA                CAPolicy
    SegmentDepth      int
}
```

### Validation Invariants at Load Time:
1. `ValidateNoConflictingExactMatches`: No two domestic rules may define identical SPIFFE IDs.
2. `ValidateNoConflictingPrefixMatches`: No two domestic rules may define identical prefix paths.
3. `ValidateSegmentAlignment`: Patterns with `*` must end strictly with `/*`. Characters like `/ests/bp/123*` or `/ests/*/aid` are rejected with `ErrInvalidWildcardPlacement`.
4. `ValidateTrustDomain`: Pattern URI authority must strictly equal declared `trust_domain`.

---

## 7. Inventory of Affected Repository Surfaces

| Component / File | Current State | Required Modification |
|---|---|---|
| `src/spiffe-proxy/internal/rbac/policy.go` | Implements `CallerPolicy` with linear array of paths and `RequiredRoles`. | Replace with `NamespacePolicy`, `NamespaceRule`, segment tree compiler, and load-time conflict rejection. |
| `src/spiffe-proxy/internal/rbac/engine.go` | Linear scan in `findCallerPolicy`, `matchPath`, `evaluateJWT` checking `r.RequiredRoles`. | Implement Radix Trie evaluator (Exact > Longest Prefix); remove `matchPath` and `hasRequiredRoles`. |
| `src/spiffe-proxy/internal/oauth/validator.go` | Validates JWT, extracts claims and roles. | Add caller identity binding validation: `ValidateCallerBinding(claims, spiffeID)`. Remove role authorization hooks. |
| `src/spiffe-proxy/internal/gateway/interceptor.go` | Enforces HTTP method/path RBAC and role matching. | Invoke namespace evaluator; inject verified `X-Spiffe-Blueprint-Id` and `X-Spiffe-Agent-Id` headers. |
| `src/spiffe-proxy/internal/mgmt/server.go` | Endpoints `/policy` accept v5.0 YAML. | Migrate `/policy` schema validation to v6.0; update health/metrics output. |
| `src/spiffe-proxy/config/spiffe-rbac-policy.yaml` | Uses v5.0 format with `/budget/read`, `/budget/submit`, and `required_roles`. | Update to v6.0 namespace hierarchy format with two Blueprints. |
| `scripts/create-entra-agent-ids.py` | Creates single Blueprint `ENTRA_BLUEPRINT_OBJECT_ID`. | Provision two Blueprints (`FINANCE` and `OPERATIONS`) and assign agent identities accordingly. |
| `scripts/lib/deploy-config.sh` & `deploy.sh` | Exports single `ENTRA_BP_OID` into Container App environments. | Update SPIRE entry registration and sidecar env vars to support dual Blueprint OIDs. |
| `scripts/test_agents.py` | Tests Scenario 1–5 based on HTTP path/method (`GET /budget/read`). | Re-baseline matrix to test Blueprint 1 allow, Blueprint 2 deny, Leaf deny override, and token binding. |
| `portal/app/services/policy.py` & `schemas/api.py` | Manages path-based rules and displays role matrices. | Update parser/serializer for hierarchical namespaces and tree visualization. |

---

## 8. Audit Logging & Portal UX

### 8.1 Structured Audit Log Schema
The access logger emits structured JSON reflecting the hierarchical decision:
```json
{
  "timestamp": "2026-09-30T22:36:29Z",
  "request_id": "req-8f4b12c0",
  "caller_spiffe_id": "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/aid/33333333-3333-3333-3333-333333333333",
  "decision": "deny",
  "enforcement_layer": "spiffe_namespace",
  "matched_rule": {
    "pattern": "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/aid/33333333-3333-3333-3333-333333333333",
    "match_type": "exact",
    "specificity_rank": 1
  },
  "overridden_rules": [
    {
      "pattern": "spiffe://aim.microsoft.com/ests/bp/11111111-1111-1111-1111-111111111111/*",
      "action": "allow",
      "match_type": "longest_prefix",
      "segment_depth": 4
    }
  ],
  "oauth_validation": {
    "token_present": true,
    "token_valid": true,
    "caller_binding_verified": true,
    "ignored_roles": ["Budget.Read"]
  }
}
```

### 8.2 Portal UX Enhancements
1. **Namespace Tree Visualization:** The Policy page in `isp-portal` renders an interactive tree:
   ```text
   ▼ aim.microsoft.com
     ▼ ests
       ▼ bp/11111111-1111-1111-1111-111111111111 (Finance Operations) [ALLOW]
           ├─ aid/2222... (budget-approval) -> Inherited [ALLOW]
           └─ aid/3333... (quarantined-agent) -> Overridden [DENY (Exact)]
       ▼ bp/22222222-2222-2222-2222-222222222222 (General Operations) [DENY]
           └─ aid/4444... (employee-menus) -> Inherited [DENY]
   ```
2. **Effective Access Simulator:** Allows administrators to input an arbitrary SPIFFE ID to evaluate the precise inheritance chain and final action.

---

## 9. Entra ID Provisioning Specification

To demonstrate hierarchical inheritance and cross-blueprint policy isolation, `scripts/create-entra-agent-ids.py` is updated to provision two separate Blueprints:

```text
Entra Tenant
 ├── Blueprint A (Finance):      DisplayName: "Agent Management Blueprint (Finance)"
 │    │                           AppId: ENTRA_BLUEPRINT_FINANCE_APP_ID
 │    │                           ObjectId: ENTRA_BLUEPRINT_FINANCE_OBJECT_ID
 │    ├── Agent Identity: budget-report    (AppId: ENTRA_AGENT_ID_BUDGET_REPORT)
 │    ├── Agent Identity: budget-approval  (AppId: ENTRA_AGENT_ID_BUDGET_APPROVAL)
 │    └── Agent Identity: budget-backend   (AppId: ENTRA_AGENT_ID_BUDGET_BACKEND)
 │
 └── Blueprint B (Operations):   DisplayName: "Agent Management Blueprint (Operations)"
      │                           AppId: ENTRA_BLUEPRINT_OPERATIONS_APP_ID
      │                           ObjectId: ENTRA_BLUEPRINT_OPERATIONS_OBJECT_ID
      ├── Agent Identity: employee-menus   (AppId: ENTRA_AGENT_ID_EMPLOYEE_MENUS)
      └── Agent Identity: rogue-agent      (AppId: ENTRA_AGENT_ID_ROGUE_AGENT)
```

### Provisioning Sequence in `scripts/create-entra-agent-ids.py`:
1. Acquire MS Graph token with `AgentIdentityBlueprint.ReadWrite.All`.
2. Provision `AgentIdentityBlueprint` A and B; create corresponding `AgentIdentityBlueprintPrincipal` service principals.
3. Provision Agent Identities with `agentIdentityBlueprintId` set to their respective parent Blueprint App ID.
4. Record environment variables to `azd env`:
   * `ENTRA_BLUEPRINT_FINANCE_OBJECT_ID`, `ENTRA_BLUEPRINT_FINANCE_APP_ID`
   * `ENTRA_BLUEPRINT_OPERATIONS_OBJECT_ID`, `ENTRA_BLUEPRINT_OPERATIONS_APP_ID`
5. Configure SPIRE server VM workload entries via `deploy.sh` to issue SVIDs reflecting the assigned parent Blueprint OID.

---

## 10. Breaking Migration Plan

Because breaking schema migration is acceptable, transition occurs cleanly across a single major version increment:

### Phase 1: Policy Schema Cutover
1. Increment policy version to `6.0`.
2. Convert `src/spiffe-proxy/config/spiffe-rbac-policy.yaml` to the new namespace schema.
3. Remove `methods`, `path`, and `required_roles` from policy definitions.

### Phase 2: Engine Replacement in `spiffe-proxy`
1. Replace `internal/rbac` with `internal/authz` (or refactor `rbac` package to implement the namespace tree).
2. Remove role evaluation logic from `oauth/validator.go` and implement `ValidateCallerBinding`.
3. Update management API endpoint `PUT /policy` to validate v6.0 syntax.

### Phase 3: Infrastructure & Deploy Script Update
1. Update `scripts/create-entra-agent-ids.py` to provision dual Blueprints.
2. Update `deploy.sh` Step 2.6 and Step 4.2 to generate SPIRE entries using dual Blueprint IDs.
3. Update `scripts/test_agents.py` to validate the new namespace matrix.

---

## 11. Acceptance & Security Test Plan

### 11.1 Functional Acceptance Tests (`engine_test.go`)
1. **Exact Overrides Blueprint:** Caller with `spiffe://aim.microsoft.com/ests/bp/BP1/aid/AGENT_DENY` is denied, even though `spiffe://aim.microsoft.com/ests/bp/BP1/*` is allowed.
2. **Inherited Blueprint Allow:** Caller with `spiffe://aim.microsoft.com/ests/bp/BP1/aid/AGENT_ALLOW` is allowed via prefix match.
3. **Inherited Blueprint Deny:** Caller with `spiffe://aim.microsoft.com/ests/bp/BP2/aid/ANY_AGENT` is denied via BP2 prefix rule.
4. **Default Deny:** Caller with unknown Blueprint `spiffe://aim.microsoft.com/ests/bp/BP_UNKNOWN/aid/X` is denied with reason `default_deny`.
5. **Caller Token Binding Pass:** Valid Entra JWT whose `oid` matches `<agent-object-id>` succeeds.
6. **Caller Token Binding Fail:** Valid Entra JWT issued to a different agent returns HTTP 401 `caller_identity_binding_mismatch`.
7. **Role Ignored:** Caller with valid token possessing zero roles still clears Layer 3 if token is cryptographically valid and bound.

### 11.2 Security Edge Cases & Attack Surface Tests
1. **Path Traversal / Canonicalization:**
   * `spiffe://aim.microsoft.com/ests/bp/BP1/aid/../aid/AGENT_DENY` -> Parse error, handshake/request rejected.
   * `spiffe://aim.microsoft.com/ests/bp/BP1/aid/AGENT_DENY/` (trailing slash) -> Parse error.
   * `spiffe://aim.microsoft.com/ests/bp/BP1/aid/%33%33...` (percent encoding) -> Parse error.
2. **Segment Delimiter Attack:**
   * Policy allows prefix `spiffe://aim.microsoft.com/ests/bp/111/*`. Caller presents `spiffe://aim.microsoft.com/ests/bp/111-rogue/aid/123`.
   * Result: **DENY** (segment boundary `/` strictly enforced; non-matching segment does not match).
3. **Foreign Trust Domain Spoofing:**
   * Caller presents `spiffe://evil.com/ests/bp/11111111-1111-1111-1111-111111111111/*`.
   * Result: Rejected at Layer 1 mTLS or immediately in domestic rule evaluator.
4. **Equal Specificity Rejection:**
   * Policy YAML defines both `allow` and `deny` for identical prefix `.../bp/111/*`.
   * Result: `store.LoadFromBytes` returns validation error `ambiguous_equal_specificity_rules`.

---

## 12. Rollout Strategy & Safe Deployment

1. **Pre-Deployment Validation:** Run `go test ./src/spiffe-proxy/...` and `python3 -m unittest` on updated provisioning scripts.
2. **Provisioning Dual Blueprints:** Execute `python3 scripts/create-entra-agent-ids.py` against Entra tenant to create Finance and Operations Blueprints and register new agent principals.
3. **Re-attestation of Workloads:** Run `./deploy.sh --skip-provision` to write new workload registration entries to SPIRE and issue new SVIDs reflecting the respective Blueprint paths.
4. **Sidecar Update:** Roll `spiffe-proxy` Container Apps with the v6.0 policy and binding validator enabled.
5. **End-to-End Verification:** Run `python3 scripts/test_agents.py` to confirm the live matrix.

---

## 13. Unresolved Decisions & Trade-Offs

1. **Subtree Path Depth Limitation:**
   * *Option A (Chosen):* Arbitrary segment depth supported by the Radix tree (supports future `spiffe://.../bp/<bp-id>/group/<group-id>/aid/<aid>`).
   * *Option B:* Fixed 4-level schema (`trust_domain/authority/blueprint/agent`).
   * *Rationale:* Option A provides extensibility for nested agent swarms or sub-teams without schema breakage.
2. **HTTP Method & Path Filtering Location:**
   * *Decision:* When HTTP method/path authorization is required for fine-grained operations (e.g. `GET /budget/read` vs `POST /budget/submit`), it should be handled by the target application workload or modeled as explicit operation scopes in a downstream policy layer, keeping the identity namespace authorization strictly focused on caller identity boundaries.
3. **Binding Token Subject vs Object ID:**
   * Entra Agent Identity tokens may populate the Service Principal Object ID in `oid` and the App ID in `appid`/`azp`. Caller binding checks should accept either claim matching the SPIRE workload registration metadata.

---

## 14. Primary References & Standards Citations

1. **SPIFFE Standards:**
   * *The SPIFFE Standard: SPIFFE ID*: [https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md). Defines `spiffe://<trust-domain>/<path>` URI syntax, RFC 3986 compliance, case sensitivity, and forbids query parameters, fragments, and percent-encoding.
   * *The SPIFFE Workload API*: [https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md). Defines X.509 SVID delivery and trust bundle distribution.
2. **`go-spiffe` Implementation:**
   * `github.com/spiffe/go-spiffe/v2/spiffeid`: Standard Go library for canonical parsing, trust domain isolation, and match evaluation.
3. **IETF RFCs:**
   * *RFC 3986:* Uniform Resource Identifier (URI): Generic Syntax.
   * *RFC 7519:* JSON Web Token (JWT).
   * *RFC 6750:* The OAuth 2.0 Authorization Framework: Bearer Token Usage.
4. **Microsoft Entra Agent Identity Documentation:**
   * Internal reference: `docs/platform-learnings/agent-id-blueprints-and-users.md`. Defines Microsoft Entra Agent Identity Blueprints and Agent Identity lifecycle via Graph Beta APIs.
