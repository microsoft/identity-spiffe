# Conditional Access (CA) — Platform Learnings

> **Purpose:** Comprehensive reference for Claude Code instances working on CA enforcement in the Identity Research for Agent Management Using SPIFFE PoC. Load this file before working on admin governance, Layer 4 enforcement, agent risk, or custom security attributes.
>
> **Last updated:** 2026-03-20
> **Sources:** Microsoft Learn docs, Entra CA team briefings, ADR-010, admin-governance-layer.md

---

## Table of Contents

1. [What Is Conditional Access?](#what-is-conditional-access)
2. [CA for Workload Identities (GA)](#ca-for-workload-identities-ga)
3. [CA for Agent Identities (Public Preview)](#ca-for-agent-identities-public-preview)
4. [Custom Security Attributes](#custom-security-attributes)
5. [Agent/Workload Risk Detection](#agentworkload-risk-detection)
6. [Token Claims and CA Signals](#token-claims-and-ca-signals)
7. [Claims Challenge Flow](#claims-challenge-flow)
8. [Graph API for CA Policies](#graph-api-for-ca-policies)
9. [Limitations and Restrictions](#limitations-and-restrictions)
10. [How This Maps to Identity Research for Agent Management Using SPIFFE PoC](#how-this-maps-to-aim-poc)
11. [Key Terminology](#key-terminology)
12. [References](#references)

---

## What Is Conditional Access?

Conditional Access (CA) is Entra ID's policy engine for controlling access to resources. Admins create if/then rules: *if* an identity matches certain conditions (location, risk level, device state), *then* enforce controls (block, require MFA, limit session).

**Key properties:**
- CA is the **admin governance layer** — it controls what an agent *is allowed* to do in a specific organization, distinct from developer-defined policies (RBAC, mTLS) that control what an agent *can* do
- CA evaluates at **two enforcement points**: token issuance time (Entra STS) and data plane (per-request)
- Admin authority **supersedes** developer authority — CA can block agents even when mTLS, RBAC, and JWT all allow
- CA policies are **binary for workloads/agents**: the only available control is "block" (no "require MFA" or "require compliant device" for non-human identities)

**Licensing:**
- Entra ID P1/P2 for user CA policies
- **Workload Identities Premium** ($3/workload/month) for workload identity CA policies
- Microsoft 365 Copilot + Frontier program for Agent ID CA policies (public preview)

---

## CA for Workload Identities (GA)

CA for workload identities is **generally available**. It extends CA policies to service principals.

### What's In Scope

- **Single-tenant service principals** registered in your tenant
- Location-based blocking (IP allowlists at token issuance)
- Risk-based blocking (ID Protection detects anomalous patterns)
- Continuous Access Evaluation (CAE) — real-time enforcement, 24-hour long-lived tokens with real-time policy checks

### What's Out of Scope

- **Managed identities** — cannot be directly targeted by CA policies (significant gap for Azure-native workloads)
- **Multi-tenant applications** — not supported
- **Third-party SaaS applications** — not supported
- **Service principals in groups** — CA policies must target SPs directly, not through group membership
- **"Require" controls** — only "block" is available (no MFA, no compliant device, no terms of use)

### Enforcement Behavior

When a service principal requests a token:
1. CA policy evaluated at the **token endpoint**
2. If conditions match and action is "block" → token request denied
3. Error returned: `"Access has been blocked due to Conditional Access policies"`
4. Sign-in log entry created with failure reason

### Available Conditions for Workload Identities

| Condition | What It Does |
|-----------|-------------|
| **Location** | Block/allow based on IP address or named location |
| **Risk level** | Block based on ID Protection risk signals (high/medium/low) |
| **Service principal targeting** | Target specific SPs by Object ID or "ServicePrincipalsInMyTenant" |
| **Application targeting** | Scope to specific resource applications |

---

## CA for Agent Identities (Public Preview)

As of March 2026, Conditional Access has been extended to **AI agent identities** as first-class citizens, with agent-specific targeting separate from workload identities and user policies.

### New Identity Constructs

| Term | Definition |
|------|-----------|
| **Agent Blueprint** | Logical definition of an agent type (template/class) |
| **Agent Blueprint Principal** | Service principal that creates agent identities and agent users |
| **Agent Identity** | Instantiated agent (performs token acquisitions, accesses resources) |
| **Agent User** | Non-human user identity for agent experiences requiring a user account |
| **Agent Resource** | Agent blueprint or identity acting as a resource (agent-to-agent flows) |

### What CA Can Target for Agents

**Assignments (scope policy to):**
- All agent identities in tenant
- Specific agent identities by Object ID
- Agent identities filtered by **custom security attributes**
- Agent identities grouped by blueprint
- All agent users in tenant

**Target Resources:**
- All resources
- All agent resources (blueprints + identities)
- Resources filtered by custom security attributes
- Specific resources by appId
- Agent blueprints (covers all parented agent identities)

**Available Conditions:**
- **Agent risk** (high, medium, low) — only condition available in public preview

**Available Controls:**
- **Block** — only control available (same limitation as workload identities)

**Modes:**
- On / Off / Report-only (for simulation without enforcement)

### What CA Does NOT Apply To (Agent Exemptions)

- Agent blueprint acquiring tokens to create agent identities/users (limited functionality by design)
- Agent blueprint/identity performing token exchange at AAD Token Exchange Endpoint: Public
- Policies scoped to users or workload identities (not agents — separate policy space)
- Tenants with security defaults enabled

### Common Agent CA Scenarios

**Scenario 1: Allow only approved agents**
- Tag agents with custom security attribute `AgentApprovalStatus = Finance_Approved`
- Tag resources with `Department = Finance`
- CA policy: block all agents except those with matching attributes

**Scenario 2: Block high-risk agents**
- Create CA policy: `agentIdRiskLevels: "high"` → block
- Integrates with ID Protection risk signals
- Microsoft provides Microsoft Managed Policies as secure baseline

**Scenario 3: Emergency lockdown**
- Admin toggles kill-switch policy: block all agent identities
- Token-time CA blocks new tokens immediately
- Data-plane CA blocks existing sessions within 30-60 seconds (cache TTL)

---

## Custom Security Attributes

Custom security attributes enable **dynamic targeting** of CA policies without manually selecting entities in each policy.

### How They Work

- Admins define attribute sets and attributes in Entra ID
- Attributes are assigned to applications, service principals, and agent identities
- CA policies can filter targets by attribute values
- Evaluated at **token issuance runtime** (not configuration time)
- Eliminates policy sprawl — no manual per-entity policy maintenance

### Technical Constraints

- **String-type only** — only string custom attributes work with CA filters
- Can assign **multiple attributes** to a single entity
- Attributes must be **pre-assigned** before policy creation
- Available operators: `Contains`, `Equals`, etc.

### Example Attribute Structure

```
Attribute Set: AgentAttributes
├─ AgentApprovalStatus (values: New, In_Review, HR_Approved, Finance_Approved, IT_Approved)
├─ AgentTier (values: Tier1, Tier2, Tier3)
├─ AgentDepartment (values: Finance, HR, IT, Marketing, Sales)

Attribute Set: ResourceAttributes
├─ Department (values: Finance, HR, IT, Marketing, Sales)
├─ SensitivityLevel (values: Public, Internal, Confidential)
```

### Use in Identity Research for Agent Management Using SPIFFE PoC

We use custom attributes to implement **tag-based A2A authorization**:
- BudgetReport and BudgetApproval both get `AgentDepartment = Finance`
- EmployeeMenus has no `AgentDepartment` attribute
- CA policy: only agents with matching department tags can call each other
- **PoC implementation:** Simulated at the data plane (sidecar checks `agent_tag` in YAML policy)
- **Production implementation:** CA blocks at STS — no token issued if attributes don't match

---

## Agent/Workload Risk Detection

Microsoft Entra ID Protection provides risk detection for workload and agent identities.

### Risk Detection Types — Workload Identities (GA)

| Detection | Analysis Type | Description |
|-----------|--------------|-------------|
| **Leaked Credentials** | Offline | Credentials found in GitHub repos or dark web |
| **Suspicious Sign-ins** | Offline | Unfamiliar IP, user agent, credential type, or resource patterns |
| **Microsoft Threat Intelligence** | Offline | Activity matching known attack patterns |
| **Anomalous Service Principal Activity** | Offline | Abnormal admin behavior or config changes |
| **Suspicious API Traffic** | Offline | Abnormal Graph API traffic or directory enumeration |
| **Admin Confirmed Compromised** | Offline | Admin manually confirmed compromise |
| **Malicious Application** | Offline | Microsoft disabled app for terms violation |
| **Suspicious Application** | Offline | App may violate terms but not yet disabled |

### Risk Detection Types — Agent Identities (Preview)

Agent risk detections are separate from workload identity risk detections. All are currently offline.

| Detection | riskEventType | Description |
|-----------|--------------|-------------|
| **Unfamiliar Resource Access** | `unfamiliarResourceAccess` | Agent targeted resources it doesn't usually access — attacker may be probing beyond intended scope |
| **Sign-in Spike** | `signInSpike` | Abnormally high sign-in frequency — may indicate automation/toolkit abuse |
| **Failed Access Attempt** | `failedAccessAttempt` | Agent tried to access unauthorized resources — possible token replay |
| **Sign-in by Risky User** | `riskyUserSignIn` | Agent signed in on behalf of a risky user (delegated auth) — compromised user credentials |
| **Confirmed Compromised** | `adminConfirmedAgentCompromised` | Admin manually confirmed agent compromise — sets risk to High |
| **Microsoft Threat Intelligence** | `threatIntelligenceAccount` | Activity matching known attack patterns from Microsoft's internal/external intel |

### Graph API for Agent Risk

Two new collections in the ID Protection APIs:
- `riskyAgents` — list/query agents flagged for risky behavior
- `agentRiskDetections` — individual risk detection events (up to 90 days)

Actions available on risky agents:
- **Confirm compromise** — sets risk to High, triggers risk-based CA policies
- **Confirm safe** — clears risk (sets to None), marks as false positive
- **Dismiss risk** — acknowledges risk but continues flagging similar activity
- **Disable** — prevents all sign-ins for the agent across Entra ID

### Risk Levels

- **High** — strong indicator of compromise
- **Medium** — suspicious but not confirmed
- **Low** — minor anomaly detected
- **None** — no risk signals

### How Risk Feeds Into CA

1. ID Protection analyzes signals and assigns risk level to the identity
2. CA policy condition `agentIdRiskLevels: "high"` matches against the risk
3. If matched → token issuance blocked
4. Risk can change mid-session → data-plane CA re-evaluates within cache TTL

### Identity Research for Agent Management Using SPIFFE PoC: Agent Risk

For the PoC, we simulate agent risk via an external "Security Portal" mock portal:
- Mock portal pushes risk level to sidecar mgmt API
- Sidecar stores risk per agent SPIFFE ID
- RBAC engine checks risk before evaluating rules
- If risk matches `blocked_risk_levels` in CA policy → 403

**Future:** Agent risk will be a CA claim in the JWT token, evaluated at both STS and data plane.

### CA Authentication Flow Coverage for Agents

Understanding which flows CA applies to is critical for PoC design:

| Authentication Flow | CA Applies? | Details |
|---|---|---|
| Agent identity → Resource | ✅ Yes | Governed by agent identity policies |
| Agent user → Resource | ✅ Yes | Governed by agent user policies |
| Agent blueprint → Graph (create agent identity/user) | ❌ No | Blueprint has limited functionality |
| Agent blueprint/identity → Token Exchange | ❌ No | Intermediate exchange, no resource access |

**Key insight for A2A:** When Agent A calls Agent B, Agent A acquires a token with audience=Agent B. CA evaluates this acquisition. This means CA can block Agent A from calling Agent B at token issuance time — the A2A call never happens. This is exactly what we need for tag-based A2A authorization.

### Sign-in Log Investigation

Agent-specific entries appear in different log locations:
- **Agent identities** accessing resources → Service principal sign-in logs → agentType: `agent ID user`
- **Agent users** accessing resources → Non-interactive user sign-ins → agentType: `agent user`
- **Users** accessing agents → User sign-ins

---

## Token Claims and CA Signals

Two JWT claims carry CA decisions from Entra STS to the data plane:

### `acrs` Claim (Authentication Context)

- Lists which authentication contexts (C1–C99) were satisfied at token issuance
- Admins configure contexts in **Entra ID > Conditional Access > Authentication context**
- The sidecar checks whether the token's `acrs` includes the context required for the requested path (`require_auth_context` in RBAC policy)
- If missing → sidecar returns claims challenge for step-up

**Example:**
```json
{
  "acrs": ["c1", "c3"],
  "aud": "api://budget-backend",
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0"
}
```

### `capolids` Claim (CA Policy IDs)

- Lists which CA policy IDs were evaluated and satisfied
- Used for audit, diagnostics, and compliance reporting
- Enables the [What If tool](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) to show which policies applied

**Example:**
```json
{
  "capolids": ["00000000-0000-0000-0000-000000000000"]
}
```

### Other Relevant Claims for Agent Identity

| Claim | Purpose |
|-------|---------|
| `sub` / `oid` | Agent identity Object ID |
| `azp` / `appid` | Client application ID (the agent requesting the token) |
| `aud` | Target resource (audience) |
| `roles` | App roles assigned to the agent for this resource |
| `tid` | Tenant ID |
| `idtyp` | Identity type (`"app"` for service principals) |

---

## Claims Challenge Flow

When data-plane CA finds insufficient claims in a token, it triggers a **claims challenge**:

1. Sidecar receives request with JWT
2. Checks `acrs` against `require_auth_context` for the requested path
3. If auth context missing → returns:
   ```
   HTTP/1.1 403 Forbidden
   WWW-Authenticate: Bearer claims="eyJ..."
   ```
4. The base64-decoded claims value contains:
   ```json
   {
     "access_token": {
       "acrs": {
         "essential": true,
         "value": "c1"
       }
     }
   }
   ```
5. Calling agent's MSAL instance uses this to re-acquire a token satisfying the requirement
6. This is the same [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge) pattern used for users, extended to agents

---

## Graph API for CA Policies

### Create CA Policy (Beta)

```
POST https://graph.microsoft.com/beta/identity/conditionalAccess/policies
```

**Required scopes:**
- `Policy.ReadWrite.ConditionalAccess`
- `Policy.Read.All`

### Sample: Block High-Risk Agent Identities

```json
{
  "displayName": "Block all high risk agents from accessing all resources",
  "state": "enabled",
  "conditions": {
    "clientAppTypes": ["all"],
    "agentIdRiskLevels": "high",
    "applications": {
      "includeApplications": ["All"]
    },
    "users": {
      "includeUsers": ["None"]
    },
    "clientApplications": {
      "includeServicePrincipals": [],
      "includeAgentIdServicePrincipals": ["All"],
      "excludeServicePrincipals": []
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

### Key Agent-Specific Fields

| Field | Purpose |
|-------|---------|
| `conditions.agentIdRiskLevels` | Risk threshold: `"high"`, `"medium"`, `"low"` |
| `conditions.clientApplications.includeAgentIdServicePrincipals` | Target agent identities by OID or `"All"` |
| `grantControls.builtInControls: ["block"]` | Binary enforcement at token issuance |

### Sample: Block Agents Without Custom Attribute

```json
{
  "displayName": "Block non-finance agents from finance resources",
  "state": "enabled",
  "conditions": {
    "clientAppTypes": ["all"],
    "applications": {
      "includeApplications": ["All"],
      "applicationFilter": {
        "mode": "include",
        "rule": "customSecurityAttribute.ResourceAttributes.Department -eq \"Finance\""
      }
    },
    "clientApplications": {
      "includeAgentIdServicePrincipals": ["All"],
      "servicePrincipalFilter": {
        "mode": "exclude",
        "rule": "customSecurityAttribute.AgentAttributes.AgentDepartment -eq \"Finance\""
      }
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

### Policy States

| State | Behavior |
|-------|----------|
| `"enabled"` | Policy actively enforced |
| `"disabled"` | Policy exists but not enforced |
| `"enabledForReportingButNotEnforced"` | Report-only mode — logs what would happen without blocking |

---

## Limitations and Restrictions

### For Workload Identities (GA)

| Limitation | Impact |
|-----------|--------|
| Only "block" control | Cannot require MFA, compliant device, or terms of use for service principals |
| Managed identities not supported | Azure-native workloads using MI cannot be targeted by CA |
| No group targeting | Must assign policies directly to SP Object IDs, not groups |
| Requires Workload Identities Premium | $3/workload/month licensing |
| ~1500 API assignment limit | SP can only be assigned to ~1500 APIs |

### For Agent Identities (Public Preview)

| Limitation | Impact |
|-----------|--------|
| Public preview — may change | Schema and features not finalized |
| Only "block" control | Same as workload identities |
| Only "agent risk" condition | Location, device, sign-in risk not yet available for agents |
| Requires M365 Copilot + Frontier | Limited availability |
| Blueprint token acquisition exempt | Cannot block blueprint from creating agent identities |

### Known S2S Issues (from Feb 24 Deep-Dive)

These are Entra S2S limitations identified by Matt and Philippe:

1. **Insecure by default** — Any SP can request a token for ANY audience. No authorization check at issuance.
2. **"Require Assignment" is binary** — Toggle says "require at least one role." Cannot scope to specific roles.
3. **SPs can't inherit app roles through groups** — Decade-old limitation. Users can; SPs cannot.
4. **~1500 API limit** — SP assignment limit.
5. **Late-bound authorization legacy** — First-party teams pushed all authz to the resource, so Entra stuffs tokens fat.

---

## How This Maps to Identity Research for Agent Management Using SPIFFE PoC

### Four-Layer Enforcement Model

```
Layer 4a: CA — Token Time (Admin)     → Entra STS blocks token issuance
Layer 4b: CA — Data Plane (Admin)     → Sidecar re-evaluates per request
Layer 3:  OAuth2/JWT (Developer)      → Sidecar validates token + roles
Layer 2:  RBAC (Developer)            → Sidecar evaluates path/method rules
Layer 1:  mTLS (Developer)            → Sidecar rejects untrusted certificates
```

### What We Implement in the PoC

| Feature | PoC Implementation | Production Path |
|---------|-------------------|-----------------|
| Custom attribute tags | Data-plane check in sidecar YAML policy (`agent_tag`) | CA blocks at STS via custom security attributes |
| Agent risk blocking | Data-plane check in sidecar (external risk push via mgmt API) | CA blocks at STS via `agentIdRiskLevels` |
| A2A authorization | Direct HTTPS with JWT + app-layer tag/risk check | CA + S2S OAuth with STS-enforced attributes |
| Agent state toggle | `agent_state: disabled` in YAML policy | CA policy with `state: enabled/disabled` |
| Risk signal source | Security Portal Mock → mgmt API | identity protection signals → Entra |

### YAML Policy v5.0 CA Section

```yaml
ca:
  agent_state: enabled              # "enabled" or "disabled" — admin kill switch
  agent_tag: finance                # Custom attribute tag for A2A authorization
  blocked_risk_levels: ["high"]     # Risk levels to block at data plane
```

---

## Key Terminology

| Term | Definition |
|------|-----------|
| **CA** | Conditional Access — Entra's admin policy engine |
| **STS** | Security Token Service — Entra's token issuance endpoint |
| **CAE** | Continuous Access Evaluation — real-time policy enforcement |
| **Claims challenge** | HTTP 403 + `WWW-Authenticate` header triggering token re-acquisition |
| **Authentication context** | Admin-defined label (C1-C99) requiring specific CA satisfaction |
| **Custom security attribute** | Admin-defined metadata on identities for dynamic CA targeting |
| **Agent risk** | Risk level assigned by ID Protection to agent identities |
| **What If tool** | Entra portal tool for simulating CA policy evaluation |
| **Data-plane CA** | Per-request CA evaluation at the sidecar (Layer 4b) |
| **Token-time CA** | CA evaluation at token issuance (Layer 4a) |
| **Admin governance** | CA policies set by IT admins that supersede developer policies |

---

## References

- [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Conditional Access for Agent ID (Preview)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id)
- [Securing workload identities with ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk)
- [Custom security attributes in Conditional Access](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/leveraging-custom-security-attributes-in-conditional-access-policies/4373293)
- [Microsoft Entra Agent ID overview](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/microsoft-entra-agent-identities-for-ai-agents)
- [Claims challenge and CAE](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge)
- [What If evaluation API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate)
- [CA optimization agent](https://learn.microsoft.com/en-us/entra/security-copilot/conditional-access-agent-optimization)
- [ADR-010: Conditional Access as Admin Governance](../decisions/010-conditional-access-admin-governance.md)
- [Admin Governance Layer Architecture](../architecture/admin-governance-layer.md)
