# ServiceNow Federation — Platform Learnings

> **Purpose:** Reference for implementing SPIFFE + Entra federation with ServiceNow workloads. Load this file before working on ServiceNow-hosted agents, OIDC token exchange from ServiceNow, or ServiceNow-to-Azure connectivity.
>
> **Last updated:** 2026-04-02
> **Sources:** ServiceNow OIDC docs, Entra WIF docs, SPIRE federation docs
> **Related:** `docs/platform-learnings/Google-Cloud-Federation.md`, `docs/platform-learnings/Amazon-Web-Services-Federation.md`

---

## Table of Contents

1. [Identity Primitives](#identity-primitives)
2. [SPIFFE Transport Layer](#spiffe-transport-layer)
3. [Entra Token Exchange (OAuth2 Layer)](#entra-token-exchange-oauth2-layer)
4. [Federated Identity Credential Setup](#federated-identity-credential-setup)
5. [Gotchas and Failure Modes](#gotchas-and-failure-modes)
6. [What Generalizes Across Platforms](#what-generalizes-across-platforms)
7. [ServiceNow-Specific Constraints](#servicenow-specific-constraints)
8. [References](#references)

---

## Identity Primitives

ServiceNow is fundamentally different from Google and AWS: it is a SaaS platform, not a cloud infrastructure provider. ServiceNow workloads run inside the ServiceNow platform, not on customer-controlled VMs or containers.

### ServiceNow OAuth2 / OIDC Provider

ServiceNow instances can function as an **OIDC provider**. A ServiceNow application can issue JWT tokens signed by the instance:

- **OIDC discovery endpoint:** `https://<instance>.service-now.com/.well-known/openid-configuration`
- **Token endpoint:** `https://<instance>.service-now.com/oauth_token.do`
- **JWKS endpoint:** `https://<instance>.service-now.com/api/now/jwt/validate/keys`

**Token claims (from ServiceNow as OIDC provider):**
- `iss`: `https://<instance>.service-now.com`
- `sub`: ServiceNow user or application sys_id
- `aud`: configured audience
- `scope`: requested scopes

### ServiceNow Integration Hub / Flow Designer

ServiceNow agents (IntegrationHub actions, Flow Designer steps, or custom scoped apps) execute within the ServiceNow platform runtime. They can make outbound HTTP calls (REST steps) but do NOT run on infrastructure where SPIRE can be installed.

### ServiceNow MID Server

The **MID Server** (Management, Instrumentation, and Discovery) is a Java application installed on customer-managed infrastructure (VM, container, or on-prem server). MID Servers:
- Run on customer-controlled compute (Windows/Linux VM)
- Act as a proxy between the ServiceNow instance and resources behind the customer's firewall
- CAN run SPIRE alongside them (the MID Server is just Java on a VM)

**This distinction is critical:** ServiceNow platform agents and MID Server-based agents have completely different identity and network models.

---

## SPIFFE Transport Layer

### No Native SPIRE Attestor for ServiceNow

SPIRE does not have a ServiceNow-specific NodeAttestor plugin. There is no equivalent of `gcp_iit` or `aws_iid`. This is because:

1. ServiceNow platform agents run inside the ServiceNow SaaS runtime — you cannot install SPIRE there
2. MID Servers run on customer infrastructure — they attest using the underlying platform's attestor (`aws_iid`, `gcp_iit`, `azure_msi`, or `join_token`)

### Two Architecture Models

**Model A: ServiceNow Platform Agent (no SPIRE possible)**

```
ServiceNow Platform
┌──────────────────────────┐
│  Flow Designer / IH       │
│  ┌────────────────────┐  │     HTTPS (no mTLS)
│  │ ServiceNow Agent   │──┼─────────────────────────► Azure (budget-backend)
│  │ (scoped app)       │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

- No SPIFFE transport plane. The ServiceNow agent calls Azure over standard HTTPS.
- Identity is OAuth2-only: ServiceNow OIDC token → Entra exchange.
- **Layer 1 (mTLS) is absent.** The agent authenticates only at Layers 2/3 (RBAC + JWT).
- The ingress proxy must accept unauthenticated TLS connections for this agent (or route through a non-mTLS path).

**Model B: MID Server Agent (SPIRE possible)**

```
Customer Infrastructure
┌──────────────────────────┐           ┌──────────────────────────┐
│  MID Server VM            │           │   BudgetBackend           │
│  ┌────────┐ ┌──────────┐ │   mTLS    │ ┌──────────┐ ┌────────┐ │
│  │ Agent  │→│ SPIFFE   │─┼───────────┼→│ SPIFFE   │→│ Agent  │ │
│  │        │ │ Proxy    │ │  (tunnel) │ │ Proxy    │ │        │ │
│  └────────┘ └──────────┘ │           │ └──────────┘ └────────┘ │
│  ┌────────┐              │           └──────────────────────────┘
│  │ SPIRE  │              │
│  │ Agent  │              │
│  └────────┘              │
└──────────────────────────┘
```

- Full SPIFFE transport plane. The MID Server runs spiffe-proxy + SPIRE Agent.
- SPIRE attestation uses the underlying platform's attestor (wherever the MID Server VM runs).
- Identity is dual-plane: SPIFFE for transport + Entra Agent Identity for authorization.
- Architecturally identical to our Google/AWS model.

### Recommendation

**For PoC:** Model A (ServiceNow platform agent, OAuth2 only) is simpler and demonstrates the ServiceNow integration story without MID Server infrastructure.

**For production:** Model B (MID Server) provides the same dual-plane security as Google/AWS agents. However, it requires customer infrastructure and is more of an on-prem pattern than a SaaS integration.

**Impact on our architecture:** Model A means the `federated_policies` schema and RBAC engine must handle agents that have OAuth2/JWT identity but NO SPIFFE identity at the transport layer. This is a new enforcement model — the existing four-layer stack assumes SPIFFE at Layer 1.

---

## Entra Token Exchange (OAuth2 Layer)

### ServiceNow as OIDC Provider → Entra FIC

ServiceNow can issue OIDC-compliant tokens that Entra accepts via Federated Identity Credentials:

```python
import httpx

# Step 1: Get ServiceNow OIDC token
# This is issued by the ServiceNow instance's OAuth2 provider
# In a scoped app / MID Server context:
snow_token = get_servicenow_oidc_token(
    instance="your-instance.service-now.com",
    client_id="snow-client-id",
    client_secret="snow-client-secret",  # or certificate
    audience="api://AzureADTokenExchange",
)

# Step 2: Exchange for Entra token (same pattern as Google/AWS)
resp = httpx.post(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data={
        "grant_type": "client_credentials",
        "client_id": blueprint_app_id,
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": agent_identity_client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": snow_token,
    },
    timeout=15,
)
```

### ServiceNow Token Acquisition Methods

| Method | Context | Secrets Required | Notes |
|---|---|---|---|
| OAuth2 client credentials | Scoped app / server-side | Client ID + secret on SNOW | Standard OAuth2. SNOW acts as IdP. |
| System OAuth2 token | MID Server | MID Server credentials | The MID Server uses its own auth to get a ServiceNow token |
| User-scoped token | Flow Designer (user context) | Per-user OAuth2 | Carries user delegation — NOT suitable for autonomous agent flows |
| Agent User as SNOW user | Scoped app / Flow Designer | None (user SSO flow) | Entra Agent User registered as SNOW user. Secretless but uses user auth flows. See "Agent User pattern" below. |

### The Secret Problem

Unlike Google (metadata server, no secrets) and AWS (IAM role, no secrets on EC2), **ServiceNow OIDC token acquisition typically requires a client secret or certificate** on the ServiceNow side. This is because ServiceNow is a SaaS platform without platform-managed identity for outbound calls.

**Options to minimize secrets:**
1. **Certificate-based client auth** to the ServiceNow OAuth2 provider (better than shared secrets)
2. **MID Server with platform-managed identity** — the MID Server VM's managed identity handles the upstream credential, and the ServiceNow OAuth2 token is only used for ServiceNow-internal auth
3. **ServiceNow Credential Store** — encrypted storage within the instance (not secretless, but centrally managed)

**Impact on strategy pattern:** The `ServiceNowOIDCProvider.get_upstream_assertion()` implementation may require stored credentials. This differs from `GoogleOIDCProvider` (metadata, no secrets) and `AWSSTSProvider` (IAM role, no secrets on instance). The strategy pattern must accommodate credential-backed providers without assuming all providers are secretless.

### The Agent User Pattern: Secretless ServiceNow via Entra Agent Users

There is a creative path around the client secret problem: **Entra Agent Users**.

Entra Agent Identity supports two identity shapes:
- **Agent Identity** (service principal) — authenticates via `client_credentials` grant. This is what Google and AWS agents use.
- **Agent User** (non-human user object) — authenticates via user-like flows (authorization code, device code, etc.). Designed for "assistive" agent scenarios where the agent acts on behalf of a human.

The insight: if you provision the ServiceNow agent as an **Agent User** in Entra and register that Agent User as a "user" in the ServiceNow instance, then:

1. ServiceNow sees a "user" and issues a user-scoped OIDC token (authorization code flow, no client secret needed on the agent side)
2. The Agent User authenticates through ServiceNow's user login flow (or a configured SSO federation back to Entra)
3. The resulting OIDC token carries the Agent User's `sub` claim
4. The FIC on the Blueprint accepts this token and issues a Blueprint exchange token (Hop 1)
5. Hop 2 produces an Agent Identity token as usual

**Why this works:** ServiceNow already has robust user OAuth2 flows. An Agent User looks like a user to ServiceNow. The token exchange with Entra doesn't care whether the upstream identity is a "real human" or an Agent User. The FIC validates `issuer`, `subject`, and `audience`. The Agent User's `sub` maps to its Entra object ID.

**Why this is experimental:** Agent Users are designed for assistive scenarios (agent acts on behalf of a human, carries user delegation context). Using them for autonomous S2S calls stretches the design intent. The Agent User would authenticate "as" a user on ServiceNow but act autonomously.

**Why people will do it anyway:** It's secretless, works with any SaaS platform that supports user OAuth2 flows, and avoids the client credential management burden. As Agent Identity adoption grows, this pattern will emerge naturally for SaaS-to-Azure integration.

**Impact on our architecture:** If we support Agent Users:
- The `CredentialProvider` strategy pattern needs a `UserFlowProvider` variant that handles authorization code flows (interactive or device code)
- The two-hop exchange stays the same (Agent Users still go through the Blueprint)
- The JWT claims differ slightly (`oid` is a user OID, not a service principal OID)
- CA policies need to handle Agent Users (Entra already supports this in public preview)

**Status:** Interesting future path, not needed for the current PoC. Note for when ServiceNow integration becomes real.

---

## Federated Identity Credential Setup

### FIC Parameters for ServiceNow

| Field | Value | Notes |
|---|---|---|
| `name` | `servicenow-wif` | Human-readable name |
| `issuer` | `https://<instance>.service-now.com` | Per-instance. NOT a global issuer. |
| `subject` | ServiceNow application sys_id or user sys_id | Must match `sub` claim in SNOW token |
| `audiences` | `["api://AzureADTokenExchange"]` | For Agent Identity Blueprint path |

### Instance-Specific Issuer

Unlike Google (`https://accounts.google.com` globally) and AWS Cognito (`https://cognito-identity.amazonaws.com` globally), ServiceNow issuers are **per-instance**:

```
https://acme.service-now.com        ← Acme Corp's instance
https://contoso.service-now.com     ← Contoso's instance
```

This means each customer's ServiceNow instance requires a separate FIC on the Blueprint. Combined with the 20-FIC limit, this constrains multi-tenant ServiceNow deployments.

### 20-FIC Limit Impact

More severe for ServiceNow than Google/AWS because each ServiceNow instance is a separate issuer. If you need to support 20+ ServiceNow instances, you'll hit the FIC limit on a single Blueprint app registration.

**Mitigation:** Use multiple Blueprint app registrations (one per group of ServiceNow instances) or funnel all ServiceNow instances through a single OIDC proxy/broker.

---

## Gotchas and Failure Modes

### 1. No SPIFFE for Platform Agents

ServiceNow platform agents cannot run SPIRE. If you use Model A (platform agent), you need an enforcement path that works without Layer 1 mTLS. The RBAC engine currently assumes a SPIFFE ID is always present (extracted from the mTLS peer certificate).

**Implication for our architecture:** Adding a ServiceNow platform agent would require:
- A non-mTLS inbound path on the target service (separate listener or TLS-only without client certs)
- RBAC evaluation without a SPIFFE ID (match by JWT claims instead)
- This is a significant architecture change — NOT needed for the Google PoC

### 2. Per-Instance OIDC Issuer

Each ServiceNow instance has a unique OIDC issuer URL. Unlike Google/AWS where one FIC covers all workloads from that cloud, ServiceNow requires one FIC per customer instance. Plan for this at the FIC management layer.

### 3. Client Secret Required for Token Acquisition

ServiceNow OAuth2 typically requires a client secret or certificate. The `ServiceNowOIDCProvider` cannot be fully secretless like `GoogleOIDCProvider`. The strategy pattern must handle credential-backed providers.

### 4. JWKS Endpoint Format

ServiceNow's JWKS endpoint (`/api/now/jwt/validate/keys`) may return keys in a non-standard format depending on the instance version. Test OIDC discovery + JWKS validation against the target instance before implementing the FIC.

### 5. Network Connectivity from ServiceNow Platform

ServiceNow platform agents make outbound HTTPS calls. These go through ServiceNow's egress infrastructure (shared IPs). You cannot restrict Azure NSG rules to specific ServiceNow source IPs without ServiceNow's published IP ranges, which change.

### 6. MID Server Is Customer Infrastructure

MID Servers run on customer-managed VMs. The customer is responsible for patching, network config, and SPIRE installation. This is an operational burden not present in the Google/AWS PoC models.

---

## What Generalizes Across Platforms

1. **Hop 0 is the only platform-specific part.** ServiceNow OIDC token replaces Google metadata token or AWS Cognito token.
2. **FIC lives on the Blueprint, not per-agent.** One FIC per ServiceNow instance per Blueprint.
3. **Hops 1 and 2 are identical** across all platforms.
4. **The `CredentialProvider` strategy pattern is the extension point.** `ServiceNowOIDCProvider` implements `get_upstream_assertion(audience)`.
5. **The portal external-agent storage is platform-agnostic.**

**However, ServiceNow introduces a new question:** What happens when there's no SPIFFE transport layer? This is unique to SaaS platforms where you can't install SPIRE. Google and AWS don't have this problem because you control the compute.

---

## ServiceNow-Specific Constraints

1. **SaaS, not IaaS.** You cannot install SPIRE on the ServiceNow platform. This is the fundamental constraint.
2. **Per-instance OIDC issuer** means per-instance FICs. Hits the 20-FIC limit faster.
3. **Client secrets likely required** for OIDC token acquisition. Not secretless like Google/AWS.
4. **Two deployment models** (platform agent vs. MID Server) with different identity and network characteristics.
5. **Model A (platform agent) challenges the four-layer enforcement model.** Layer 1 (mTLS) is absent. The RBAC engine needs to handle JWT-only authentication if we go this route.
6. **MID Server model** is architecturally sound but operationally heavy (customer infrastructure dependency).
7. **Rate limits.** ServiceNow enforces REST API rate limits per instance. Token refresh frequency should respect these limits.

---

## Architectural Decision: Protect the Google Implementation

When implementing the Google agent, ensure these patterns don't close off ServiceNow:

1. **`CredentialProvider.get_upstream_assertion()` should accept optional kwargs** for credential-backed providers (ServiceNow needs `client_secret` or `certificate`). Don't hardcode the interface as "secretless only."

2. **`federated_policies` should NOT require a SPIFFE ID.** If we later add ServiceNow Model A (OAuth2-only, no SPIFFE), the policy entry needs to match by JWT claims or agent name instead of SPIFFE ID. Consider making `spiffe_id` optional in the schema from the start, with a clear validation rule: either `spiffe_id` is required (SPIFFE transport present) or a `jwt_only: true` flag is set (no transport layer, OAuth2 enforcement only).

3. **The portal external-agent storage should include a `transport` field** (e.g., `spiffe` or `https_only`) so the portal knows whether to expect Layer 1 enforcement results for this agent.

4. **Don't assume all agents have SPIFFE IDs in the RBAC engine.** The `findCallerPolicy()` for JWT-only callers would match by JWT `oid` or `appid` claims instead of SPIFFE ID. This is NOT needed for the Google PoC but should not be structurally blocked.

---

## References

- [ServiceNow OIDC Provider](https://docs.servicenow.com/bundle/vancouver-platform-security/page/administer/security/concept/openid-connect.html)
- [ServiceNow OAuth2](https://docs.servicenow.com/bundle/vancouver-platform-security/page/administer/security/concept/c_OAuthApplications.html)
- [ServiceNow MID Server](https://docs.servicenow.com/bundle/vancouver-it-operations-management/page/product/mid-server/concept/mid-server-landing.html)
- [Entra Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Entra FIC assertion format](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials#assertion-format)
