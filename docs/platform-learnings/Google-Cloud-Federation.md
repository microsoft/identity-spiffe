# Google Cloud Federation — Platform Learnings

> **Purpose:** Reference for implementing SPIFFE + Entra federation with Google Cloud workloads. Load this file before working on GCP-hosted agents, `gcp_iit` attestation, or Google-to-Entra token exchange.
>
> **Last updated:** 2026-04-02
> **Sources:** SPIRE plugin docs, Entra WIF docs, GCP OIDC docs, implementation PoC analysis
> **Related:** `docs/architecture/next-google-cloud-agent-federation.md`

---

## Table of Contents

1. [Identity Primitives](#identity-primitives)
2. [SPIFFE Transport Layer](#spiffe-transport-layer)
3. [Entra Token Exchange (OAuth2 Layer)](#entra-token-exchange-oauth2-layer)
4. [Federated Identity Credential Setup](#federated-identity-credential-setup)
5. [Gotchas and Failure Modes](#gotchas-and-failure-modes)
6. [What Generalizes Across Platforms](#what-generalizes-across-platforms)
7. [GCP-Specific Constraints](#gcp-specific-constraints)
8. [References](#references)

---

## Identity Primitives

Google Cloud workloads identify themselves through two mechanisms:

### GCE Instance Identity Token

Every GCE VM can request an **instance identity token** from the metadata server. This is a Google-signed JWT containing the instance's identity.

```bash
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=<audience>"
```

**Token claims:**
- `iss`: `https://accounts.google.com`
- `sub`: GCP service account **numeric unique ID** (NOT email)
- `aud`: whatever audience you request (set to match your FIC)
- `azp`: service account email
- `google.compute_engine.instance_id`: GCE instance ID
- `google.compute_engine.project_id`: GCP project ID
- `google.compute_engine.zone`: availability zone

**Key property:** This token is available to any process on the VM. It does not require special permissions beyond having a service account attached to the VM.

### Google Service Account

Every GCP workload runs under a service account. The service account has:
- An **email** (e.g., `gcp-agent@project.iam.gserviceaccount.com`) — human-readable identifier
- A **numeric unique ID** (e.g., `100330114984210007855`) — the actual `sub` claim in OIDC tokens

**Critical distinction:** The `sub` claim in Google OIDC tokens is the **numeric unique ID**, not the email. This matters for FIC configuration (see Gotchas).

### google.auth Library

The `google-auth` Python library provides a unified API for obtaining identity tokens across GCE, Cloud Run, GKE, and local development:

```python
import google.auth
from google.auth.transport.requests import Request

credentials, _ = google.auth.default()
credentials = credentials.with_target_audience("api://my-app")
credentials.refresh(Request())
token = credentials.token  # Google-signed JWT
```

This auto-detects the runtime (IMDS for GCE, metadata service for Cloud Run/GKE) so the same code works across GCP deployment targets. Requires `pip install google-auth`.

---

## SPIFFE Transport Layer

### SPIRE Node Attestation: `gcp_iit`

The `gcp_iit` (GCP Instance Identity Token) NodeAttestor is the production-grade option for GCE VMs. It uses the GCE metadata server to obtain a Google-signed identity token and presents it to the SPIRE Server during node attestation.

**Server-side configuration:**

```hcl
NodeAttestor "gcp_iit" {
    plugin_data {
        projectid_allow_list = ["my-gcp-project-id"]
        use_instance_metadata = true  # enables richer selectors
    }
}
```

**Agent-side configuration:**

```hcl
NodeAttestor "gcp_iit" {
    plugin_data {}
}
```

**Requirements:**
- The GCE VM must have a service account attached (`--service-account` flag)
- The SPIRE Server must be able to validate Google's OIDC signing keys (outbound HTTPS to `accounts.google.com`)
- If `use_instance_metadata = true`, the SPIRE Server needs a service account with `compute.instances.get` IAM permission

**Agent SPIFFE ID format:**

```
spiffe://<trust-domain>/spire/agent/gcp_iit/<project-id>/<instance-id>
```

Customizable via `agent_path_template` using Go text/template.

**Selectors available:**

| Selector | Example |
|---|---|
| `gcp_iit:project-id` | `gcp_iit:project-id:my-project-123` |
| `gcp_iit:zone` | `gcp_iit:zone:us-central1-a` |
| `gcp_iit:instance-name` | `gcp_iit:instance-name:gcp-budget-agent` |
| `gcp_iit:tag` | `gcp_iit:tag:aim-agent` (requires `use_instance_metadata`) |
| `gcp_iit:sa` | `gcp_iit:sa:gcp-agent@proj.iam.gserviceaccount.com` (requires `use_instance_metadata`) |

**Security model:** Trust On First Use (TOFU). A given GCE instance can only attest once. Subsequent attempts are rejected. This prevents non-agent code from impersonating the agent.

**Cloud Run limitation:** `gcp_iit` requires the GCE metadata server (IMDS). Cloud Run does not expose IMDS. For Cloud Run, you would need join tokens or a custom attestor. This is one reason GCE is recommended for the PoC.

### SPIFFE Federation Model

SPIFFE federation between a GCP SPIRE Server and the Azure SPIRE Server uses **bundle endpoint exchange**:

```
Azure SPIRE Server                          GCP SPIRE Server
(td: aim.microsoft.com)                     (td: gcp.aim.microsoft.com)
       │                                           │
       ├── Exposes bundle on :8443 ──────────────►│
       │                                   Fetches Azure bundle
       │◄────────────────────────── Exposes bundle on :8443
  Fetches GCP bundle                               │
       │                                           │
  Now trusts SVIDs from                    Now trusts SVIDs from
  gcp.aim.microsoft.com                    aim.microsoft.com
```

**Configuration on Azure SPIRE Server:**
```bash
spire-server federation create \
    -trustDomain gcp.aim.microsoft.com \
    -bundleEndpointURL https://<gcp-spire-ip>:8443 \
    -bundleEndpointProfile https_web
```

**Configuration on GCP SPIRE Server:**
```bash
spire-server federation create \
    -trustDomain aim.microsoft.com \
    -bundleEndpointURL https://<azure-spire-ip>:8443 \
    -bundleEndpointProfile https_web
```

**Bundle refresh:** Default is 5 minutes. Configurable. After initial setup, wait up to 5 minutes for the first bundle exchange before testing mTLS.

**Workload entry registration (`-federatesWith`):**
```bash
spire-server entry create \
    -parentID spiffe://gcp.aim.microsoft.com/spire/agent/gcp_iit/<project>/<instance> \
    -spiffeID spiffe://gcp.aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid> \
    -selector unix:uid:0 \
    -federatesWith aim.microsoft.com
```

The `-federatesWith` flag is **critical**. Without it, the SVID won't include the federated trust bundle, and mTLS to the Azure side will fail with a certificate validation error.

---

## Entra Token Exchange (OAuth2 Layer)

### Two Paths: Direct FIC vs. Agent Identity Two-Hop

**Path 1: Direct FIC (standard WIF)**

Used by most Google-to-Entra integrations. One-hop exchange:

```
Google OIDC token → Entra token endpoint → access token
```

FIC on an app registration. Token exchange uses `client_credentials` grant with `client_assertion`.

**Path 2: Agent Identity Two-Hop (Identity Research for Agent Management Using SPIFFE model)**

Used by our platform. Two-hop exchange through the Blueprint:

```
Google OIDC token → Blueprint exchange (Hop 1) → Agent Identity token (Hop 2)
```

FIC on the **Blueprint** (not the per-agent identity). The `fmi_path` parameter in Hop 1 routes the exchange to the correct Agent Identity.

**Our plan uses Path 2** because the whole point is demonstrating Agent Identity. But the FIC + Google OIDC exchange mechanics are identical in both paths — only the FIC target (app reg vs. Blueprint) and the grant parameters differ.

### Token Exchange Implementation

```python
# Hop 0: Get Google OIDC token from metadata server
gcp_token = httpx.get(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
    params={"audience": "api://AzureADTokenExchange"},
    headers={"Metadata-Flavor": "Google"},
    timeout=5,
).text

# Hop 1: Exchange for Blueprint token
resp = httpx.post(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data={
        "grant_type": "client_credentials",
        "client_id": blueprint_app_id,
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": agent_identity_client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": gcp_token,
    },
    timeout=15,
)
t1 = resp.json()["access_token"]

# Hop 2: Exchange for Agent Identity token (same as Azure agents)
resp = httpx.post(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data={
        "grant_type": "client_credentials",
        "client_id": agent_identity_client_id,
        "scope": f"api://{blueprint_app_id}/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": t1,
    },
    timeout=15,
)
t2 = resp.json()["access_token"]
```

**MSAL Python does not support this flow.** MSAL lacks the `WithClientAssertion` callback needed for FIC token exchange. Use raw HTTP. See hard-won-learnings #31.

---

## Federated Identity Credential Setup

### FIC Parameters for Google

| Field | Value | Notes |
|---|---|---|
| `name` | `gcp-workload-identity` | Human-readable name |
| `issuer` | `https://accounts.google.com` | Google OIDC issuer |
| `subject` | Numeric unique ID (e.g., `100330114984210007855`) | **NOT the email.** See Gotchas. |
| `audiences` | `["api://AzureADTokenExchange"]` | For Agent Identity Blueprint path |

**Where the FIC lives:** On the **Blueprint** app registration (not per-agent identity). This matches the existing Agent Identity model.

### Creation via Graph API

```bash
az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/applications/$BLUEPRINT_OBJ_ID/federatedIdentityCredentials" \
    --body '{
        "name": "gcp-budget-reader-wif",
        "issuer": "https://accounts.google.com",
        "subject": "$GCP_SA_UNIQUE_ID",
        "audiences": ["api://AzureADTokenExchange"],
        "description": "GCP budget reader workload identity federation"
    }'
```

### 20-FIC Limit

Each Entra app registration supports a maximum of **20 Federated Identity Credentials**. If you create many agent identities each with a separate GCP service account, you can hit this limit on the Blueprint.

**Mitigation for scale:** Use one GCP service account per cloud (not per agent) and differentiate agents at the Agent Identity level.

---

## Gotchas and Failure Modes

### 1. FIC Subject Must Be Numeric Unique ID

**Error:** `AADSTS70021: No matching federated identity record found for presented assertion subject`

**Cause:** FIC `subject` set to GCP SA email instead of numeric unique ID.

**Fix:**
```bash
gcloud iam service-accounts describe $SA_EMAIL --format 'value(uniqueId)'
# Returns: 100330114984210007855 (use this, not the email)
```

### 2. Metadata Server Unavailable on Cloud Run

Cloud Run does not expose the Instance Identity Token via the standard IMDS path. The `google.auth` library handles this transparently via the Cloud Run metadata service, but SPIRE's `gcp_iit` attestor does NOT work on Cloud Run.

**Implication:** Cloud Run requires join tokens for SPIRE attestation, not `gcp_iit`.

### 3. GCE VM Must Have Service Account

If the GCE VM was created without `--service-account`, the metadata server returns a 404 for identity token requests. `gcp_iit` attestation will also fail.

**Verify:**
```bash
gcloud compute instances describe <vm> --format='get(serviceAccounts[0].email)'
```

### 4. Case-Sensitive FIC Fields

Entra FIC matching is **case-sensitive** for `issuer`, `subject`, and `audience`. Google's issuer URL is `https://accounts.google.com` (no trailing slash). Getting the case or trailing slash wrong causes silent match failure.

### 5. `gcp_iit` Is TOFU (Trust On First Use)

A given GCE instance can only attest once. If you need to re-attest (e.g., after SPIRE Agent restart), you must either:
- Delete the agent entry on the SPIRE Server and let it re-attest
- Use a new GCE instance

This is a SPIRE security mechanism, not a bug. Unlike join tokens (which are single-use but the mechanism is obvious), TOFU failures can be confusing because the agent silently fails to attest.

---

## What Generalizes Across Platforms

These patterns apply to Google, AWS, and ServiceNow (and any future platform):

1. **Hop 0 is the only platform-specific part.** The upstream credential acquisition (metadata server call) changes per platform. Hops 1 and 2 (Blueprint exchange and Agent Identity exchange) are identical.

2. **FIC lives on the Blueprint, not per-agent.** One FIC per platform on the Blueprint. Multiple agents from the same platform use the same FIC (they share the service account identity) but get different Agent Identity tokens via `fmi_path`.

3. **SPIFFE federation is symmetric.** Both SPIRE servers exchange bundles. The configuration is the same regardless of which cloud is on the other end.

4. **`federated_policies` schema is platform-agnostic.** The `trust_domain` field on each entry handles any foreign domain. No Google-specific code in the RBAC engine.

5. **The `CredentialProvider` strategy pattern is the extension point.** `AzureMIProvider`, `GoogleOIDCProvider`, `AWSSTSProvider`, `ServiceNowOIDCProvider` all implement `get_upstream_assertion(audience)` and the rest is shared.

6. **The portal external-agent storage is platform-agnostic.** It stores `invoke_url` and display name. No cloud-specific fields.

---

## GCP-Specific Constraints

These are GCP-only considerations that don't apply to AWS or ServiceNow:

1. **`gcp_iit` only works on GCE VMs** (not Cloud Run, not GKE pods, not Cloud Functions). For other GCP compute, use join tokens or contributor-level SPIRE plugin work.

2. **Google OIDC issuer is always `https://accounts.google.com`** regardless of project, region, or service account. This simplifies FIC configuration but means you can't scope FIC trust to a specific GCP project via the issuer field alone.

3. **Google identity tokens have a 1-hour default TTL.** Token caching should respect `exp` claims.

4. **GCE VMs require explicit service account attachment.** Default compute service account works but production should use a dedicated SA with minimal permissions.

---

## References

- [SPIRE `gcp_iit` server plugin](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_gcp_iit.md)
- [SPIRE `gcp_iit` agent plugin](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_nodeattestor_gcp_iit.md)
- [Entra Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [GCE Instance Identity Tokens](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)
- [Entra + GCP federation walkthrough](https://blog.identitydigest.com/azuread-federate-gcp/)
- `docs/architecture/next-google-cloud-agent-federation.md` — implementation plan
- `docs/runbooks/hard-won-learnings.md` — #30 (FIC subject), #31 (MSAL), #32 (container modes)
