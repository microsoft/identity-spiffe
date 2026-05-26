# Amazon Web Services Federation — Platform Learnings

> **Purpose:** Reference for implementing SPIFFE + Entra federation with AWS workloads. Load this file before working on AWS-hosted agents, `aws_iid` attestation, or AWS-to-Entra token exchange.
>
> **Last updated:** 2026-04-02
> **Sources:** SPIRE plugin docs, Entra WIF docs, AWS OIDC/STS docs
> **Related:** `docs/platform-learnings/Google-Cloud-Federation.md` (same structure for cross-reference)

---

## Table of Contents

1. [Identity Primitives](#identity-primitives)
2. [SPIFFE Transport Layer](#spiffe-transport-layer)
3. [Entra Token Exchange (OAuth2 Layer)](#entra-token-exchange-oauth2-layer)
4. [Federated Identity Credential Setup](#federated-identity-credential-setup)
5. [Gotchas and Failure Modes](#gotchas-and-failure-modes)
6. [What Generalizes Across Platforms](#what-generalizes-across-platforms)
7. [AWS-Specific Constraints](#aws-specific-constraints)
8. [References](#references)

---

## Identity Primitives

AWS workloads identify themselves through several mechanisms. For SPIFFE + Entra integration, two matter:

### EC2 Instance Identity Document (IID)

Every EC2 instance can request a signed Instance Identity Document from the Instance Metadata Service (IMDS):

```bash
# IMDSv2 (recommended, requires session token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/dynamic/instance-identity/document
```

**IID contents:**
- `accountId`: AWS account ID
- `instanceId`: EC2 instance ID (e.g., `i-0b22a22eec53b9321`)
- `region`: AWS region
- `availabilityZone`: AZ
- `imageId`: AMI ID
- `instanceType`: instance type

The IID is signed by AWS. SPIRE uses this for `aws_iid` attestation.

**IMDSv1 vs IMDSv2:** IMDSv1 uses simple GET requests. IMDSv2 requires a PUT to get a session token first (defense against SSRF). SPIRE supports both. Prefer IMDSv2.

### AWS STS (Security Token Service) for OIDC

For Entra federation, AWS workloads obtain OIDC tokens through AWS STS via IAM Roles Anywhere or Amazon Cognito. The key mechanism:

1. EC2 instance role or EKS pod identity provides AWS credentials
2. AWS STS `AssumeRoleWithWebIdentity` or Cognito issues an OIDC-compatible token
3. The OIDC token is exchanged with Entra via FIC

**For EKS pods:** EKS natively projects OIDC tokens via the EKS OIDC provider:
```
https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>
```

**For EC2 instances:** No native OIDC token issuer exists. Options:
- Use Amazon Cognito as an OIDC intermediary
- Use STS `GetCallerIdentity` + a custom OIDC wrapper
- Use IAM Roles Anywhere with X.509 certificates (SPIFFE SVID is valid)

### IAM Roles Anywhere (SPIFFE SVID → AWS Credentials)

AWS IAM Roles Anywhere accepts X.509 certificates (including SPIFFE SVIDs) as authentication credentials. This enables a bidirectional pattern:

```
SPIFFE SVID → IAM Roles Anywhere → AWS IAM Role → AWS credentials
```

This is relevant if the AWS agent needs to call AWS services, but NOT directly relevant for Entra token exchange (Entra doesn't accept AWS IAM credentials directly).

---

## SPIFFE Transport Layer

### SPIRE Node Attestation: `aws_iid`

The `aws_iid` (AWS Instance Identity Document) NodeAttestor is the production-grade option for EC2 instances. It uses the IMDS to obtain a signed IID and presents it to the SPIRE Server during node attestation.

**Server-side configuration:**

```hcl
NodeAttestor "aws_iid" {
    plugin_data {
        # Minimal config — no AWS credentials needed if SPIRE Server
        # has ec2:DescribeInstances permission.
        # If cross-account, use assume_role.
    }
}
```

**Required IAM permissions on the SPIRE Server:**

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:DescribeInstances", "iam:GetInstanceProfile"],
        "Resource": "*"
    }]
}
```

**Agent-side configuration:**

```hcl
NodeAttestor "aws_iid" {
    plugin_data {}
}
```

**Agent SPIFFE ID format:**

```
spiffe://<trust-domain>/spire/agent/aws_iid/<account-id>/<region>/<instance-id>
```

**Selectors available:**

| Selector | Example |
|---|---|
| `aws_iid:account_id` | `aws_iid:account_id:123456789012` |
| `aws_iid:region` | `aws_iid:region:us-east-1` |
| `aws_iid:az` | `aws_iid:az:us-east-1a` |
| `aws_iid:instance:id` | `aws_iid:instance:id:i-0b22a22eec53b9321` |
| `aws_iid:image:id` | `aws_iid:image:id:ami-5fb8c835` |
| `aws_iid:iamrole` | `aws_iid:iamrole:arn:aws:iam::123456789012:role/SpireAgent` |
| `aws_iid:sg:id` | `aws_iid:sg:id:sg-01234567` |
| `aws_iid:tag:key` | `aws_iid:tag:name:aim-agent` |

**Security model:** TOFU, same as `gcp_iit`. A given EC2 instance can only attest once. Also includes an anti-tampering check: verifies the root volume has not been detached (`skip_block_device = false` by default).

**Cross-account attestation:** If the SPIRE Server runs in a different AWS account than the agent, use `assume_role` in the server config.

**EKS integration:** `aws_iid` supports `validate_eks_cluster_membership` to verify that the attesting instance belongs to a specific EKS cluster's node group.

### SPIFFE Federation with AWS

Identical to Google federation. Both SPIRE servers exchange bundle endpoints:

```bash
# On Azure SPIRE Server:
spire-server federation create \
    -trustDomain aws.aim.microsoft.com \
    -bundleEndpointURL https://<aws-spire-ip>:8443 \
    -bundleEndpointProfile https_web

# On AWS SPIRE Server:
spire-server federation create \
    -trustDomain aim.microsoft.com \
    -bundleEndpointURL https://<azure-spire-ip>:8443 \
    -bundleEndpointProfile https_web
```

The `federated_policies` schema in the RBAC YAML handles AWS agents identically to Google agents — just a different `trust_domain` value.

---

## Entra Token Exchange (OAuth2 Layer)

### The AWS Challenge: No Native OIDC Token for EC2

Unlike Google (which gives every GCE VM an OIDC identity token via metadata), **AWS EC2 does not issue OIDC tokens natively**. This is the single biggest difference between GCP and AWS for Entra WIF.

**Options for obtaining an OIDC-compatible token from AWS:**

| Option | Compute Target | OIDC Issuer | Complexity |
|---|---|---|---|
| **Amazon Cognito Identity Pool** | Any (EC2, ECS, Lambda) | `cognito-identity.amazonaws.com` | Medium. Requires Cognito setup. |
| **EKS OIDC Provider** | EKS pods only | `oidc.eks.<region>.amazonaws.com/id/<cluster-id>` | Low (if already on EKS). |
| **SPIFFE SVID → Entra FIC** | Any with SPIRE | N/A (X.509), use SPIFFE as issuer | Experimental. Entra supports SPIFFE SVIDs as federated credentials. |
| **Custom OIDC endpoint** | Any | Self-hosted | High complexity, not recommended. |
| **STS GetCallerIdentity** | Any | Not OIDC-compatible | Cannot be used with Entra FIC directly. |

### Recommended Path for EC2: Amazon Cognito

For EC2 instances (no EKS), the recommended approach is Amazon Cognito Identity Pool:

1. Create a Cognito Identity Pool with "unauthenticated identities" enabled or backed by an IAM role
2. EC2 instance uses its IAM role to get Cognito OIDC token
3. OIDC token is exchanged with Entra via FIC

```python
import boto3
import httpx

cognito = boto3.client("cognito-identity", region_name="us-east-1")

# Get Cognito identity
identity = cognito.get_id(IdentityPoolId="us-east-1:pool-id")
cognito_id = identity["IdentityId"]

# Get OIDC token
token_response = cognito.get_open_id_token(IdentityId=cognito_id)
aws_oidc_token = token_response["Token"]

# Exchange for Entra token (same pattern as Google)
resp = httpx.post(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data={
        "grant_type": "client_credentials",
        "client_id": blueprint_app_id,
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": agent_identity_client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": aws_oidc_token,
    },
    timeout=15,
)
```

### Alternative Path: EKS OIDC (if on EKS)

If the AWS agent runs on EKS, the projected service account token is directly usable:

```python
# EKS automatically mounts a projected token at this path
with open("/var/run/secrets/eks.amazonaws.com/serviceaccount/token") as f:
    eks_token = f.read()

# Exchange with Entra directly
# FIC issuer = "https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>"
# FIC subject = "<namespace>:<service-account-name>"
```

### Alternative Path: SPIFFE SVID as Federated Credential

Entra WIF explicitly supports SPIFFE SVIDs as federated credentials. The SPIFFE SVID (X.509 certificate) can be used as a `client_assertion` with `client_assertion_type` set to `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. However, this path uses the SVID's JWT form (not X.509), which requires the SPIRE agent to issue a JWT-SVID alongside the X.509-SVID.

This is still experimental and adds complexity. The Cognito path is more proven.

---

## Federated Identity Credential Setup

### FIC Parameters for AWS (Cognito path)

| Field | Value | Notes |
|---|---|---|
| `name` | `aws-cognito-wif` | Human-readable name |
| `issuer` | `https://cognito-identity.amazonaws.com` | Cognito OIDC issuer |
| `subject` | Cognito Identity ID (e.g., `us-east-1:12345678-abcd-...`) | From `get_id()` response |
| `audiences` | `["api://AzureADTokenExchange"]` | For Agent Identity Blueprint path |

### FIC Parameters for AWS (EKS path)

| Field | Value | Notes |
|---|---|---|
| `name` | `aws-eks-wif` | Human-readable name |
| `issuer` | `https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>` | Per-cluster OIDC provider |
| `subject` | `system:serviceaccount:<namespace>:<sa-name>` | K8s service account |
| `audiences` | `["api://AzureADTokenExchange"]` | For Agent Identity Blueprint path |

### 20-FIC Limit Impact

Same as Google: each Blueprint app registration supports max 20 FICs. With Google + AWS + future platforms, plan for one FIC per cloud per agent type, not one FIC per agent instance.

---

## Gotchas and Failure Modes

### 1. No Native OIDC Token on EC2

EC2 instances do NOT issue OIDC tokens from the metadata service (unlike GCE). You must use an intermediary (Cognito, custom endpoint, or SPIFFE SVID). This makes the `AWSSTSProvider` (our strategy pattern) more complex than `GoogleOIDCProvider`.

**Impact on our strategy pattern:** The `AWSSTSProvider.get_upstream_assertion()` method has two sub-steps (get IAM credentials -> get Cognito OIDC token) vs. Google's single metadata call.

### 2. IMDSv2 Hop Limit

IMDSv2 has a default hop limit of 1 (HTTP PUT TTL). If the SPIRE agent runs in a Docker container on EC2, the container network adds a hop. You may need `--metadata-options HttpPutResponseHopLimit=2` on the EC2 instance.

### 3. Cross-Account SPIRE Server Needs `assume_role`

If the SPIRE Server runs in a different AWS account than the agent instances, the `aws_iid` server plugin must be configured with `assume_role` pointing to a role in the agent's account with `ec2:DescribeInstances` permission.

### 4. Security Group Changes Can Break SPIRE

AWS security groups are stateful but changes take effect immediately. If an SG update removes the rule allowing SPIRE Agent -> SPIRE Server (port 8081), in-flight connections are preserved but new attestation attempts fail.

### 5. Cognito Identity Pool Setup Is Non-Trivial

Cognito Identity Pools have their own IAM role mappings, auth/unauth roles, and identity lifecycle. Getting the trust relationship right between the Cognito pool, the EC2 instance role, and the Entra FIC requires careful mapping.

### 6. EKS OIDC Provider Thumbprint Rotation

EKS rotates the OIDC provider's signing key periodically. Entra downloads the JWKS from the OIDC discovery endpoint. If the endpoint is unreachable during rotation, token validation fails. Entra caches only the first 100 signing keys.

---

## What Generalizes Across Platforms

Same as documented in `Google-Cloud-Federation.md`:

1. **Hop 0 is the only platform-specific part.** Cognito OIDC token (AWS) replaces metadata token (Google).
2. **FIC lives on the Blueprint, not per-agent.** One FIC per platform.
3. **SPIFFE federation is symmetric.** Bundle exchange is identical.
4. **`federated_policies` schema is platform-agnostic.**
5. **The `CredentialProvider` strategy pattern is the extension point.** `AWSSTSProvider` implements `get_upstream_assertion(audience)`.
6. **The portal external-agent storage is platform-agnostic.**

---

## AWS-Specific Constraints

1. **EC2 has no native OIDC token** — requires Cognito or EKS OIDC intermediary. This is the primary complexity difference from Google.
2. **`aws_iid` requires IAM permissions** on the SPIRE Server (`ec2:DescribeInstances`). Google's `gcp_iit` is simpler (no server-side API call required for basic attestation).
3. **IMDSv2 hop limit** can break containerized SPIRE agents. Remember to set `HttpPutResponseHopLimit=2`.
4. **Cross-account attestation** requires `assume_role` configuration on the SPIRE Server.
5. **Lambda and Fargate** do not support `aws_iid` attestation (no IMDS access). Similar to Google Cloud Run. Join tokens or custom attestors are needed.
6. **AWS has rich selector support** — security groups, instance tags, IAM roles. More granular than Google's selectors.
7. **VPN options:** AWS offers VPN Gateway, Transit Gateway, and VPC Peering. Transit Gateway is the most scalable if connecting multiple accounts.

---

## References

- [SPIRE `aws_iid` server plugin](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_aws_iid.md)
- [SPIRE `aws_iid` agent plugin](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_nodeattestor_aws_iid.md)
- [Entra Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Entra + AWS federation walkthrough](https://blog.identitydigest.com/azuread-federate-aws/)
- [AWS IMDSv2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Amazon Cognito Identity Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html)
- [EKS OIDC Provider](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html)
- [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
