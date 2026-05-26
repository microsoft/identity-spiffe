# GitHub Actions Federation — Platform Learnings

> **Purpose:** Reference for implementing SPIFFE + Entra federation with GitHub Actions workloads. Load this file before working on GitHub-hosted agents, OIDC token exchange, or Flexible FIC configuration.
>
> **Last updated:** 2026-04-19
> **Sources:** GitHub OIDC docs, Entra FIC docs, Azure Flexible FIC preview docs
> **Related:** `docs/architecture/next-github-actions-agent-federation.md`

---

## Table of Contents

1. [Identity Primitives](#identity-primitives)
2. [SPIFFE Transport Layer](#spiffe-transport-layer)
3. [Entra Token Exchange (OAuth2 Layer)](#entra-token-exchange-oauth2-layer)
4. [Flexible Federated Identity Credential](#flexible-federated-identity-credential)
5. [Gotchas and Failure Modes](#gotchas-and-failure-modes)
6. [What Generalizes Across Platforms](#what-generalizes-across-platforms)
7. [GitHub-Specific Constraints](#github-specific-constraints)
8. [References](#references)

---

## Identity Primitives

GitHub Actions workflows identify themselves through OIDC tokens.

### GitHub Actions OIDC Token

Any workflow with `permissions: id-token: write` can request an OIDC token from GitHub's token endpoint. This is a GitHub-signed JWT.

```bash
curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange"
```

**Response format:** JSON `{"value": "<jwt>"}` (NOT plain text like Google).

**Token claims (signed):**
- `iss`: `https://token.actions.githubusercontent.com`
- `sub`: `repo:<owner>/<repo>:ref:refs/heads/<branch>` or `repo:<owner>/<repo>:environment:<env>`
- `aud`: configurable (set to match FIC audience)
- `repository`: full repo name (e.g., `microsoft/identity-spiffe`)
- `repository_owner`: org name (e.g., `microsoft`)
- `ref`: git ref (e.g., `refs/heads/main`)
- `sha`: commit SHA
- `workflow`: workflow name
- `job_workflow_ref`: stable workflow reference (use for RBAC)
- `run_id`: workflow run ID
- `runner_environment`: `github-hosted` or `self-hosted`

**Key property:** The `sub` claim format is determined by the workflow trigger and context. It includes the org, repo, and ref — which is what Flexible FIC matches against.

---

## SPIFFE Transport Layer

Unlike Google (which needs a separate trust domain and SPIRE federation), the GitHub runner lives in the Azure VNet and joins the existing SPIRE mesh.

- **Trust domain:** `aim.microsoft.com` (same as Azure agents)
- **SPIFFE ID:** `spiffe://aim.microsoft.com/agent/github-budget-reader`
- **No SPIRE federation needed** — same SPIRE server, same VNet
- **No VPN needed** — runner is an Azure VM

This is simpler than Google because there's no cross-cloud networking.

---

## Entra Token Exchange (OAuth2 Layer)

Same two-hop exchange as Google, different Hop 0:

1. **Hop 0:** Fetch GitHub OIDC token from `ACTIONS_ID_TOKEN_REQUEST_URL`
2. **Hop 1:** Exchange OIDC token for Blueprint exchange token (T1) via FIC
3. **Hop 2:** Exchange T1 for Agent Identity token (T2)

`TOKEN_SOURCE=github_oidc` selects `GitHubOIDCProvider` in the credential strategy pattern.

---

## Flexible Federated Identity Credential

### The FIC Scaling Problem

Azure limits you to **20 FICs per app registration**. With standard FICs (exact subject match), each repo needs its own FIC. At 21 repos, you hit the wall.

### Identity Research for Agent Management Using SPIFFE's Solution

Identity Research for Agent Management Using SPIFFE uses a **single Flexible FIC** on the Agent Identity Blueprint with `claimsMatchingExpression`:

```json
{
  "name": "github-actions-federation",
  "issuer": "https://token.actions.githubusercontent.com",
  "claimsMatchingExpression": {
    "value": "claims['sub'] matches 'repo:microsoft/*'",
    "languageVersion": 1
  },
  "audiences": ["api://AzureADTokenExchange"]
}
```

This trusts ALL repos in the `microsoft` org with ONE FIC. Per-repo authorization is handled by Identity Research for Agent Management Using SPIFFE's RBAC engine (`required_tags` on rules), not by FIC proliferation.

**IMPORTANT:** `claimsMatchingExpression` and `subject` are **mutually exclusive**. You cannot set both. Flexible FIC requires the Azure preview feature.

### Created via Graph API

```bash
az rest --method POST \
  --uri "https://graph.microsoft.com/beta/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
  --body '<json above>'
```

---

## Gotchas and Failure Modes

### 1. Flexible FIC Not Available

**Error:** `BadRequest` or `unknown property` when creating FIC with `claimsMatchingExpression`.

**Cause:** The Flexible FIC feature is in Azure preview and not enabled in your tenant.

**Fix:** Enable the preview, or fall back to a standard FIC with exact subject for one repo.

### 2. `claimsMatchingExpression` vs `subject`

**Error:** `BadRequest: Cannot specify both subject and claimsMatchingExpression`.

**Cause:** The two FIC matching modes are mutually exclusive.

**Fix:** Use `claimsMatchingExpression` only (no `subject` field).

### 3. GitHub OIDC Response is JSON, Not Text

**Error:** Token exchange fails silently or returns garbled data.

**Cause:** GitHub's OIDC endpoint returns `{"value": "<jwt>"}` (JSON). Google's metadata server returns plain text. If you parse it as text, you get the JSON wrapper, not the JWT.

**Fix:** Parse with `resp.json()["value"]`, not `resp.text`.

### 4. Forked PR OIDC Tokens Don't Match Org Wildcard

**Expected behavior:** A forked PR from `attacker/evil-fork` gets subject `repo:attacker/evil-fork:ref:refs/pull/N/merge`. The wildcard `repo:microsoft/*` correctly rejects it.

This is a security feature, not a bug.

### 5. `ACTIONS_ID_TOKEN_REQUEST_URL` Not Available

**Error:** `GitHubOIDCProvider` returns None, logs "GitHub Actions OIDC not available."

**Cause:** The workflow doesn't have `permissions: id-token: write`.

**Fix:** Add the permission to the workflow YAML.

### 6. Self-Hosted Runner Required for SPIFFE

GitHub-hosted runners don't have SPIRE agents. You must use a self-hosted runner provisioned with `deploy.sh --github` for the full 5-layer demo.

---

## What Generalizes Across Platforms

(Same as Google — see `Google-Cloud-Federation.md` "What Generalizes" section.)

1. **Hop 0 is the only platform-specific part.**
2. **FIC lives on the Blueprint, not per-agent.** GitHub goes further: Flexible FIC on the Blueprint + RBAC handles per-repo auth.
3. **`federated_policies` schema is platform-agnostic.**
4. **The `CredentialProvider` strategy pattern is the extension point.** `GitHubOIDCProvider` joins `AzureMIProvider` and `GoogleOIDCProvider`.
5. **The portal external-agent storage is platform-agnostic.**

---

## GitHub-Specific Constraints

1. **Flexible FIC is preview.** The `add-github-agent.sh` script fails closed if the feature isn't available.
2. **Self-hosted runners are required** for SPIFFE mesh participation. GitHub-hosted runners can't run SPIRE agents.
3. **Runner registration tokens expire in 1 hour.** The `deploy.sh --github` script acquires them just-in-time via `gh api`.
4. **Custom Entra claims** carry GitHub provenance (repo, workflow, ref, sha) inside the JWT for tamper-proof RBAC tag evaluation.

---

## References

- [GitHub OIDC — About security hardening](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Configuring OIDC in Azure](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- [Flexible Federated Identity Credentials (preview)](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials)
- [Entra Agent Identity — Request tokens](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/autonomous-agent-request-tokens)

## Deployment Checklist

Use placeholders for public examples. A deployed environment should have:

- Runner VM: `github-runner` in `rg-<env>`
- GitHub Actions runner: `identity-spiffe-runner-github`, online, labels: `self-hosted,identity-spiffe-runner,Linux,X64`
- SPIRE agent: attested, workload entry registered
- `spiffe-proxy`: running on `127.0.0.1:8080`
- Entra Agent Identity: `github-budget-reader` with a deployment-specific object ID
- Flexible FIC: `claims['sub'] matches 'repo:<org>/*'`
- `Budget.Read` role: assigned
- RBAC policy: `github-budget-reader` federated entry updated with the deployed agent ID

To complete an end-to-end validation, trigger the workflow from the GitHub Actions UI or run:

```bash
gh workflow run "Identity Research for Agent Management Using SPIFFE Budget Check"
```
