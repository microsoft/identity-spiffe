# GitHub Actions Agent Federation — HOWTO

Onboard a GitHub Actions-hosted agent (`github-budget-reader`) that calls the Azure-side `budget-backend` through the same five-layer enforcement as domestic agents: **mTLS transport → SPIFFE identity → Entra JWT → RBAC policy → Tag-based auth**.

One command (`./deploy.sh --new --github`) deploys the full stack end-to-end.

**References:**

- Architecture: [`docs/architecture/next-github-actions-agent-federation.md`](docs/architecture/next-github-actions-agent-federation.md)
- Platform learnings: [`docs/platform-learnings/GitHub-Actions-Federation.md`](docs/platform-learnings/GitHub-Actions-Federation.md)

---

## Prerequisites

### Azure

```bash
az login
azd auth login
```

### GitHub

```bash
gh auth login
```

You need push access to the target repo (for runner registration).

---

## Quick Start

### New Environment

```bash
./deploy.sh --new --github
```

This provisions everything from scratch: Azure infrastructure, SPIRE server, Container Apps, GitHub runner VM, Entra Agent Identity, Flexible FIC, RBAC policy, and portal registration.

### Existing Environment

```bash
./deploy.sh --skip-provision --github
```

Adds the GitHub runner to an existing AIM deployment.

---

## Running the Demo

After deployment, trigger the demo workflow:

```bash
gh workflow run "AIM Budget Check" --repo microsoft/aim-foundry-poc
```

Or from the GitHub Actions UI: go to Actions → AIM Budget Check → Run workflow.

The workflow will:
1. Fetch a GitHub OIDC token
2. Exchange it for an Entra Agent Identity token (2-hop via FIC)
3. Call `budget-backend` through spiffe-proxy (mTLS)
4. Display the result and provenance metadata

### Verifying Each Layer

To prove each security layer independently:

| Layer | How to break it | Expected result |
|-------|----------------|-----------------|
| Layer 1 (SPIFFE) | Remove runner SPIFFE ID from mTLS allow list | mTLS handshake fails |
| Layer 2 (RBAC) | Remove `github-budget-reader` from `federated_policies` | 403 Forbidden |
| Layer 3 (JWT) | Delete the FIC on the Blueprint | Token exchange fails, 401 |
| Layer 4a (CA) | Set `agent_state: disabled` in RBAC policy | CA blocks the call |
| Layer 4b (Tags) | Add `required_tags: {github_repo: wrong/repo}` | Tag mismatch, 403 |

---

## Key Differentiator: FIC Scaling

Azure limits FICs to 20 per app registration. AIM solves this:

- **One Flexible FIC** on the Blueprint trusts `repo:microsoft/*`
- **RBAC `required_tags`** authorize per-repo (e.g., `github_repo: microsoft/aim-foundry-poc`)
- **No per-repo FICs needed** — scales to unlimited repos

This is deployment governance as identity policy.

---

## Troubleshooting

### OIDC token not available

Add to your workflow:
```yaml
permissions:
  id-token: write
```

### FIC exchange fails (AADSTS70021)

Check that the Flexible FIC exists on the Blueprint:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/beta/applications/<BP_OBJECT_ID>/federatedIdentityCredentials"
```

### Runner not picking up jobs

Verify runner is registered and online:
```bash
gh api repos/microsoft/aim-foundry-poc/actions/runners --jq '.runners[] | {name, status}'
```

Verify labels match:
```yaml
runs-on: [self-hosted, aim-runner]
```

### Check overall deployment status

Run the deployment dashboard to see all resources, identities, and cross-cloud agents:
```bash
./scripts/current-deployment.sh
```
