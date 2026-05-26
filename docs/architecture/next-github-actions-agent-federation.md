# Next: GitHub Actions Agent via Entra + SPIFFE Federation

**Status:** Reference design
**Mode:** Scoped implementation guide
**Target:** One GitHub Actions caller visible in the existing portal
**Supersedes:** Earlier broad cross-cloud federation assumptions
**Last updated:** 2026-04-18

## Executive Summary

Add one GitHub Actions-hosted caller agent, `github-budget-reader`, that behaves like the existing Google-hosted caller but runs on a self-hosted GitHub Actions runner in Azure.

It must prove two identity planes at the same time:

1. **Entra identity plane**
   - GitHub Actions OIDC token is exchanged into an **Entra Agent Identity** token through a **Blueprint-level Federated Identity Credential (FIC)**.
   - The caller stays secretless.
2. **SPIFFE transport plane**
   - The self-hosted runner presents a **SPIFFE ID** over mTLS through the existing SPIRE mesh (same trust domain as Azure agents — no federation needed since the runner is in-VNet).

The portal must discover and render this GitHub caller through the **existing dynamic agent path**, with full GitHub provenance visibility (repo, workflow, ref, SHA, run ID).

**Key differentiator:** AIM eliminates the FIC scaling problem. Azure limits you to 20 FICs per app registration. AIM solves this: one flexible FIC on the Agent Identity Blueprint trusts the GitHub org, and AIM's RBAC layer handles per-repo/per-workflow authorization. No per-repo FICs needed. This is deployment governance as identity policy.

## Architecture

```
GitHub Actions (self-hosted runner on Azure VM)
┌─────────────────────────────────────────────┐
│  GitHub Actions Workflow                     │
│  ┌──────────────┐  ┌────────────────────┐   │
│  │ aim-auth      │  │ budget-check step  │   │
│  │ (OIDC→Entra)  │  │ (curl via proxy)   │   │
│  └──────────────┘  └────────┬───────────┘   │
│  ┌───────────────┐           │               │
│  │ spiffe-proxy   │←──────────┘ mTLS         │
│  │ (egress)       │                          │
│  └───────┬───────┘                           │
│  ┌───────┴───────┐                           │
│  │ SPIRE Agent    │                          │
│  └───────┬───────┘                           │
└──────────┼──────────────────────────────────┘
           │ (same Azure VNet — no VPN needed)
           ▼
┌──────────────────┐        ┌─────────────────────┐
│ SPIRE Server     │        │   budget-backend     │
│ (Azure VM)       │        │ ┌──────┐┌───────┐   │
│ td: aim.ms.com   │        │ │Proxy ││ Agent │   │
└──────────────────┘        │ │:8443 ││:8000  │   │
                            │ └──────┘└───────┘   │
                            └─────────────────────┘
```

**Key difference from Google:** No VPN, no SPIRE federation, no separate trust domain. The self-hosted runner is an Azure VM in the same VNet, enrolled in the same SPIRE server. Simpler infrastructure, same identity model.

## Implementation Phases

### Phase 1: Core Identity (Vertical Slice)

Add `GitHubOIDCProvider` to the credential provider strategy pattern.

| File | Change |
|---|---|
| `src/shared/entra_token_exchange.py` | New `GitHubOIDCProvider` class. `TOKEN_SOURCE=github_oidc`. Fetches OIDC token from `ACTIONS_ID_TOKEN_REQUEST_URL`. Returns as Hop 0 assertion. |
| `src/shared/test_credential_providers.py` | Unit tests: provider selection, OIDC fetch success/failure, fail-closed on missing env vars, two-hop exchange with GitHub assertion. |

**GitHub OIDC token retrieval:**
```bash
curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
     "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange"
```

Hop 1 (FIC exchange) and Hop 2 (Entra agent token) are unchanged from the existing pipeline.

### Phase 2: Provisioning

| Script | Purpose |
|---|---|
| `scripts/add-github-agent.sh` | One-time setup: create Agent Identity, flexible FIC on Blueprint, assign `Budget.Read`, SPIFFE allow list, portal registration. |
| `scripts/add-github-repo.sh` | Per-repo onboarding: creates Agent Identity + RBAC entry + portal metadata only. No additional FIC needed. |

**FIC is created ONCE on the Blueprint (wildcard).** Per-repo onboarding does NOT create additional FICs.

**Flexible FIC shape (Graph API):**

Flexible FICs use `claimsMatchingExpression`, NOT `subject` (they are mutually exclusive). Created via `az rest` or Graph API:

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

| Example Subject | Allowed? | Why |
|---|---|---|
| `repo:microsoft/aim-foundry-poc:ref:refs/heads/main` | ✅ | Matches `microsoft/*` |
| `repo:microsoft/infrastructure:environment:Production` | ✅ | Matches `microsoft/*` |
| `repo:attacker/malicious-repo:ref:refs/heads/main` | ❌ | Not in `microsoft/` org |
| Forked PR from external org | ❌ | Subject uses fork's org |

### Phase 3: Infrastructure + Runner Bootstrap

- Self-hosted runner VM provisioned in Azure VNet (no VPN needed)
- GitHub Actions runner installed, registered, and running as systemd service
- SPIRE agent installed on runner VM (same pattern as GCE)
- spiffe-proxy egress sidecar as persistent systemd service
- Bicep module: `infra/modules/github-runner-vm.bicep`
- `deploy.sh --github` flag wires the full flow
- GitHub org runner group configured with allowed repos and `aim-runner` label
- Runner setup script adapted from `setup-gce-agent.sh` (strip GCE-specific sections)
- **Demo gate:** One workflow on one repo calls budget-backend through all 5 layers with static RBAC policy

### Phase 4: RBAC Engine Extension + Provenance

This phase extends the spiffe-proxy RBAC engine to support request-scoped tag evaluation. This is new Go code.

- **`engine.go`**: Extend `Evaluate()` to accept request-scoped metadata (from Entra JWT custom claims). Tags keyed by request context, not just SPIFFE ID.
- **`validator.go`**: Parse custom Entra claims (GitHub provenance: repo, workflow, ref, sha, run_id) from the bearer token.
- **`access.go`**: Add GitHub provenance fields to audit log schema.
- **`policy.go`**: Allow per-SPIFFE-ID policy to reference request-scoped tags (e.g., `github.repo`, `github.workflow_ref`).
- **Portal**: Display GitHub provenance in agent identity view.
- **Entra custom claims**: Configure on Agent Identity app registration via Graph API. GitHub OIDC claims embedded during FIC exchange.
- **Note:** Layer 2 (SPIFFE ID in `federated_policies`) authorizes the *runner*. Layer 4b (request-scoped tags) authorizes the *repo/workflow*. These are different granularities by design.

### Phase 5: Per-Repo Onboarding + Packaging (gated on Phase 4)

- `scripts/add-github-repo.sh` — per-repo onboarding (Agent Identity + RBAC tag rules + portal metadata)
- Reusable GitHub Action: `.github/actions/aim-auth/action.yml`
- `docs/platform-learnings/GitHub-Actions-Federation.md`
- Demo workflow: `.github/workflows/aim-budget-check.yml`
- Update `README.md` and `CLAUDE.md`

## GitHub OIDC Claim Trust Matrix

Not all GitHub provenance attributes are equally trustworthy. RBAC policy should only make security decisions on **signed** claims.

| Attribute | Source | Trust Level | Available In | RBAC Tag |
|---|---|---|---|---|
| `repository` | Signed OIDC claim | **Signed** | All events | `github.repo` |
| `repository_owner` | Signed OIDC claim | **Signed** | All events | `github.org` |
| `ref` | Signed OIDC claim | **Signed** | push, workflow_dispatch | `github.ref` |
| `sha` | Signed OIDC claim | **Signed** | All events | `github.sha` |
| `workflow` | Signed OIDC claim | **Signed** | All events | `github.workflow` |
| `job_workflow_ref` | Signed OIDC claim | **Signed** | All events | `github.workflow_ref` |
| `environment` | Signed OIDC claim | **Signed** | If configured | `github.environment` |
| `run_id` | Signed OIDC claim | **Signed** | All events | `github.run_id` |
| `runner_environment` | Signed OIDC claim | **Signed** | All events | `github.runner_env` |
| `actor` | Signed OIDC claim | **Locally observed** | All events | Informational only |
| `artifact_digest` | Not in OIDC token | **Derived** | Post-build only | Future (v2) |

**Rule:** MVP RBAC policies use only **Signed** claims for authorization. Locally observed and derived claims are logged for portal visibility but not enforced.

**Canonical claim for workflow enforcement:** Use `job_workflow_ref` (stable, includes path) for RBAC policy matching. Use `workflow` (display name) for portal display only.

**Forked PRs:** GitHub OIDC tokens for forked PR workflows use `ref: refs/pull/N/merge` and the fork's repo as subject. The FIC wildcard `repo:microsoft/*` will NOT match forks from external orgs. This is correct security behavior.

## Provenance Tag Transport

GitHub OIDC claims travel inside the Entra token as custom claims, NOT as HTTP headers. This prevents spoofing by malicious workflows.

1. **FIC exchange:** During `claimsMatchingExpression` evaluation, Azure FIC verifies the GitHub JWT. The signed claims are trustworthy because the FIC exchange succeeded.
2. **Custom Entra claims:** GitHub provenance (repo, workflow_ref, ref, sha, run_id) is configured as custom claims on the Agent Identity app registration via Graph API. These claims are embedded in the Entra access token during FIC exchange.
3. **Token parsing:** spiffe-proxy's `validator.go` extracts custom claims from the Entra JWT during Layer 3 validation.
4. **RBAC consumption:** The extracted claims are passed to `Evaluate()` as request-scoped tags. RBAC policy matches `github.*` tag rules against these values.
5. **Audit logging:** `access.go` logs GitHub provenance fields alongside SPIFFE ID and Entra identity.
6. **Portal display:** Portal reads provenance from audit logs / admin-CP discovery.

## Runtime Sequence

```
1. Runner VM boots → SPIRE agent starts → attests to SPIRE server
2. spiffe-proxy starts on runner → obtains SVID from SPIRE agent
3. GitHub Actions workflow starts on runner
4. aim-auth action step:
   a. Fetches OIDC token from $ACTIONS_ID_TOKEN_REQUEST_URL
      (audience: api://AzureADTokenExchange)
   b. GitHubOIDCProvider exchanges OIDC token → Entra agent token
      via FIC (Hop 0→1)
   c. Entra agent token acquired for Budget.Read scope (Hop 2)
5. Workflow calls budget-backend via spiffe-proxy egress:
   a. spiffe-proxy presents runner's SVID (mTLS) — Layer 1
   b. spiffe-proxy on budget-backend verifies SPIFFE ID
      against federated_policies — Layer 2
   c. Entra JWT validated, scopes checked — Layer 3
   d. CA risk evaluation — Layer 4a
   e. Tag-based auth (github.repo, github.workflow, github.ref) — Layer 4b
6. budget-backend responds with budget data
7. Portal logs: SPIFFE ID, Entra identity, GitHub provenance, all 5 decisions
```

The runner VM runs spiffe-proxy as a persistent systemd service (same as GCE pattern). The GitHub Action does NOT start spiffe-proxy — it's already running.

## Minimum Workflow YAML

```yaml
name: AIM Budget Check
on: workflow_dispatch
permissions:
  id-token: write   # Required for GitHub OIDC token
  contents: read
jobs:
  check-budget:
    runs-on: [self-hosted, aim-runner]
    steps:
      - uses: microsoft/aim-foundry-poc/.github/actions/aim-auth@main
        with:
          aim-endpoint: ${{ vars.AIM_ENDPOINT }}
      - run: |
          # spiffe-proxy egress handles mTLS — call via localhost
          curl -s -H "Authorization: Bearer $AIM_TOKEN" \
            http://localhost:8080/budget/remaining
```

## Lifecycle Management

| Action | Script/Command | What It Does |
|---|---|---|
| **Onboard repo** | `add-github-repo.sh --repo org/repo` | Creates Agent Identity, RBAC entry, portal metadata. FIC already exists (wildcard). |
| **Rotate runner** | `scripts/reattest.sh` (existing) | Re-attests SPIRE agent on runner VM. New SVID issued. |
| **Revoke repo access** | `add-github-repo.sh --repo org/repo --revoke` | Removes Agent Identity, RBAC entry, portal metadata. |
| **Emergency deny** | Edit `spiffe-rbac-policy.yaml` — remove federated entry | Immediately blocks all GitHub callers at RBAC layer. |
| **Decommission runner** | Delete VM + remove SPIRE entry | Runner SPIFFE ID becomes invalid. mTLS calls fail. |
| **FIC compromise** | Delete FIC on Blueprint via Azure Portal/CLI | All GitHub OIDC → Entra exchanges fail immediately. |

## Key Files Changed

| File | What it does |
|---|---|
| `src/shared/entra_token_exchange.py` | `GitHubOIDCProvider` — `TOKEN_SOURCE=github_oidc`. Fetches OIDC from Actions env, returns as Hop 0 assertion. |
| `src/shared/test_credential_providers.py` | Unit tests for GitHub provider: selection, fetch, fail-closed, two-hop exchange. |
| `src/spiffe-proxy/internal/rbac/engine.go` | Extend `Evaluate()` to accept request-scoped metadata for tag matching. |
| `src/spiffe-proxy/internal/rbac/engine_test.go` | Tests for request-scoped tag evaluation in RBAC engine. |
| `src/spiffe-proxy/internal/oauth/validator.go` | Parse custom Entra claims (GitHub provenance) from bearer tokens. |
| `src/spiffe-proxy/internal/logging/access.go` | Add GitHub provenance fields to audit log schema. |
| `src/spiffe-proxy/config/spiffe-rbac-policy.yaml` | `federated_policies` entry for `github-budget-reader` with `github.*` tag rules. |
| `scripts/add-github-agent.sh` | One-time GitHub agent provisioning (Agent Identity, FIC, SPIFFE, portal). |
| `scripts/add-github-repo.sh` | Per-repo lightweight onboarding (Agent Identity + RBAC tag rules + portal only). |
| `scripts/lib/federation-helpers.sh` | Shared provisioning functions extracted from Google + GitHub scripts. |
| `infra/modules/github-runner-vm.bicep` | Self-hosted runner VM with SPIRE agent + GitHub Actions runner. |
| `deploy.sh` | `--github` flag for integrated deployment. |
| `.github/actions/aim-auth/action.yml` | Reusable composite action for OIDC → AIM auth. |
| `.github/workflows/aim-budget-check.yml` | Demo workflow. |
| `portal/app/routers/api.py` | GitHub provenance display in agent identity view. |
| `docs/platform-learnings/GitHub-Actions-Federation.md` | Platform learnings doc. |
| `scripts/current-deployment.sh` | Deployment status dashboard (shows all resources, identities, cross-cloud agents). |

## Success Criteria

1. GitHub Actions workflow successfully calls `budget-backend` through all 5 security layers
2. Portal shows GitHub provenance (repo, workflow, ref, run_id) in the agent identity view
3. Selectively disabling each layer produces the correct rejection (same as Google demo)
4. `deploy.sh --github` provisions the full stack from scratch
5. `add-github-repo.sh` onboards a new repo in under 60 seconds
6. `aim-auth` GitHub Action works in any workflow on the approved runner pool
7. Platform learnings doc captures FIC scaling solution and hard-won learnings

## Deferred Decisions

1. **Idempotency and rollback in provisioning scripts.** Scripts should check-before-create and handle partial failures gracefully, same as `add-google-agent.sh`. Exact rollback order TBD during implementation.
2. **Runner pool GitHub org configuration.** The approved runner pool requires GitHub org settings (runner group, allowed repos, labels). This is org admin setup, not AIM code. Document in platform learnings.
3. **Runner trust vs repo trust separation.** Runner pool bootstrap (SPIRE enrollment, SPIFFE allow list) is done once. Repo onboarding (Agent Identity, RBAC, portal) is per-repo. These are separate tracks in `deploy.sh --github`.
4. **Demo agent naming.** Should be a new `github-budget-reader` app (like `google-budget-reader`) or reuse existing budget demo flow. TBD.

## What Generalizes

The GitHub federation validates that AIM's cross-cloud identity model works beyond Google:

1. **Credential provider strategy pattern** — `TOKEN_SOURCE` selects the provider. Adding a new platform means adding one class.
2. **FIC on Blueprint** — the trust relationship lives on the Agent Identity Blueprint, not per-app. Scales to any number of repos/workflows.
3. **Federated RBAC policies** — same `federated_policies` section in spiffe-proxy, different trust domain / SPIFFE ID.
4. **Portal external agent store** — same `hosting_platform` field, different value.
5. **Provisioning script pattern** — `add-{platform}-agent.sh` follows the same 6-step structure.

If this works, AWS (`--aws`) and ServiceNow (`--servicenow`) follow the same pattern. The stubs are already in `deploy.sh`.
