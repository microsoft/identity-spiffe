# CLAUDE.md — Scripts

> Deployment, testing, and identity management scripts.

When only the cloud portal UX/auth surface changed, prefer `./deploy.sh --portal-only`.
That path rebuilds and updates `isp-portal` + `securityportal-mock` without touching agent sidecars or forcing SPIRE re-attestation.

Read alongside:

- `docs/getting-started/quickstart.md`
- `docs/developer/parallel-deployments.md`
- `docs/reference/authentication-flows.md`

## Scripts Overview

| Script | Language | Lines | Purpose |
|--------|----------|-------|---------|
| `lib/deploy-config.sh` | Bash | small | Shared deployment defaults and agent metadata |
| `lib/azure-helpers.sh` | Bash | ~120 | Shared azd env loading and managed VM run-command helper. **Critical:** `azure_vm_run()` must wait for ARM `provisioningState` to reach terminal before deleting — see `docs/runbooks/hard-won-learnings.md` #20 |
| `lib/entra-scope.sh` | Bash | small | Shared shell wrapper for env-scoped Entra naming helpers |
| `test_agents.py` | Python | ~790 | Enforcement matrix validation (7 layers, ~18 scenarios) |
| `entra_provisioning.py` | Python | ~300 | Shared dedicated provisioner app bootstrap + Graph token helper |
| `entra_scope.py` | Python | ~350 | Shared legacy/scoped Entra naming resolution + persistence |
| `setup-entra-deploy-permissions.sh` | Bash | small | Ensures the provisioner app exists and has Graph consent before deploy |
| `create-entra-agent-ids.py` | Python | ~860 | Entra Agent Identity provisioning via Graph beta API |
| `create-custom-attributes.py` | Python | ~450 | Real Entra custom security attribute + CA policy provisioning |
| `reattest.sh` | Bash | ~110 | Re-attest agents with fresh join tokens. **Run this EVERY TIME a Container App revision is created/restarted.** Lightweight fix — no rebuild, no Entra changes, just fresh tokens (~30s per agent). Usage: `./scripts/reattest.sh` (all) or `./scripts/reattest.sh admin-control-plane` (one) |
| `add-demo-agent.sh` | Bash | ~350 | Dynamically add a demo agent to running deployment |
| `remove-demo-agent.sh` | Bash | ~130 | Remove a dynamically-added demo agent |
| `portal-members.sh` | Bash | small | Add/remove/list members of the portal Administrators/Viewers groups post-deploy. Usage: `./scripts/portal-members.sh add-admin <upn>` |
| `teardown.sh` | Bash | ~80 | Clean teardown of all resources |

---

## test_agents.py

The enforcement matrix validation script. Runs all 22 scenarios and reports pass/fail.

```bash
python3 scripts/test_agents.py
```

### What It Tests

**Transport Layer (mTLS):**
1. BudgetReport → BudgetBackend: ✅ connection succeeds
2. EmployeeMenus → BudgetBackend: ❌ connection refused (mTLS rejection)
3. BudgetApproval → BudgetBackend: ✅ connection succeeds

**Application Layer (RBAC):**
4. BudgetReport → GET /budget/read: ✅ 200
5. BudgetReport → POST /budget/submit: ❌ 403
6. BudgetApproval → POST /budget/submit: ✅ 200
7. BudgetApproval → GET /budget/read: ✅ 200

**Identity chain, OAuth2, S2S, A2A, and CA risk:**
8. Identity chain: BudgetReport
9. Identity chain: BudgetApproval
10. OAuth2 token: BudgetReport
11. OAuth2 token: BudgetApproval
12. S2S JWT enforcement: BudgetReport read
13. S2S JWT enforcement: BudgetReport submit denied
14. S2S JWT enforcement: BudgetApproval submit
15. S2S JWT enforcement: BudgetApproval read
16. A2A: BudgetReport → BudgetApproval allowed
17. A2A: EmployeeMenus → BudgetApproval denied
18. A2A: BudgetReport → EmployeeMenus denied
19. CA risk: BudgetReport high risk denied
20. CA risk: BudgetReport low risk recovered
21. CA risk: BudgetApproval high risk denied
22. Baseline recovery checks / summary

### Configuration

The script reads agent endpoints from environment or defaults to the deployed Container App FQDNs. If endpoints change after redeployment, update the script or pass endpoints as env vars.

### Expected Output

```
=== Enforcement Matrix Validation ===
[1/9] BudgetReport → BudgetBackend (mTLS)     ... ✅ PASS
[2/9] EmployeeMenus → BudgetBackend (mTLS)    ... ✅ PASS (connection refused)
[3/9] BudgetApproval → BudgetBackend (mTLS)   ... ✅ PASS
[4/9] BudgetReport GET /budget/read            ... ✅ PASS (200)
[5/9] BudgetReport POST /budget/submit         ... ✅ PASS (403)
[6/9] BudgetApproval POST /budget/submit       ... ✅ PASS (200)
[7/9] BudgetApproval GET /budget/read          ... ✅ PASS (200)
[8/9] BudgetApproval DELETE /admin/data        ... ✅ PASS (403)
[9/9] Management API via BudgetApproval        ... ✅ PASS

Results: 22/22 PASSED
```

---

## create-entra-agent-ids.py

Provisions Entra Agent Identity Blueprint and per-agent identities via the Microsoft Graph beta API.

```bash
python3 scripts/create-entra-agent-ids.py
```

### What It Does

1. Resolves `ISP_ENV_SCOPE_MODE` / `ISP_ENV_SCOPE_KEY` for the current azd environment
2. Creates or reuses the current env's Agent Identity Blueprint
3. Creates or reuses the current env's per-agent identities and FICs
4. Stores Blueprint IDs plus per-agent Agent Identity `appId` values in `azd env`

Existing environments with stored bootstrap IDs stay `legacy`. Fresh environments
default to `scoped` names derived from `AZURE_ENV_NAME`.

### Prerequisites

- `./scripts/setup-entra-deploy-permissions.sh` should have succeeded first
- The signed-in operator must be able to create/update the provisioner app and grant admin consent, or must ask an Entra administrator to do so
- The tenant must support the Agent Identity beta API

---

## create-custom-attributes.py

Provisions real Entra custom security attributes and a Conditional Access policy using the same dedicated provisioner app as Agent ID creation.

Default behavior is strict: `REQUIRE_REAL_CA=true`. If Graph permissions, licensing, or tenant support are missing, the script exits non-zero. Only set `REQUIRE_REAL_CA=false` when you intentionally want YAML fallback mode.

---

## deploy.sh

Primary deployment entrypoint for the repo.

```bash
./deploy.sh --portal-only
```

Use `--portal-only` for:
- `portal/` backend or UI changes
- `securityportal-mock/` changes
- portal auth/config wiring in `deploy.sh`

Do not use `--portal-only` for:
- agent app changes
- `src/spiffe-proxy/` changes
- any sidecar env/runtime changes
- SPIRE / join-token / attestation changes
- Entra Agent Identity / FIC / CA provisioning changes

If a Container App revision touched an agent sidecar, use a full deploy path or `./scripts/reattest.sh` as appropriate.

---

## add-demo-agent.sh / remove-demo-agent.sh

Dynamically add or remove a demo agent to/from a running deployment. Used for live demos showing the platform can onboard new agents without redeploying existing ones.

These scripts should use the shared managed VM run-command helper from `scripts/lib/azure-helpers.sh`, not `az vm run-command invoke`.
They now also use `scripts/lib/entra-scope.sh` so demo agent Entra identities and
FICs follow the current environment's naming scope instead of colliding with other deployments.

If direct A2A remains part of the product story, the dynamic-agent path also needs to learn the same runtime contract:
- target discovery / registry
- Entra attribute sync expectations
- management/auth path for governance lookups

That is not fully generalized yet.

```bash
# Add a demo agent
./scripts/add-demo-agent.sh

# Remove it
./scripts/remove-demo-agent.sh

# Clean up current env's Entra Agent Identity objects only
python3 scripts/cleanup-entra-agent-ids.py

# Old tenant-wide cleanup behavior (explicit only)
python3 scripts/cleanup-entra-agent-ids.py --all-envs
```

---

## teardown.sh

Clean teardown of all Azure resources created by the deployment.

```bash
./scripts/teardown.sh
```

Wraps `azd down --force --purge` with additional cleanup for SPIRE server state and orphaned resources.
