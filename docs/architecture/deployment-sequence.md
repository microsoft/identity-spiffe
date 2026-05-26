# Deployment Sequence

> `deploy.sh` is the supported entrypoint. It is non-interactive by default, validates the live deployment unless `--no-verify` is passed, and only launches the portal when `--portal` is supplied. Real Entra CA provisioning is required by default; set `REQUIRE_REAL_CA=false` only when you intentionally want YAML fallback mode. For portal/CrowdStrike-only changes, use `--portal-only` to skip SPIRE work and avoid re-attestation.

```
Step 1: azd provision        Step 2: Wait 90s        Step 2.5: Entra bootstrap
(Bicep → infra)              (AcrPull role            (provisioner app +
                              propagation)            Graph consent)

Step 2.7/2.8: Entra IDs +    Step 3: Build proxy      Step 4: Start SPIRE Server
real CA provisioning         (spiffe-proxy → ACR)     (VM image pull +
                                                           start spire-server)

Step 5: Update agents        Step 6: Register entries Step 7: Verify
(join tokens, trust          + generate portal config (scripts/test_agents.py)
 bundle, sidecars)
```

> **Note:** Step 2.5 (Foundry agent creation) was removed in ADR-009. The SPIFFE ID format now uses Entra Agent Identity OIDs directly, eliminating the Foundry dependency.

## Step Details

### Step 1: `azd provision`
Deploys all Azure infrastructure via Bicep: Container Apps Environment, ACR, SPIRE Server VM, networking, managed identities. Does NOT deploy application containers.

### Step 2: Wait for Role Propagation
AcrPull role assignments and VM cloud-init are given 90 seconds to settle before build/deploy starts.

### Step 2.5: Entra Bootstrap
Runs `scripts/setup-entra-deploy-permissions.sh` to ensure the dedicated provisioner app exists, has the required Microsoft Graph application permissions, and has admin consent. If the signed-in operator cannot grant those rights, deploy fails with an explicit “ask an Entra administrator” message.

### Step 2.7 / 2.8: Entra Agent IDs + Real CA
`deploy.sh` first resolves the Entra scope for the current `azd` environment:

- existing environments with stored bootstrap state stay `legacy`
- fresh environments default to `scoped`
- the script prints the exact Blueprint, Agent Identity, FIC, portal group, and portal app names before it provisions anything

It then provisions Agent Blueprints / Agent IDs for that scope and provisions
custom security attributes plus the CA policy using the same dedicated provisioner app.
By default this is a required deploy path. Only `REQUIRE_REAL_CA=false` allows the old YAML fallback behavior.

The dedicated provisioner app plus the CA schema/policy remain shared tenant-wide.
The Agent Blueprint, Agent Identity, FIC, and portal app registration names are
env-scoped for new deployments so parallel environments do not clobber each other.
The portal administrator/viewer groups stay shared tenant-wide.

### Step 3: Build and Push spiffe-proxy
Builds the Go proxy Docker image and pushes to ACR. Tag: `v22` (current by default).

### Step 4: SPIRE Server Setup
Uses the managed `az vm run-command create/show/delete` flow through the shared deployment helper. This gives server-side timeouts and cleanup, avoiding the old stuck `invoke` path.

### Step 5: Token Generation + Agent Update
For each agent:
1. Generate join token with SPIFFE ID: `spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>`
2. Extract the trust bundle from the SPIRE server
3. Update the full Container App spec so sidecars restart with the new token and bundle
4. Re-inject critical runtime env for A2A / admin governance (`MGMT_API_KEY`, target URLs, control-plane endpoint, caller MI IDs) if Azure drops them during template replacement

The SPIFFE ID uses the Entra Agent Identity Blueprint format: `ests/bp/<blueprint-oid>/aid/<agent-oid>`. The `ests` namespace reflects ESTS (Entra STS) as the identity authority.

### Step 6: Workload Registration + Portal Config
After agents attest, `deploy.sh` creates workload entries using the `agent/<name>` parent chain and writes `portal/portal-config.json`.

Each Container App is deployed as a full multi-container spec:
- **Agent container** (Python FastAPI)
- **SPIRE Agent sidecar** (with join token env var)
- **spiffe-proxy sidecar** (with RBAC policy config, target endpoints)

All three containers are deployed in a single operation to avoid the multi-container reset bug (Learning #3).

### Step 7: Verification
Runs `python3 scripts/test_agents.py` by default. Use `--no-verify` if you only need to refresh runtime config or recover a partial deployment.

The verification suite now includes:
- transport mTLS
- RBAC
- identity chain
- OAuth2
- S2S JWT enforcement
- direct A2A target selection
- CA risk enforcement

## Flags

- `--skip-provision`: Skip Steps 1+2, resume from Step 3. Use after a failed deploy when infra is already up.
- `--skip-provisioning`: Alias for `--skip-provision`.
- `--skip-build`: Skip the Docker build in Step 3. Use when redeploying with an existing image tag.
- `--portal-only`: Build and update only `aim-portal` and `crowdstrike-mock`, then refresh portal auth wiring. Skips Entra Agent IDs, SPIRE VM startup, join-token generation, sidecar updates, and re-attestation.
- `--no-verify`: Skip the live test suite.
- `--portal`: Launch the portal after a successful deploy.
- `REQUIRE_REAL_CA=false`: Explicitly allow fallback CA mode when real Entra custom attribute or CA policy provisioning fails.

## Full Teardown and Redeploy

```bash
./scripts/teardown.sh
./deploy.sh
```
