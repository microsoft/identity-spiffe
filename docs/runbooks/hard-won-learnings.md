# Hard-Won Learnings

> Every major gotcha we hit building this PoC. Read before debugging anything.

## 1. SPIRE azure_msi NodeAttestor Is Incompatible with Container Apps

The server-side resolver only queries `Microsoft.Compute/virtualMachines` and `Microsoft.Compute/virtualMachineScaleSets`. Container Apps (`Microsoft.App/containerApps`) returns "resource not found." This is a code limitation, not a config issue.

**Fix:** Join token attestation. See ADR-003.
**Production fix:** Upstream SPIRE contribution (~200-300 lines Go).

## 2. SPIRE Server Needs IMDS Access → Must Be a VM

SPIRE Server's azure_iid NodeAttestor validates tokens via Azure IMDS (169.254.169.254). Container Apps doesn't expose IMDS to user containers. SPIRE Server must run on an Azure VM.

**Current:** SPIRE Server on Azure VM, SPIRE Agents as Container App sidecars.

## 3. Container Apps Multi-Container Update Resets Non-Target Containers

When you update one container in a multi-container Container App, Azure resets the other containers to a placeholder image. You must update ALL containers in a single deployment YAML.

**Fix:** deploy.sh always deploys the full container spec (agent + spire-agent + spiffe-proxy) in one operation.

## 4. Container Apps Internal TCP Routing Uses App Name

To route TCP traffic between Container Apps without hitting the external TLS termination layer, use the Container App's name as the hostname (e.g., `budget-backend`). This works on the internal virtual network. Using the FQDN (`.internal.<env>.<region>.azurecontainerapps.io`) triggers TLS termination which breaks mTLS.

## 5. Join Tokens Are Single-Use and Don't Survive Restarts

A join token is consumed on first SPIRE Agent connection. If the container restarts, the token is gone. The agent can't re-attest. Must redeploy with a fresh token.

**Impact:** PoC-acceptable. Production-blocking. See ADR-003 production path.

## 6. Two-Hop Parent ID Chain for SPIRE

SPIRE workload entries need a parent ID that points to the SPIRE Agent's node entry. The chain is:

```
SPIRE Server
  └── Node Entry (from join_token attestation): spiffe://aim.microsoft.com/spire/agent/join_token/{token-hash}
        └── Workload Entry: spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid> (parent = node entry above)
```

`deploy.sh` captures the node SPIFFE ID after token generation and uses it as the parent ID for workload registration.

## 7. `entry show` Not `entry list`

The SPIRE CLI command to view registered entries is `spire-server entry show`, not `entry list`. `entry list` doesn't exist and silently returns nothing.

## 8. `az vm run-command` Returns JSON-Wrapped Output

Output from `az vm run-command invoke` is a JSON object with `stdout` and `stderr` fields. You need `jq -r '.value[0].message'` to extract the actual command output. Don't pipe raw output to other commands.

## 9. revisionSuffix Causes Deployment Conflicts

Azure Container Apps rejects deployments if the `revisionSuffix` matches an existing revision. Strip `revisionSuffix` from YAML templates before deploying, or use a unique suffix per deployment.

**Fix:** deploy.sh strips `revisionSuffix` from all Container App YAML updates.

## 10-14. Foundry-Specific Learnings (HISTORICAL)

> Learnings #10-14 were specific to Azure AI Foundry (API versions, SKUs, soft-deleted accounts, etc.). Foundry was removed in ADR-009 because it provided zero enforcement value. These learnings are preserved here for reference but are no longer relevant to the current architecture. See `docs/decisions/009-remove-foundry.md` for the full rationale.

## 15. Azure Role Propagation: Read Before Write

Azure RBAC data actions (`agents/read`, `agents/write`) don't propagate simultaneously. Read permissions typically arrive 15-30s before write permissions. This means `list_agents()` can succeed while `create_agent()` still gets `PermissionDenied`. Always add retry logic to *both* read and write operations when they depend on a recent role assignment.

## 16. Large Removals Surface Latent Bugs

Removing Foundry touched 22 files and deleted 597 lines. The follow-up commits reveal a pattern: variable names, imports, and references to removed components linger in files you didn't directly edit. After a large removal:
- Grep for the removed component's name across the entire codebase
- Check scripts that consume environment variables — names may have changed
- Test the deploy end-to-end; unit tests won't catch broken shell variable references

## 17. `az vm run-command invoke` Has No Server-Side Timeout — Use Managed API

The legacy `az vm run-command invoke` has two fatal flaws:

1. **No server-side timeout** — the command runs until it finishes or the VM is destroyed
2. **Single-slot** — only one invoke command can run at a time per VM; subsequent calls get `(Conflict)`

Client-side wrappers (`gtimeout 180 az vm run-command invoke ...`) make it WORSE: they kill the local `az` process but the server-side command keeps running, permanently blocking all future `invoke` calls. The only recovery is `azd down --force --purge` (full teardown).

**Fix:** Use the managed run-command API (`az vm run-command create`) which supports:
- `--timeout-in-seconds` — kills the command ON THE VM
- `az vm run-command delete` — cancels/cleans up stuck commands
- Multiple concurrent commands (no single-slot limitation)

deploy.sh uses the `vm_run` helper function that wraps this API with polling and cleanup.

## 18. Unsupervised SPIRE Agent Background Process Silently Breaks mTLS

The SPIRE Agent runs as a background process (`&`) in `entrypoint.sh`, then `exec` replaces the shell with the Go proxy. If the agent dies (OOM, SVID rotation bug, network error), PID 1 (the Go proxy) has no idea — it keeps running, Container Apps reports the container as healthy, but the mTLS tunnel silently breaks because SVIDs can't renew. The failure is invisible until a request hits the dead tunnel.

**Symptoms:** Portal shows all agents "healthy" (FastAPI `/health` responds 200), but management API calls return 502 and test scenarios fail. SPIRE server logs show no SVID renewals for the affected agents.

**Root cause discovered:** Budget-approval and budget-backend SPIRE agents died ~24h after deployment. Employee-menus and budget-report agents (with idle tunnels) survived.

**Fix:** Added a monitor loop in `entrypoint.sh` that checks `kill -0 $SPIRE_PID` every 10s and restarts the agent on death. The restarted agent re-attests using cached key material in `/opt/spire/data/agent/`. This does NOT help on full container restart (join token consumed + data dir wiped — needs `azure_msi` attestor).

**Debugging note:** Container Apps purges sidecar logs on restart, so if you restart the containers before capturing logs, the crash evidence is lost. Always check `az containerapp logs show --container <name>-spiffe-proxy` BEFORE restarting.

## 19. insecure_bootstrap=true Means Zero Server Verification — MITM Risk

SPIRE agent's `insecure_bootstrap = true` setting means the agent accepts the SPIRE server's trust bundle on first connect with no prior verification. An attacker who can intercept the Container App → SPIRE server VM traffic (ARP poisoning, DNS hijack) can impersonate the server, issue fraudulent SVIDs, and bypass all downstream mTLS enforcement. This is a bootstrap trust problem — once the agent has a valid bundle, subsequent connections are verified.

**Fix:** Extract the trust bundle from the SPIRE server after startup (`spire-server bundle show -format pem`), inject it as the `SPIRE_TRUST_BUNDLE` env var into each agent sidecar, and set `trust_bundle_path` in `agent.conf`. The entrypoint writes the bundle to disk before the agent starts (deploy.sh Step 4.5, GitHub issue #63).

**Production hardening:** Store the bundle in Azure Key Vault, mount as a Container Apps secret volume, rotate via Key Vault + SPIRE bundle rotation API. The env var approach is pragmatic for the PoC but Key Vault is required for production (secrets in env vars are visible in Container App config).

## 20. az vm run-command Has Two State Machines — Deleting Too Early Wedges the VM

`az vm run-command create` has two independent state machines: `instanceView.executionState` (guest agent level — reports whether the script finished) and `provisioningState` (ARM resource level — reports whether Azure has finalized the resource). The guest can report "Succeeded" while ARM is still "Running."

**What happens:** If you delete the run-command resource while `provisioningState` is still "Running", the Azure guest agent (`waagent`) enters a permanently wedged state. Once wedged, ALL subsequent VM operations fail or hang: new run-commands, password resets, VM stop, VM restart. The only recovery is force-deallocating the VM from the portal.

**Root cause discovered:** `azure-helpers.sh` polled `executionState`, saw "Succeeded", grabbed the output, and immediately deleted the ARM resource. But `provisioningState` was still "Running". The delete-during-transition corrupted the guest agent's internal queue.

**Fix:** After `executionState` reaches a terminal state, poll `provisioningState` until it also reaches terminal ("Succeeded", "Failed", or "Canceled") before issuing the delete. Added to `azure_vm_run()` in `scripts/lib/azure-helpers.sh`.

**Debugging tip:** When VM operations hang, check the **Azure Activity Log** (portal or `az monitor activity-log list`) first. It shows the ARM-level state of each run-command resource and reveals which specific operation got stuck. Don't theorize about race conditions — read the actual state sequence.

## 21. Replace az vm run-command with Direct SPIRE API or SSH

`az vm run-command` is designed as a debugging/emergency tool, not a production deployment mechanism. It depends entirely on the Azure guest agent, which processes operations serially and is fragile under rapid successive calls. Every deploy risks wedging the VM (see Learning #20).

**Alternatives (in order of preference):**
1. **SPIRE Server Registration API** — gRPC on port 8081. Call directly from deploy.sh over the network. Requires opening port 8081 on the VM NSG. Fastest and most reliable.
2. **SSH** — Add an SSH key during VM provisioning, then `ssh azureuser@<ip> "docker exec spire-server ..."`. Requires port 22 on NSG.
3. **Keep az vm run-command** with the provisioningState fix — works but remains the weakest link.

**Status:** Using option 3 (managed `az vm run-command` API) with the provisioningState fix from Learning #20. SSH was attempted but key synchronization proved unreliable across deploys — `Permission denied (publickey)` failures required manual intervention too often. The managed run-command API authenticates via Azure RBAC (your `az login`), eliminating key management entirely. Migration to option 1 (SPIRE Registration API) is the long-term fix.

## 22. ACR Build Cache Serves Stale Code — Use --no-cache for App Images

Azure Container Registry's `az acr build` uses Docker layer caching by default. For the Go sidecar (multi-stage, slow compilation), this is fine — the `COPY` of source files invalidates downstream layers reliably. But for the portal Python images, ACR's remote build cache was serving stale layers even when `server.py`, `index.html`, or `jwt_validator.py` changed. The `CACHE_BUST` Docker ARG didn't help because `deploy.sh` never passed a dynamic value via `--build-arg`.

**Symptoms:** Deploy completes successfully, Container App restarts, but the running code is from a previous build. Auth fixes, UI changes, and bug fixes don't appear. Extremely confusing to debug — you're reading the new code locally but the container is running old code.

**Failed workaround:** Appending `# cache bust: <timestamp>` comments to Python files before build. Fragile, ugly, and pollutes git history.

**Fix:** Pass `--no-cache` to `az acr build` for portal images. These are small Python containers (~15s full rebuild including pip install), so the tradeoff is correct. The Go sidecar image keeps normal caching (compilation is expensive).

**Rule:** For small app images where build time is <30s, always use `--no-cache`. Reserve layer caching for images with expensive compilation steps.

## 23. SPIRE SVID TTL of 1h Causes Overnight Outages

With `default_x509_svid_ttl = "1h"` in `server.conf`, SVIDs expire within an hour if the SPIRE server stops renewing them. This happened on 2026-03-27: the SPIRE server hung overnight, all SVIDs expired by morning, and every mTLS tunnel failed with `x509: certificate has expired`. The portal showed `backend_mgmt_unreachable` on all management operations.

**Symptoms:** Portal Policy Editor, Network Access, and System Health pages all show errors. Sidecar logs: `transport: authentication handshake failed: x509svid: could not verify leaf certificate: x509: certificate has expired or is not yet valid`. The expired-at timestamp will be exactly 1h (old) or 12h (new) after the last successful renewal.

**Root cause:** Unknown — the SPIRE server process hangs or stops serving after hours of idle. Logs were previously lost on restart because Docker used the default `json-file` driver with no external shipping.

**Fix applied:**
1. SVID TTL increased to 12h, CA TTL to 168h (7 days) — `src/spiffe-proxy/spire-config/server.conf`
2. SPIRE server Docker logs now ship to Log Analytics via Azure Monitor Agent + syslog — `infra/modules/spire-server-vm.bicep`
3. Query: `Syslog | where ProcessName == "spire-server" | order by TimeGenerated desc`

**Recovery:** Full redeploy (`./deploy.sh`). Cannot use `--skip-provision` because the SPIRE server Docker container must be replaced. The stuck `az vm run-command` issue (Learning #20) may also be present — restart the VM first if run-commands fail with "Conflict".

## 24. SPIRE Server VM Logs Were Lost Before Centralized Logging

Before the Azure Monitor Agent was added to the SPIRE server VM, Docker container logs existed only on the VM. Every time the SPIRE server hung and we restarted/redeployed, the evidence was destroyed. This prevented root cause analysis of the overnight hang issue (Learning #23).

**Fix:** Docker now runs with `--log-driver=syslog --log-opt tag=spire-server`. Azure Monitor Agent extension on the VM collects syslog and ships to the same Log Analytics workspace that Container Apps uses (`cae7rw4gg77yidmi-logs`). Data Collection Rule `spire-server-dcr` collects `daemon` and `user` syslog facilities.

**Infrastructure:** Defined in `infra/modules/spire-server-vm.bicep` — AMA extension, DCR, DCR association, Monitoring Metrics Publisher role assignment.

## 25. NEVER `docker rm` the SPIRE Server — It Destroys the CA

On 2026-03-27, we needed to reconfigure the SPIRE server Docker container to use syslog logging. The approach was `docker stop && docker rm && docker run` with the new `--log-driver=syslog` flag. This destroyed the SQLite database at `/opt/spire/data/server/datastore.sqlite3`, which contains the CA keypair, all agent attestation records, and all workload registration entries.

**What breaks:** Every agent in every Container App has SVIDs signed by the old CA. The new SPIRE server generates a new CA. Agents can't renew their SVIDs because the new server doesn't recognize their attestation. SVIDs expire at their original TTL, then all mTLS tunnels die.

**Symptoms:** Identical to Learning #23 — `x509: certificate has expired`, `backend_mgmt_unreachable`, portal shows blank content.

**Recovery:** Full redeploy (`./deploy.sh --skip-build`) to generate fresh join tokens and re-attest all agents to the new CA. Takes ~10 minutes.

**Rule:** To reconfigure the SPIRE server container (logging, env vars, etc.), EITHER:
1. Use `docker update` for supported settings, OR
2. Mount `/opt/spire/data/server` as a Docker volume BEFORE first deploy, so the data survives `docker rm`, OR
3. After `docker rm` + `docker run`, ALWAYS re-run deploy.sh Steps 5-6 to re-attest agents

**TODO:** Mount the SPIRE data directory as a Docker volume in the cloud-init script (`spire-server-vm.bicep`). This is the proper fix — makes the CA persistent across container restarts.

## 26. `azd deploy <agent>` Kills SPIFFE Sidecars — Use deploy.sh or reattest.sh

`azd deploy admin-control-plane` (or any agent service) creates a new Container App revision that resets the sidecar container. The consumed join token is gone, and the sidecar enters a crash loop (`join token does not exist or has already been used`). The SPIRE server is fine — centralized logging confirmed healthy SVID rotation. The only failure is the individual sidecar.

**Symptoms:** Portal Overview tab goes blank (management API calls timeout because the sidecar is dead). `/admin/health` returns 502. Agent logs show "All connection attempts failed" on localhost:8080.

**Misdiagnosis risk:** Looks identical to the SPIRE server overnight hang (Learning #23). Check centralized logs FIRST — if SVIDs are being signed for other agents, the SPIRE server is healthy and the problem is a single sidecar.

**Fix:** `./scripts/reattest.sh admin-control-plane` (~30s). Generates a fresh join token and updates just the `JOIN_TOKEN` env var. For agent code changes, use `./deploy.sh --skip-provision` (rebuilds + re-attests all agents).

**Rule:** NEVER use `azd deploy` for agent Container Apps. Only safe for portals (`aim-portal`, `securityportal-mock`) which have no SPIFFE sidecar.

## 27. Agent Discovery Must Be Dynamic — Never Hardcode URLs or Use Static Env Vars

On 2026-03-26, commit `f8b49a76` added the `/admin/agents` endpoint to admin-control-plane. The commit message claimed it also modified deploy.sh to inject `SERVICE_*_ENDPOINT_URL` env vars — but deploy.sh was never actually changed. The discovery endpoint read env vars that didn't exist. The Execute Request feature was broken from inception and nobody noticed because the Overview/RBAC/mTLS tabs use different API paths.

**Root cause:** Static env var approach for dynamic data. Agent URLs change on every deploy, and dynamic agents (add-demo-agent.sh) can be added at runtime.

**Fix:** `CONTAINER_APP_ENV_DNS_SUFFIX` — Azure injects this into every Container App at runtime. Any app's FQDN = `<app-name>.<dns-suffix>`. Admin-control-plane derives all agent URLs from this single variable. Zero config, works with dynamically added/removed agents.

**Lesson for AI assistants:** When writing code that reads from env vars, config, or APIs — trace the write side in the same session. Run `git diff --staged --name-only` before committing to verify every file mentioned in the commit message was actually changed.

## 28. Policy Push to Sidecar Requires Raw YAML, Not JSON-Wrapped

The sidecar's `/mgmt/policy` PUT endpoint expects raw YAML with `Content-Type: application/x-yaml`, not a JSON object containing a `yaml` field. Sending `{"yaml": "..."}` as `application/json` causes `version is required` errors because the Go YAML parser receives a JSON string, not YAML.

**Correct:**
```bash
curl -X PUT -H "Content-Type: application/x-yaml" -H "X-Spiffe-Admin-Key: $KEY" \
  "$ADMIN_CP_URL/admin/policy" --data-binary @policy.yaml
```

**Wrong:**
```bash
curl -X PUT -H "Content-Type: application/json" \
  "$ADMIN_CP_URL/admin/policy" -d '{"yaml": "version: 5.0\n..."}'
```

**Also:** Python's `yaml.dump()` quotes version `'5.0'` as a string, which the Go parser may reject. Always use the original YAML file from disk when pushing policy changes, with targeted `str.replace()` for modifications.

## 29. Container App `--set-env-vars` Can Nuke Other Containers

Using `az containerapp update --set-env-vars` to change a single env var can cause Azure to reset other containers in the multi-container revision to placeholder images. The sidecar proxy container silently reverts to an older or broken state.

**Fix:** Always use the full-YAML workflow:
1. `az containerapp show -n <name> -g <rg> -o yaml > /tmp/app.yaml`
2. Edit the YAML file (update env vars, remove `revisionSuffix` or set a unique value)
3. `az containerapp update -n <name> -g <rg> --yaml /tmp/app.yaml`

This ensures all containers in the revision spec are preserved exactly as specified.

## 30. Entra FIC Subject for GCP Must Be Numeric Unique ID, Not Email

When creating a Federated Identity Credential that accepts Google-issued identity tokens, the `subject` field must be the GCP service account's **numeric unique ID** (e.g., `100330114984210007855`), not the email address (e.g., `gcp-agent@project.iam.gserviceaccount.com`). Google identity tokens carry `sub: "100330..."` as a numeric string.

Using the email produces: `AADSTS70021: No matching federated identity record found for presented assertion subject`.

Resolve the correct value:
```bash
gcloud iam service-accounts describe $GCP_SA_EMAIL --format 'value(uniqueId)'
```

## 31. MSAL Python Does Not Support FIC (`WithClientAssertion`)

MSAL Python lacks the `WithClientAssertion` callback required for Federated Identity Credential token exchange flows. When implementing cross-cloud token acquisition (e.g., GCP OIDC -> Entra), use raw HTTP requests to the Entra token endpoint instead of the MSAL library. The `client_assertion_type` and `client_assertion` parameters must be set manually in the POST body.

This is not a bug — MSAL Python is designed for interactive and confidential client flows. The FIC exchange flow is closer to how workload identity federation works, and raw HTTP is the documented Microsoft approach.

## 32. spiffe-proxy Only Supports `server` and `agent-proxy` Container Modes

The spiffe-proxy `entrypoint.sh` currently only supports `CONTAINER_MODE=server` (SPIRE Server) and `CONTAINER_MODE=agent-proxy` (starts embedded SPIRE Agent + proxy). There is no `proxy-only` mode for connecting to an external SPIRE Agent socket.

For SPIFFE federation scenarios where the SPIRE Agent runs as a separate process (e.g., GCP `gcp_iit` attestation), a new container mode or socket override is needed. See `docs/architecture/next-google-cloud-agent-federation.md` for details.

## 34. Rapid-Fire Run-Commands Wedge the Guest Agent on Fresh VMs

On 2026-04-03, `deploy.sh --new` for the `aim-crosscloud` environment stalled at Step 4 (SPIRE server configuration). The SPIRE server Docker container was running and healthy, but the deploy hung indefinitely.

**Root cause:** `deploy.sh` fires 8-10 `az vm run-command create` calls in rapid succession (SPIRE start → trust bundle extract → 5x token generate → 5x entry create). Each call goes through the create → poll → provisioningState wait → delete cycle. On a fresh B1s VM where the guest agent (`waagent`) has just finished cloud-init, the agent cannot process the delete cleanup before the next create arrives. The RunCommandHandler extension enters a confused state where commands execute successfully on the guest but return empty output to ARM, or the ARM resource gets stuck in a transitional `provisioningState`.

**Symptoms:** Deploy hangs with no error message. The SPIRE server is healthy (verified via manual `az vm run-command create` after killing the deploy). The Activity Log shows run-command write/delete pairs succeeding, but the deploy script's poll loop sees empty `executionState` and loops forever.

**Why fresh VMs are worse:** The guest agent is slower on first boot — it's processing cloud-init, installing Docker, pulling images, and registering extensions. The same deploy.sh works fine on warm VMs because the agent has settled.

**Fix:** Added an 8-second cooldown after every `az vm run-command delete` in `azure_vm_run()` (`scripts/lib/azure-helpers.sh`). This gives the guest agent time to clean up the RunCommandHandler extension state before the next command arrives. Also removed `>/dev/null` suppression on delete to surface errors.

**Trade-off:** Adds ~80 seconds to a full deploy (8s × ~10 run-commands). Acceptable — the alternative is a permanently stalled deploy requiring manual intervention.

**Long-term fix:** Migrate to SPIRE Registration API (gRPC on port 8081) or SSH. Both bypass the guest agent entirely. See Learning #21.

## 33. GitHub Actions Runner config.sh Must Not Run as Root

`az vm run-command create` always executes as root. The GitHub Actions runner `config.sh` refuses to run as root ("Must not run with sudo"). Use `su - azureuser -c "cd /home/azureuser/actions-runner && ./config.sh ..."` to run as the non-root user.

**Error:** `Must not run with sudo`
**Fix:** `su - azureuser -c "./config.sh --url ... --token ... --unattended"`

## 34. Bicep Multi-Line Strings Treat ${} as Interpolation

Bicep multi-line strings (triple-quoted `'''...'''`) treat `${VAR}` as Bicep interpolation, not shell variable expansion. Use `__PLACEHOLDER__` format with `replace()` functions instead. The `spire-server-vm.bicep` uses `__ACR_SERVER__`, `__CONTAINER_IMAGE__`, `__TENANT_ID__` — follow this pattern.

**Error:** `BCP057: The name "AZURE_TENANT_ID" does not exist in the current context`
**Fix:** `replace(cloudInit, '__TENANT_ID__', azureTenantId)`

## 35. Flexible FIC Uses claimsMatchingExpression, Not subject

Flexible Federated Identity Credentials use `claimsMatchingExpression` for wildcard matching. This field is **mutually exclusive** with `subject` — you cannot set both. The expression language is `claims['sub'] matches 'repo:microsoft/*'` with `languageVersion: 1`.

**Error:** `BadRequest: Cannot specify both subject and claimsMatchingExpression`
**Fix:** Remove `subject` field entirely when using `claimsMatchingExpression`.

## 36. azd env Values ≠ Shell Environment for Bicep readEnvironmentVariable

`readEnvironmentVariable()` in `.bicepparam` reads from **shell** environment variables, not the azd env store. `azd env set FOO bar` stores in the azd store, but `readEnvironmentVariable('FOO', 'default')` reads `$FOO` from the shell. `azd provision` does export azd env values as shell vars, but if you run `az bicep build` or `az deployment` directly, they won't be set.

**Fix:** Either `export DEPLOY_GITHUB_RUNNER=true` in the shell, or set the azd env value AND let `azd provision` handle the export.

## 37. workflow_dispatch Workflows Must Exist on Default Branch

GitHub Actions `workflow_dispatch` workflows only appear in the API and UI if the workflow YAML exists on the repository's default branch (main). A workflow file only on a feature branch cannot be triggered via `gh workflow run` or the Actions API until the branch is merged.

**Workaround:** Push the workflow YAML to main first, or trigger via UI which allows branch selection.

## 38. ACR Admin Must Be Enabled for VM Docker Pull Without MSI

VMs without user-assigned managed identity (like the GitHub runner VM) can't use MSI-based ACR authentication. Enable ACR admin credentials: `az acr update -n <acr> --admin-enabled true`, then `docker login <acr> -u <acr-name> -p <password>`.

**Fix:** `az acr update -n $ACR_NAME --admin-enabled true` before runner setup.
