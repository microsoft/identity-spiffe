# Google Cross-Cloud Agent Federation — HOWTO

Onboard a GCP-hosted agent (`google-budget-reader`) that calls the Azure-side `budget-backend` through the same four-layer enforcement as domestic agents: **mTLS transport → SPIFFE identity → Entra JWT → RBAC policy**.

One command (`./deploy.sh --new --google`) deploys the full stack end-to-end.

**References:**

- Architecture: [`docs/architecture/next-google-cloud-agent-federation.md`](docs/architecture/next-google-cloud-agent-federation.md)

---

## Prerequisites

### Azure

```bash
az login
azd auth login
```

### GCP

```bash
gcloud auth login
```

You need a GCP project with billing enabled, or let the script create and configure one. If you don't have the `gcloud` CLI:

```bash
brew install google-cloud-sdk   # macOS
```

---

## One-Command Deploy

```bash
# Tell azd which GCP project to use
azd env set GCP_PROJECT my-project

# Optional: if the project doesn't exist yet, provide a billing account
azd env set GCP_BILLING_ID <BILLING_ACCOUNT_ID>

# Deploy everything — Azure infra + agents + Google cross-cloud
./deploy.sh --new --google
```

For an existing environment where Azure is already deployed:

```bash
./deploy.sh --skip-provision --google
```

### What happens

The `--google` flag appends the cross-cloud flow after the standard Azure deployment:

1. **Azure infra + agents deploy** (~10 min) — VNet, ACA environment, SPIRE server, agent containers
2. **GCP project bootstrap** — enables Compute, IAM, and networking APIs; creates the `isp-agent` service account
3. **GCE VM provisioned** — Ubuntu 22.04 with Docker, SPIRE agent, `spiffe-proxy`, and `demo-agent`
4. **VPN Gateway deployed** (~30 min) — Azure VpnGw1 with IPsec; the script shows progress while waiting
5. **GCP VPN tunnel established** — Classic Cloud VPN, forwarding rules, route to Azure VNet CIDR
6. **Cross-cloud connectivity validated** — TCP + TLS checks from GCE to `budget-backend:8443`
7. **Entra Agent Identity created** — Blueprint-level FIC with `https://accounts.google.com` issuer and the service account's numeric unique ID as subject
8. **`Budget.Read` app role assigned** to the Google Agent Identity
9. **RBAC policy + mTLS allow list patched** — `federated_policies` stanza injected, SPIFFE ID added to allow list
10. **SPIRE bundle federation configured** — both sides exchange trust bundles
11. **Agent runtime deployed on GCE** — containers started with `TOKEN_SOURCE=google_oidc`
12. **E2E test runs automatically** — confirms `GET /budget/read → 200` through all four layers

---

## What Gets Created

| Azure | GCP |
|---|---|
| VNet (`10.200.0.0/16`) + ACA environment | VPC + subnet |
| VPN Gateway (VpnGw1) + IPsec connection | Cloud VPN tunnel + static IP |
| Entra Agent Identity + Blueprint FIC | `isp-agent` service account |
| `federated_policies` RBAC entry | SPIRE server + agent |
| mTLS allow list entry | `spiffe-proxy` + `demo-agent` containers |

---

## Verification

### Portal

1. Open the Identity Research for Agent Management Using SPIFFE Portal → **Overview** tab
2. `google-budget-reader` appears in the agent list with `hosting_platform: gcp`

### Test Calls

1. Select **google-budget-reader** in the portal
2. Choose **GET /budget/read** → expect **200 OK**
3. Inspect the response body for token provenance:
   - `token_source: google_oidc`
   - `issuer: https://accounts.google.com`

### CLI validation

```bash
python3 scripts/test_agents.py
```

### Cloud identity endpoint

From the GCE VM (or via its public IP):

```bash
curl http://<GCE-IP>:8000/cloud-identity
```

Returns the active OIDC token metadata from the GCE metadata server.

---

## How It Works

Two identity planes run in parallel — both must pass for a request to succeed.

### Identity plane (secretless, 3 hops)

```
GCE metadata OIDC token (sub = SA numeric ID)
  → Entra FIC exchange → Blueprint token (T1)
  → OBO exchange → Agent Identity token (T2, with Budget.Read role)
```

The `GoogleOIDCProvider` in [`src/shared/entra_token_exchange.py`](src/shared/entra_token_exchange.py) handles this automatically when `TOKEN_SOURCE=google_oidc`. No secrets are stored on the GCE VM.

### Transport plane (mTLS via SPIRE federation)

```
SPIFFE SVID from trust domain gcp.aim.microsoft.com
  → mTLS tunnel over VPN to Azure
  → spiffe-proxy ingress checks: (1) mTLS valid, (2) SPIFFE ID in allow list,
    (3) JWT present with required roles, (4) RBAC policy permits path+method
```

For the full architecture, see [`docs/architecture/next-google-cloud-agent-federation.md`](docs/architecture/next-google-cloud-agent-federation.md).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS700213: No matching federated identity record` | GCE VM using the wrong service account (default compute SA instead of `isp-agent`) | Check: `gcloud compute instances describe <vm> --format 'get(serviceAccounts[0].email)'`. Fix: `gcloud compute instances set-service-account <vm> --service-account isp-agent@<project>.iam.gserviceaccount.com` |
| `AADSTS70021: No matching FIC subject` | FIC subject is the SA email instead of the numeric ID | Get the numeric ID: `gcloud iam service-accounts describe <email> --format 'value(uniqueId)'`. Delete and recreate the FIC with this value. |
| `certificate signed by unknown authority` (mTLS) | SPIRE trust bundles not exchanged, or expired after a redeploy | Re-run `./deploy.sh --google` — bundle exchange is idempotent |
| `tls: bad certificate` | `budget-backend` SPIRE entry missing `federatesWith gcp.aim.microsoft.com` | Re-run `./deploy.sh --google` — fixes the entry automatically |
| `insufficient_roles` (403) | `Budget.Read` app role not assigned to the Google Agent Identity | Re-run `scripts/add-google-agent.sh` — now includes role assignment |
| VPN tunnel stuck at `FIRST_HANDSHAKE` | Azure Local Network Gateway pointing at the GCE VM IP instead of the GCP VPN Gateway IP | Check: `gcloud compute addresses describe isp-vpn-ip --region <region>` — use this static IP, not the VM's ephemeral IP |
| Deploy hangs at SPIRE VM step | Guest agent overwhelmed by rapid `run-command` calls | Already fixed with 10 s cooldown between commands. Kill the script and re-run. |
| Portal shows "Sync failed" | Graph secrets empty on portal container after a fresh deploy | Re-run `./deploy.sh --portal-only` |
| Portal shows "Caller URL not configured" for Google agent | External agent store missing `invoke_url` | Re-run `scripts/add-google-agent.sh --invoke-url http://<GCE-IP>:8000` |
| `AADSTS70011` or scope error at Hop 1 | `ENTRA_OAUTH2_AUDIENCE` set to Agent Identity client ID instead of Blueprint client ID | Check env vars on GCE — `ENTRA_OAUTH2_AUDIENCE` must be the Blueprint `client_id` |
| `token_acquisition_failed` with no upstream details | GCE metadata server unreachable or service account not attached | Verify the VM is on GCE and the `isp-agent` SA is attached: `curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email` |

---

## Manual Steps (Advanced)

For users who prefer to run individual steps instead of `--google`:

### 1. Provision GCE infrastructure

```bash
GCP_PROJECT=my-project ./scripts/provision-gce-vm.sh
```

Creates the VPC, subnet, firewall rules, service account, and Ubuntu VM with Docker.

### 2. Deploy Azure VPN Gateway

The VPN Gateway is provisioned by `infra/modules/vpn-gateway.bicep` when `gcpVpnPublicIp` is set:

```bash
azd env set GCP_VPN_PUBLIC_IP <static-ip-from-step-1>
./deploy.sh --skip-provision
```

### 3. Create GCP VPN tunnel

```bash
GCP_PROJECT=my-project \
AZURE_VPN_GATEWAY_IP=<azure-vpn-gw-ip> \
VPN_SHARED_KEY=<psk> \
  ./scripts/provision-gcp-vpn.sh
```

### 4. Validate connectivity

```bash
GCE_VM_IP=<gce-ip> \
BUDGET_BACKEND_PRIVATE_IP=<budget-backend-private-ip> \
SPIRE_SERVER_PRIVATE_IP=<spire-server-private-ip> \
  ./scripts/test-crosscloud-connectivity.sh
```

Runs 6 checks: SSH preflight, tool availability, VPN status (both sides), TCP to budget-backend, TCP to SPIRE server, TLS handshake, and Azure agent regression.

### 5. Provision Entra identity

```bash
./scripts/add-google-agent.sh \
  --gcp-sa isp-agent@my-project.iam.gserviceaccount.com \
  --invoke-url http://<gce-ip>:8000 \
  --name google-budget-reader
```

Creates the Agent Identity, FIC, app role assignment, mTLS allow list entry, and portal registration.

### 6. Deploy agent runtime on GCE

The GCE VM needs these env vars (printed by `add-google-agent.sh`):

```bash
TOKEN_SOURCE=google_oidc
ENTRA_OAUTH2_AUDIENCE=<blueprint-client-id>
ENTRA_AGENT_ID=<agent-identity-client-id>
AZURE_TENANT_ID=<tenant-id>
TARGET_HOST=<budget-backend-private-ip>
TARGET_PORT=8443
```

### 7. Configure SPIRE bundle federation

Exchange trust bundles on both SPIRE servers and add a `federatesWith` entry on the budget-backend workload registration. Use `azure_vm_run()` from `scripts/lib/azure-helpers.sh` for Azure SPIRE commands — never `az vm run-command invoke` (no timeout, can permanently block the VM).

---

## See Also

- [`docs/architecture/next-google-cloud-agent-federation.md`](docs/architecture/next-google-cloud-agent-federation.md) — architecture decision record
- [`docs/runbooks/hard-won-learnings.md`](docs/runbooks/hard-won-learnings.md) — #29 (container env nuke), #30 (FIC numeric ID), #31 (MSAL FIC gap), #32 (proxy-only mode)
- Platform learnings: Google, AWS, ServiceNow — see `docs/runbooks/`
- [`scripts/add-google-agent.sh`](scripts/add-google-agent.sh) — Entra identity provisioning
- [`scripts/current-deployment.sh`](scripts/current-deployment.sh) — full deployment status dashboard
- [`src/shared/entra_token_exchange.py`](src/shared/entra_token_exchange.py) — `GoogleOIDCProvider` implementation
- [`src/spiffe-proxy/internal/rbac/`](src/spiffe-proxy/internal/rbac/) — federated policy engine
